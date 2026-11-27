'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const http = require('node:http');
const { DatabaseSync } = require('node:sqlite');
const bcrypt = require('bcryptjs');
const { createApp, parseRupeesToPaise, paiseToDecimalString, sanitizeStoredText } = require('../server');

class TestClient {
  constructor(baseUrl) {
    this.baseUrl = baseUrl;
    this.cookie = '';
    this.csrf = '';
  }

  async req(method, urlPath, body) {
    const headers = { 'Content-Type': 'application/json' };
    if (this.cookie) headers['Cookie'] = this.cookie;
    if (this.csrf && method !== 'GET' && method !== 'HEAD') {
      headers['X-CSRF-Token'] = this.csrf;
    }
    const res = await fetch(this.baseUrl + urlPath, {
      method,
      headers,
      body: body !== undefined ? JSON.stringify(body) : undefined,
    });
    const setCookie = res.headers.getSetCookie ? res.headers.getSetCookie() : [];
    for (const c of setCookie) {
      const m = /^([^=]+=[^;]+)/.exec(c);
      if (m) this.cookie = m[1];
    }
    const text = await res.text();
    let json = null;
    try { json = JSON.parse(text); } catch {}
    if (json && json.csrfToken) this.csrf = json.csrfToken;
    return { status: res.status, headers: res.headers, body: json, raw: text, setCookie };
  }
}

let tmpDir, server, baseUrl, db;
const capturedLogs = [];

test.before(async () => {
  tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'spendwise-inr-test-'));
  const created = createApp({
    dataDir: tmpDir,
    dbPath: path.join(tmpDir, 'test.db'),
    sessionSecret: 'test-secret-key-at-least-32-chars-long',
    authRateLimit: { windowMs: 60_000, max: 50 },
    apiRateLimit: { windowMs: 60_000, max: 300 },
    logger: (entry) => capturedLogs.push(entry),
  });
  db = created.db;
  server = http.createServer(created.app);
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const addr = server.address();
  baseUrl = `http://127.0.0.1:${addr.port}`;
});

test.after(async () => {
  await new Promise(resolve => server.close(resolve));
  db.close();
  fs.rmSync(tmpDir, { recursive: true, force: true });
});

test('paise helper avoids floating-point drift and enforces 2 decimal places', () => {
  assert.equal(parseRupeesToPaise('0.10') + parseRupeesToPaise('0.20'), 30);
  assert.equal(parseRupeesToPaise('19.99'), 1999);
  assert.equal(parseRupeesToPaise('1,25,000.50'), 12500050);
  assert.equal(parseRupeesToPaise('₹500.05'), 50005);
  assert.equal(parseRupeesToPaise('-250.75', { allowNegative: true }), -25075);
  assert.equal(parseRupeesToPaise('12.345'), null); // >2 decimals rejected
  assert.equal(parseRupeesToPaise('0', { allowZero: false }), null);
  assert.equal(paiseToDecimalString(12500050), '125000.50');
  assert.equal(paiseToDecimalString(30), '0.30');
});

test('sanitizeStoredText strips scripts, closed/unclosed HTML tags, angle brackets, and control chars', () => {
  assert.equal(sanitizeStoredText('<script>alert(1)</script>Groceries\x00', 100), 'Groceries');
  assert.equal(sanitizeStoredText('<script>alert(1)', 100), '');
  assert.equal(sanitizeStoredText('<img src=x onerror=alert(1) x=', 100), '');
  assert.equal(sanitizeStoredText('Chai <img src=x onerror=alert(1) x=', 100), 'Chai');
  assert.equal(sanitizeStoredText('<b>Food</b> & Dining', 100), 'Food & Dining');
  assert.equal(sanitizeStoredText('Rent < 500 > 100', 100), 'Rent 500 100');
  assert.equal(sanitizeStoredText('Tea\n\tChai', 100), 'Tea Chai');
});

test('security headers, strict script CSP, external JS, and zero inline handlers/scripts', async () => {
  const res = await fetch(baseUrl + '/api/auth/me');
  assert.equal(res.headers.get('x-powered-by'), null);
  assert.equal(res.headers.get('x-content-type-options'), 'nosniff');
  assert.equal(res.headers.get('x-frame-options'), 'SAMEORIGIN');
  assert.ok(res.headers.get('permissions-policy'));

  const csp = res.headers.get('content-security-policy') || '';
  const directives = Object.fromEntries(
    csp.split(';').map(d => d.trim()).filter(Boolean).map(d => {
      const [name, ...vals] = d.split(/\s+/);
      return [name, vals.join(' ')];
    })
  );
  assert.ok(directives['script-src']);
  assert.equal(directives['script-src'].includes("'self'"), true);
  assert.equal(directives['script-src'].includes('unsafe-inline'), false);

  const htmlRes = await fetch(baseUrl + '/');
  assert.equal(htmlRes.status, 200);
  const html = await htmlRes.text();
  assert.equal(html.includes('<script src="/app.js" defer></script>'), true);

  // Every <script> tag must reference an external src (zero inline <script> blocks)
  const scriptTags = html.match(/<script\b[^>]*>/gi) || [];
  assert.equal(scriptTags.length, 1);
  assert.ok(/\bsrc=["']\/app\.js["']/i.test(scriptTags[0]));

  // Zero inline on* event handler attributes in HTML markup
  assert.equal(/\son[a-z]+\s*=/i.test(html), false);

  const jsRes = await fetch(baseUrl + '/app.js');
  assert.equal(jsRes.status, 200);
  const jsBody = await jsRes.text();
  assert.equal(/innerHTML|outerHTML|insertAdjacentHTML|document\.write/i.test(jsBody), false);

  // Public static directory must never contain SQLite database or WAL/SHM files
  const publicFiles = fs.readdirSync(path.join(__dirname, '..', 'public'));
  assert.equal(publicFiles.some(f => /\.db(?:-wal|-shm)?$/i.test(f)), false);
});

test('user ID and password rules reject invalid IDs, spaces, special chars, and short passwords', async () => {
  const c = new TestClient(baseUrl);
  const badUserIds = ['ab', 'bad user', 'bad-name', 'user@1', 'alice\x00', 'a'.repeat(31), ''];
  for (const uid of badUserIds) {
    const r = await c.req('POST', '/api/auth/register', { userId: uid, password: 'ValidPass123' });
    assert.equal(r.status, 400);
  }
  const badPasswords = ['short1A', 'Pass word1', 'Pass@1234', 'Pass_1234', 'Pass-1234', 'Pass!1234', 'Пароль1234', 'a'.repeat(73), ''];
  for (const pw of badPasswords) {
    const r = await c.req('POST', '/api/auth/register', { userId: 'ruleuser', password: pw });
    assert.equal(r.status, 400);
  }
});

test('registration, unique user ID, bcrypt hashing, and INR-only enforcement', async () => {
  const c = new TestClient(baseUrl);
  const r1 = await c.req('POST', '/api/auth/register', { userId: 'Aarav01', password: 'Alpha99Password' });
  assert.equal(r1.status, 201);
  assert.ok(r1.body.csrfToken);

  const storedUser = db.prepare('SELECT password_hash FROM users WHERE user_id = ?').get('Aarav01');
  assert.ok(storedUser);
  assert.match(storedUser.password_hash, /^\$2[aby]\$12\$/);
  assert.equal(bcrypt.compareSync('Alpha99Password', storedUser.password_hash), true);

  const s = await c.req('GET', '/api/settings');
  assert.equal(s.status, 200);
  assert.equal(s.body.currency, 'INR');
  assert.equal(s.body.limitPaise, 1000000);
  assert.equal(s.body.balancePaise, 0);

  // Attempting to set non-INR currency is rejected
  const badCurSet = await c.req('PUT', '/api/settings', { currency: 'USD', limitPaise: 500000 });
  assert.equal(badCurSet.status, 400);

  const badCurTx = await c.req('POST', '/api/transactions', {
    type: 'expense', amountPaise: 5000, currency: 'EUR', category: 'Food & Dining', date: '2026-11-20',
  });
  assert.equal(badCurTx.status, 400);

  // >2 decimal places rejected
  const badDecTx = await c.req('POST', '/api/transactions', {
    type: 'expense', amount: '10.125', category: 'Food & Dining', date: '2026-11-20',
  });
  assert.equal(badDecTx.status, 400);

  // Duplicate user ID rejected
  const c2 = new TestClient(baseUrl);
  const rDup = await c2.req('POST', '/api/auth/register', { userId: 'aarav01', password: 'Beta88Password' });
  assert.equal(rDup.status, 409);

  // Security logs must never contain plaintext passwords
  const serializedLogs = JSON.stringify(capturedLogs);
  assert.equal(serializedLogs.includes('Alpha99Password'), false);
  assert.equal(serializedLogs.includes('Beta88Password'), false);
});

test('INR CRUD in exact paise, stored text sanitization, search/filters/sorting, and cross-device sync', async () => {
  const dev1 = new TestClient(baseUrl);
  await dev1.req('POST', '/api/auth/login', { userId: 'Aarav01', password: 'Alpha99Password' });

  await dev1.req('PUT', '/api/settings', {
    setupDone: true,
    period: 'monthly',
    limitPaise: 12500050,   // ₹1,25,000.50
    balancePaise: 5000000,  // ₹50,000.00
    alertThreshold: 80,
    catBudgetsPaise: { Groceries: 1500075 },
  });

  const tx1 = await dev1.req('POST', '/api/transactions', {
    type: 'expense', amount: '12500.50', category: 'Groceries',
    date: '2026-11-20', note: '<script>evil()</script>Monthly ration', clientRequestId: 'inr-req-1',
  });
  assert.equal(tx1.status, 201);
  assert.equal(tx1.body.transaction.amountPaise, 1250050);
  assert.equal(tx1.body.transaction.currency, 'INR');
  assert.equal(tx1.body.transaction.note, 'Monthly ration');

  const tx1Dup = await dev1.req('POST', '/api/transactions', {
    type: 'expense', amount: '12500.50', category: 'Groceries',
    date: '2026-11-20', note: '<script>evil()</script>Monthly ration', clientRequestId: 'inr-req-1',
  });
  assert.equal(tx1Dup.status, 200);
  assert.equal(tx1Dup.body.deduplicated, true);

  const tx2 = await dev1.req('POST', '/api/transactions', {
    type: 'income', amountPaise: 7500025, category: 'Other',
    date: '2026-11-25', note: 'Salary credit',
  });
  assert.equal(tx2.status, 201);

  // Unclosed tag stored XSS payloads are stripped and malformed alertFired values rejected
  const unclosedXss = await dev1.req('POST', '/api/transactions', {
    type: 'expense', amountPaise: 5000, category: 'Tea <img src=x onerror=alert(1) x=',
    date: '2026-11-26', note: 'Morning <img src=x onerror=alert(1) x=',
  });
  assert.equal(unclosedXss.status, 201);
  assert.equal(unclosedXss.body.transaction.category, 'Tea');
  assert.equal(unclosedXss.body.transaction.note, 'Morning');

  const badAlertVal = await dev1.req('PUT', '/api/settings', {
    alertFired: { 'monthly:2026-11-01:over': '<img src=x onerror=alert(1)>' },
  });
  assert.equal(badAlertVal.status, 400);

  const badAlertKey = await dev1.req('PUT', '/api/settings', {
    alertFired: { '<img src=x onerror=alert(1) x=': true },
  });
  assert.equal(badAlertKey.status, 400);

  // Device 2 fresh login syncs exact paise
  const dev2 = new TestClient(baseUrl);
  await dev2.req('POST', '/api/auth/login', { userId: 'Aarav01', password: 'Alpha99Password' });
  const s2 = await dev2.req('GET', '/api/settings');
  assert.equal(s2.body.limitPaise, 12500050);
  assert.equal(s2.body.balancePaise, 5000000);
  assert.equal(s2.body.catBudgetsPaise.Groceries, 1500075);

  const searchAmt = await dev2.req('GET', '/api/transactions?q=' + encodeURIComponent('12500.50'));
  assert.equal(searchAmt.status, 200);
  assert.equal(searchAmt.body.length, 1);
  assert.equal(searchAmt.body[0].id, tx1.body.id);

  // Own-user transaction update (PUT) and delete (DELETE)
  const tempTx = await dev2.req('POST', '/api/transactions', {
    type: 'expense', amount: '100.25', category: 'Transport', date: '2026-11-24', note: 'Auto rickshaw',
  });
  assert.equal(tempTx.status, 201);

  const updTx = await dev2.req('PUT', `/api/transactions/${tempTx.body.id}`, {
    amount: '150.75', category: 'Transport', note: '<b>Metro</b> pass', date: '2026-11-24',
  });
  assert.equal(updTx.status, 200);
  assert.equal(updTx.body.transaction.amountPaise, 15075);
  assert.equal(updTx.body.transaction.note, 'Metro pass');

  const delTx = await dev2.req('DELETE', `/api/transactions/${tempTx.body.id}`);
  assert.equal(delTx.status, 200);
  const delAgain = await dev2.req('DELETE', `/api/transactions/${tempTx.body.id}`);
  assert.equal(delAgain.status, 404);
});

test('malformed JSON, non-object bodies, and oversized payloads return JSON errors', async () => {
  const c = new TestClient(baseUrl);
  await c.req('POST', '/api/auth/login', { userId: 'Aarav01', password: 'Alpha99Password' });

  const badJsonRes = await fetch(baseUrl + '/api/transactions', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Cookie: c.cookie, 'X-CSRF-Token': c.csrf },
    body: '{"broken": ',
  });
  assert.equal(badJsonRes.status, 400);
  const badJsonBody = await badJsonRes.json();
  assert.equal(badJsonBody.error, 'Malformed JSON payload.');

  const arrBody = await c.req('POST', '/api/transactions', ['not-an-object']);
  assert.equal(arrBody.status, 400);

  // Exceed 512kb payload limit
  const hugeRes = await fetch(baseUrl + '/api/import', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Cookie: c.cookie, 'X-CSRF-Token': c.csrf },
    body: JSON.stringify({ transactions: [], categories: ['x'.repeat(600 * 1024)] }),
  });
  assert.equal(hugeRes.status, 413);
});

test('cross-user isolation, SQL injection resilience, and CSRF', async () => {
  const aarav = new TestClient(baseUrl);
  await aarav.req('POST', '/api/auth/login', { userId: 'Aarav01', password: 'Alpha99Password' });
  const aaravTx = (await aarav.req('GET', '/api/transactions')).body[0];

  const priya = new TestClient(baseUrl);
  await priya.req('POST', '/api/auth/register', { userId: 'Priya02', password: 'PriyaPass99' });

  assert.equal((await priya.req('GET', '/api/transactions')).body.length, 0);
  assert.equal((await priya.req('PUT', `/api/transactions/${aaravTx.id}`, { amountPaise: 100 })).status, 404);
  assert.equal((await priya.req('DELETE', `/api/transactions/${aaravTx.id}`)).status, 404);

  const sqli = await priya.req('GET', "/api/transactions?q=' OR '1'='1&sortBy=amount;DROP TABLE users;--");
  assert.equal(sqli.status, 200);
  assert.equal(sqli.body.length, 0);

  // CSRF protection: missing or mismatched X-CSRF-Token must be rejected with 403
  const missingCsrf = await fetch(baseUrl + '/api/transactions', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Cookie: priya.cookie },
    body: JSON.stringify({ type: 'expense', amount: '50.00', category: 'Other', date: '2026-11-26' }),
  });
  assert.equal(missingCsrf.status, 403);

  const badCsrf = await fetch(baseUrl + '/api/settings', {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json', Cookie: priya.cookie, 'X-CSRF-Token': '0'.repeat(64) },
    body: JSON.stringify({ period: 'weekly' }),
  });
  assert.equal(badCsrf.status, 403);

  const badCatCsrf = await fetch(baseUrl + '/api/categories', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Cookie: priya.cookie, 'X-CSRF-Token': 'invalid-token' },
    body: JSON.stringify({ name: 'Books' }),
  });
  assert.equal(badCatCsrf.status, 403);
});

test('local import flags non-INR data for review instead of silently relabeling', async () => {
  const priya = new TestClient(baseUrl);
  await priya.req('POST', '/api/auth/login', { userId: 'Priya02', password: 'PriyaPass99' });

  const imp = await priya.req('POST', '/api/import', {
    transactions: [
      { id: 'old-usd-1', type: 'expense', amount: 45.25, currency: 'USD', category: 'Shopping', date: '2026-11-12', note: 'Jacket' },
      { id: 'old-inr-1', type: 'expense', amount: 350.5, currency: 'INR', category: 'Food & Dining', date: '2026-11-13', note: 'Dosa' },
    ],
    categories: ['Coffee', "Tea');alert(1);//<img src=x"],
    settings: { currency: 'USD', period: 'monthly', limit: 1500, balance: 200, alertThreshold: 90 },
    importSettings: true,
  });
  assert.equal(imp.status, 200);
  assert.equal(imp.body.imported, 2);
  assert.equal(imp.body.flaggedForReview, 1);

  const cats = (await priya.req('GET', '/api/categories')).body;
  assert.ok(cats.some(c => c.name === "Tea');alert(1);//"));

  const s = await priya.req('GET', '/api/settings');
  assert.equal(s.body.needsCurrencyReview, true);
  assert.equal(s.body.legacyCurrency, 'USD');

  const txs = (await priya.req('GET', '/api/transactions')).body;
  const usdTx = txs.find(t => t.note === 'Jacket');
  const inrTx = txs.find(t => t.note === 'Dosa');
  assert.equal(usdTx.needsCurrencyReview, true);
  assert.equal(usdTx.originalCurrency, 'USD');
  assert.equal(usdTx.originalAmount, '45.25');
  assert.equal(inrTx.needsCurrencyReview, false);
  assert.equal(inrTx.amountPaise, 35050);

  // Deliberate review confirms USD item as INR
  const rev = await priya.req('POST', `/api/transactions/${usdTx.id}/review-inr`, { amount: '3800.75' });
  assert.equal(rev.status, 200);
  assert.equal(rev.body.transaction.needsCurrencyReview, false);
  assert.equal(rev.body.transaction.amountPaise, 380075);

  const revSet = await priya.req('PUT', '/api/settings', { limit: '25000.00', balance: '5000.00', confirmCurrencyReview: true });
  assert.equal(revSet.status, 200);
  assert.equal((await priya.req('GET', '/api/settings')).body.needsCurrencyReview, false);
});

test('rate limiting ignores forged X-Forwarded-For by default and production HTTPS rejects plain HTTP without forwarded headers', async () => {
  // 1. Default trustProxy=false: spoofed X-Forwarded-For & X-Forwarded-Proto cannot bypass rate limit or HTTPS check
  const directDir = fs.mkdtempSync(path.join(os.tmpdir(), 'spendwise-direct-'));
  const prevNodeEnv = process.env.NODE_ENV;
  process.env.NODE_ENV = 'production';
  let directCreated, directServer;
  try {
    directCreated = createApp({
      dataDir: directDir,
      dbPath: path.join(directDir, 'direct.db'),
      sessionSecret: 'direct-secret-key-at-least-32-characters',
      authRateLimit: { windowMs: 60_000, max: 2 },
      apiRateLimit: { windowMs: 60_000, max: 20 },
      quiet: true,
    });
    directServer = http.createServer(directCreated.app);
    await new Promise(resolve => directServer.listen(0, '127.0.0.1', resolve));
    const directUrl = `http://127.0.0.1:${directServer.address().port}`;

    // Production enforces HTTPS even with NO x-forwarded-proto header
    const noHdrRes = await fetch(directUrl + '/api/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ userId: 'nobody', password: 'WrongPassword1' }),
    });
    assert.equal(noHdrRes.status, 403);
    assert.ok(noHdrRes.headers.get('strict-transport-security'));

    // Spoofed x-forwarded-proto: https must NOT bypass enforceHttps when trustProxy=false
    const spoofHttpsRes = await fetch(directUrl + '/api/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'x-forwarded-proto': 'https' },
      body: JSON.stringify({ userId: 'nobody', password: 'WrongPassword1' }),
    });
    assert.equal(spoofHttpsRes.status, 403);
  } finally {
    if (prevNodeEnv === undefined) delete process.env.NODE_ENV;
    else process.env.NODE_ENV = prevNodeEnv;
    if (directServer) await new Promise(resolve => directServer.close(resolve));
    if (directCreated) directCreated.db.close();
    fs.rmSync(directDir, { recursive: true, force: true });
  }

  // 2. Direct plain-HTTP server with enforceHttps=false: rotating X-Forwarded-For cannot evade rate limit
  const xffDir = fs.mkdtempSync(path.join(os.tmpdir(), 'spendwise-xff-'));
  const xffCreated = createApp({
    dataDir: xffDir,
    dbPath: path.join(xffDir, 'xff.db'),
    sessionSecret: 'xff-secret-key-at-least-32-characters-long',
    authRateLimit: { windowMs: 60_000, max: 2 },
    apiRateLimit: { windowMs: 60_000, max: 20 },
    quiet: true,
  });
  const xffServer = http.createServer(xffCreated.app);
  await new Promise(resolve => xffServer.listen(0, '127.0.0.1', resolve));
  const xffUrl = `http://127.0.0.1:${xffServer.address().port}`;
  try {
    for (let i = 0; i < 2; i++) {
      const r = await fetch(xffUrl + '/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'x-forwarded-for': `203.0.113.${i + 1}` },
        body: JSON.stringify({ userId: 'nobody', password: 'WrongPassword1' }),
      });
      assert.equal(r.status, 401);
    }
    const evadedAttempt = await fetch(xffUrl + '/api/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'x-forwarded-for': '203.0.113.99' },
      body: JSON.stringify({ userId: 'nobody', password: 'WrongPassword1' }),
    });
    assert.equal(evadedAttempt.status, 429);
  } finally {
    await new Promise(resolve => xffServer.close(resolve));
    xffCreated.db.close();
    fs.rmSync(xffDir, { recursive: true, force: true });
  }

  // 3. Explicit trustProxy='loopback' behind TLS proxy enforces HTTPS, sets Secure cookie, and rate-limits
  const rlDir = fs.mkdtempSync(path.join(os.tmpdir(), 'spendwise-rl-'));
  const rlLogs = [];
  const rlCreated = createApp({
    dataDir: rlDir,
    dbPath: path.join(rlDir, 'rl.db'),
    sessionSecret: 'rl-secret-key-at-least-32-characters-long',
    authRateLimit: { windowMs: 60_000, max: 3 },
    apiRateLimit: { windowMs: 60_000, max: 20 },
    enforceHttps: true,
    trustProxy: 'loopback',
    logger: (entry) => rlLogs.push(entry),
  });
  const rlServer = http.createServer(rlCreated.app);
  await new Promise(resolve => rlServer.listen(0, '127.0.0.1', resolve));
  const rlUrl = `http://127.0.0.1:${rlServer.address().port}`;

  try {
    const plainHttpRes = await fetch(rlUrl + '/api/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ userId: 'nobody', password: 'WrongPassword1' }),
    });
    assert.equal(plainHttpRes.status, 403);

    // Registration over proxied HTTPS sets Secure attribute on sw.sid cookie
    const regProxy = await fetch(rlUrl + '/api/auth/register', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'x-forwarded-proto': 'https', 'x-forwarded-for': '198.51.100.10' },
      body: JSON.stringify({ userId: 'proxyuser', password: 'ProxyPass99' }),
    });
    assert.equal(regProxy.status, 201);
    const setCookies = regProxy.headers.getSetCookie ? regProxy.headers.getSetCookie() : [];
    assert.ok(setCookies.some(c => c.startsWith('sw.sid=') && /;\s*Secure\b/i.test(c)));

    for (let i = 0; i < 2; i++) {
      const r = await fetch(rlUrl + '/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'x-forwarded-proto': 'https', 'x-forwarded-for': '198.51.100.10' },
        body: JSON.stringify({ userId: 'nobody', password: 'WrongPassword1' }),
      });
      assert.equal(r.status, 401);
      assert.ok(r.headers.get('strict-transport-security'));
    }

    const blocked = await fetch(rlUrl + '/api/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'x-forwarded-proto': 'https', 'x-forwarded-for': '198.51.100.10' },
      body: JSON.stringify({ userId: 'nobody', password: 'WrongPassword1' }),
    });
    assert.equal(blocked.status, 429);
    assert.ok(blocked.headers.get('retry-after'));
    assert.ok(rlLogs.some(l => l.event === 'security.rate_limit_exceeded'));
    assert.ok(rlLogs.some(l => l.event === 'security.https_rejected'));
  } finally {
    await new Promise(resolve => rlServer.close(resolve));
    rlCreated.db.close();
    fs.rmSync(rlDir, { recursive: true, force: true });
  }
});

test('legacy pre-INR SQLite schema migrates safely and flags non-INR rows', async () => {
  const migDir = fs.mkdtempSync(path.join(os.tmpdir(), 'spendwise-mig-'));
  const migDbPath = path.join(migDir, 'legacy.db');
  try {
    const rawDb = new DatabaseSync(migDbPath);
    rawDb.exec(`
      CREATE TABLE users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id TEXT NOT NULL UNIQUE COLLATE NOCASE,
        password_hash TEXT NOT NULL,
        created_at TEXT NOT NULL DEFAULT (datetime('now')),
        updated_at TEXT NOT NULL DEFAULT (datetime('now'))
      );
      CREATE TABLE settings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_pk INTEGER NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,
        setup_done INTEGER NOT NULL DEFAULT 1,
        currency TEXT NOT NULL DEFAULT 'USD',
        period TEXT NOT NULL DEFAULT 'monthly',
        limit_amount REAL NOT NULL DEFAULT 2000,
        balance REAL NOT NULL DEFAULT 500,
        alert_threshold INTEGER NOT NULL DEFAULT 80,
        notif_in_app INTEGER NOT NULL DEFAULT 1,
        notif_browser INTEGER NOT NULL DEFAULT 0,
        alert_fired TEXT NOT NULL DEFAULT '{}',
        cat_budgets TEXT NOT NULL DEFAULT '{}',
        updated_at TEXT NOT NULL DEFAULT (datetime('now'))
      );
      CREATE TABLE categories (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_pk INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        name TEXT NOT NULL,
        sort_order INTEGER NOT NULL DEFAULT 0,
        created_at TEXT NOT NULL DEFAULT (datetime('now')),
        UNIQUE(user_pk, name)
      );
      CREATE TABLE transactions (
        id TEXT NOT NULL,
        user_pk INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        type TEXT NOT NULL,
        amount REAL NOT NULL,
        currency TEXT NOT NULL DEFAULT 'USD',
        category TEXT NOT NULL DEFAULT 'Other',
        date TEXT NOT NULL,
        note TEXT NOT NULL DEFAULT '',
        source_id TEXT,
        created_at TEXT NOT NULL DEFAULT (datetime('now')),
        updated_at TEXT NOT NULL DEFAULT (datetime('now')),
        PRIMARY KEY (user_pk, id)
      );
    `);
    const hash = bcrypt.hashSync('LegacyPass99', 8);
    rawDb.prepare('INSERT INTO users (user_id, password_hash) VALUES (?, ?)').run('LegacyUser', hash);
    rawDb.prepare("INSERT INTO settings (user_pk, setup_done, currency, limit_amount, balance, cat_budgets) VALUES (1, 1, 'EUR', 1500.5, 250.25, '{\"Food\": 300.5}')").run();
    rawDb.prepare("INSERT INTO transactions (id, user_pk, type, amount, currency, category, date, note) VALUES ('t-eur', 1, 'expense', 99.95, 'EUR', 'Food', '2026-11-10', 'Cafe')").run();
    rawDb.prepare("INSERT INTO transactions (id, user_pk, type, amount, currency, category, date, note) VALUES ('t-inr', 1, 'expense', 420.5, 'INR', 'Food', '2026-11-11', 'Thali')").run();
    rawDb.close();

    const migrated = createApp({ dataDir: migDir, dbPath: migDbPath, sessionSecret: 'mig-secret-key-at-least-32-characters-long', quiet: true });
    const migServer = http.createServer(migrated.app);
    await new Promise(resolve => migServer.listen(0, '127.0.0.1', resolve));
    const migUrl = `http://127.0.0.1:${migServer.address().port}`;

    try {
      const client = new TestClient(migUrl);
      const login = await client.req('POST', '/api/auth/login', { userId: 'LegacyUser', password: 'LegacyPass99' });
      assert.equal(login.status, 200);

      const s = (await client.req('GET', '/api/settings')).body;
      assert.equal(s.currency, 'INR');
      assert.equal(s.limitPaise, 150050);
      assert.equal(s.balancePaise, 25025);
      assert.equal(s.catBudgetsPaise.Food, 30050);
      assert.equal(s.needsCurrencyReview, true);
      assert.equal(s.legacyCurrency, 'EUR');

      const txs = (await client.req('GET', '/api/transactions')).body;
      const eurTx = txs.find(t => t.id === 't-eur');
      const inrTx = txs.find(t => t.id === 't-inr');
      assert.equal(eurTx.needsCurrencyReview, true);
      assert.equal(eurTx.originalCurrency, 'EUR');
      assert.equal(eurTx.originalAmount, '99.95');
      assert.equal(inrTx.needsCurrencyReview, false);
      assert.equal(inrTx.amountPaise, 42050);
    } finally {
      await new Promise(resolve => migServer.close(resolve));
      migrated.db.close();
    }
  } finally {
    fs.rmSync(migDir, { recursive: true, force: true });
  }
});

test('categories CRUD, transaction filters/sorting, and LIKE wildcard escaping', async () => {
  const kabir = new TestClient(baseUrl);
  const reg = await kabir.req('POST', '/api/auth/register', { userId: 'Kabir03', password: 'KabirPass99' });
  assert.equal(reg.status, 201);

  assert.equal((await kabir.req('POST', '/api/categories', { name: '<script>x</script>' })).status, 400);
  const cat = await kabir.req('POST', '/api/categories', { name: 'Chai & Snacks' });
  assert.equal(cat.status, 201);
  assert.equal(cat.body.name, 'Chai & Snacks');

  const dupCat = await kabir.req('POST', '/api/categories', { name: 'chai & snacks' });
  assert.equal(dupCat.status, 409);

  assert.equal((await kabir.req('DELETE', '/api/categories/notanumber')).status, 400);

  // Cross-user category deletion must fail with 404
  const priya = new TestClient(baseUrl);
  await priya.req('POST', '/api/auth/login', { userId: 'Priya02', password: 'PriyaPass99' });
  assert.equal((await priya.req('DELETE', `/api/categories/${cat.body.id}`)).status, 404);

  assert.equal((await kabir.req('DELETE', `/api/categories/${cat.body.id}`)).status, 200);
  assert.equal((await kabir.req('DELETE', `/api/categories/${cat.body.id}`)).status, 404);

  await kabir.req('POST', '/api/transactions', {
    type: 'expense', amount: '500.00', category: 'Groceries', date: '2026-11-10', note: '50% discount',
  });
  await kabir.req('POST', '/api/transactions', {
    type: 'expense', amount: '200.00', category: 'Transport', date: '2026-11-15', note: 'Cab_ride',
  });
  await kabir.req('POST', '/api/transactions', {
    type: 'income', amount: '1000.00', category: 'Other', date: '2026-11-20', note: 'Freelance bonus',
  });

  assert.equal((await kabir.req('GET', '/api/transactions?type=bogus')).status, 400);
  assert.equal((await kabir.req('GET', '/api/transactions?from=bad-date')).status, 400);
  assert.equal((await kabir.req('GET', '/api/transactions?type=expense')).body.length, 2);
  assert.equal((await kabir.req('GET', '/api/transactions?category=Groceries')).body.length, 1);

  const dateWin = await kabir.req('GET', '/api/transactions?from=2026-11-12&to=2026-11-18');
  assert.equal(dateWin.status, 200);
  assert.equal(dateWin.body.length, 1);
  assert.equal(dateWin.body[0].note, 'Cab_ride');

  const asc = await kabir.req('GET', '/api/transactions?sortBy=amount&sortDir=asc');
  assert.deepEqual(asc.body.map(t => t.amountPaise), [20000, 50000, 100000]);

  const desc = await kabir.req('GET', '/api/transactions?sortBy=amount&sortDir=desc');
  assert.deepEqual(desc.body.map(t => t.amountPaise), [100000, 50000, 20000]);

  // % and _ in search query must be matched literally, not as SQL LIKE wildcards
  const pctMatch = await kabir.req('GET', '/api/transactions?q=' + encodeURIComponent('50%'));
  assert.equal(pctMatch.body.length, 1);
  assert.equal(pctMatch.body[0].note, '50% discount');

  const underscoreMatch = await kabir.req('GET', '/api/transactions?q=' + encodeURIComponent('Cab_ride'));
  assert.equal(underscoreMatch.body.length, 1);
  const underscoreNoWildcard = await kabir.req('GET', '/api/transactions?q=' + encodeURIComponent('CabXride'));
  assert.equal(underscoreNoWildcard.body.length, 0);
});

test('logout and account deletion enforce CSRF, password check, and cascade cleanup', async () => {
  const meera = new TestClient(baseUrl);
  const reg = await meera.req('POST', '/api/auth/register', { userId: 'Meera03', password: 'MeeraPass99' });
  assert.equal(reg.status, 201);

  const tx = await meera.req('POST', '/api/transactions', {
    type: 'expense', amount: '120.00', category: 'Food & Dining', date: '2026-11-26', note: 'Lunch',
  });
  assert.equal(tx.status, 201);

  const logoutNoCsrf = await fetch(baseUrl + '/api/auth/logout', {
    method: 'POST',
    headers: { Cookie: meera.cookie },
  });
  assert.equal(logoutNoCsrf.status, 403);

  const logoutBadCsrf = await fetch(baseUrl + '/api/auth/logout', {
    method: 'POST',
    headers: { Cookie: meera.cookie, 'X-CSRF-Token': 'bad-csrf-token' },
  });
  assert.equal(logoutBadCsrf.status, 403);

  const logoutOk = await meera.req('POST', '/api/auth/logout');
  assert.equal(logoutOk.status, 200);
  assert.equal((await meera.req('GET', '/api/auth/me')).body.authenticated, false);

  const relogin = await meera.req('POST', '/api/auth/login', { userId: 'Meera03', password: 'MeeraPass99' });
  assert.equal(relogin.status, 200);

  const wrongPwDel = await meera.req('DELETE', '/api/auth/account', { password: 'WrongPassword1' });
  assert.equal(wrongPwDel.status, 403);

  const delOk = await meera.req('DELETE', '/api/auth/account', { password: 'MeeraPass99' });
  assert.equal(delOk.status, 200);
  assert.equal((await meera.req('GET', '/api/auth/me')).body.authenticated, false);
  assert.equal((await meera.req('POST', '/api/auth/login', { userId: 'Meera03', password: 'MeeraPass99' })).status, 401);
  assert.equal(db.prepare('SELECT id FROM users WHERE user_id = ?').get('Meera03'), undefined);
});

test('health endpoint allows internal HTTP probes in production and respects DATA_DIR/RAILWAY_VOLUME_MOUNT_PATH/DB_PATH', async () => {
  const volRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'spendwise-vol-'));
  const railDir = path.join(volRoot, 'rail-data');
  const customDb = path.join(volRoot, 'custom', 'nested', 'app.db');
  const prevEnv = {
    NODE_ENV: process.env.NODE_ENV,
    DATA_DIR: process.env.DATA_DIR,
    DB_PATH: process.env.DB_PATH,
    RAILWAY_VOLUME_MOUNT_PATH: process.env.RAILWAY_VOLUME_MOUNT_PATH,
  };

  try {
    process.env.NODE_ENV = 'production';
    delete process.env.DATA_DIR;
    delete process.env.DB_PATH;
    process.env.RAILWAY_VOLUME_MOUNT_PATH = railDir;

    const railCreated = createApp({ quiet: true, sessionSecret: 'rail-secret-key-at-least-32-characters-long' });
    const railServer = http.createServer(railCreated.app);
    await new Promise(resolve => railServer.listen(0, '127.0.0.1', resolve));
    const railUrl = `http://127.0.0.1:${railServer.address().port}`;
    try {
      const healthGet = await fetch(railUrl + '/health');
      assert.equal(healthGet.status, 200);
      assert.deepEqual(await healthGet.json(), { ok: true });
      assert.equal(healthGet.headers.get('cache-control'), 'no-store');

      const healthPost = await fetch(railUrl + '/health', { method: 'POST' });
      assert.equal(healthPost.status, 403);

      const rootHttp = await fetch(railUrl + '/', { redirect: 'manual' });
      assert.equal(rootHttp.status, 301);

      assert.equal(fs.existsSync(path.join(railDir, 'spendwise.db')), true);
    } finally {
      await new Promise(resolve => railServer.close(resolve));
      railCreated.db.close();
    }

    // DB_PATH takes precedence over DATA_DIR and creates nested parent dirs
    process.env.DATA_DIR = path.join(volRoot, 'data-dir');
    process.env.DB_PATH = customDb;
    const dbCreated = createApp({ quiet: true, sessionSecret: 'db-secret-key-at-least-32-characters-long-1' });
    dbCreated.db.close();
    assert.equal(fs.existsSync(customDb), true);
  } finally {
    for (const [k, v] of Object.entries(prevEnv)) {
      if (v === undefined) delete process.env[k];
      else process.env[k] = v;
    }
    fs.rmSync(volRoot, { recursive: true, force: true });
  }
});
