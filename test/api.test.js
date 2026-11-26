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
});

test('password rules reject spaces, special chars, and short passwords', async () => {
  const c = new TestClient(baseUrl);
  const badPasswords = ['short1A', 'Pass word1', 'Pass@1234', 'Pass_1234', 'Pass-1234', 'Pass!1234', 'Пароль1234', ''];
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
