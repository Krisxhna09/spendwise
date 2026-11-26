'use strict';

// ── Constants ─────────────────────────────────────────────────────────────────
const MAX_PAISE = 1_000_000_000_000; // ₹1,000 crore
const IN_NUMBER_FMT = new Intl.NumberFormat('en-IN');

const CAT_COLORS = [
  '#6c8ef5', '#34c97a', '#f5a623', '#f05454', '#9b6cf5',
  '#0dcaf0', '#fd7e14', '#20c997', '#e83e8c', '#6ea8fe',
];
const CAT_EMOJI = {
  'Food & Dining': '🍽️', 'Groceries': '🛒', 'Transport': '🚗', 'Shopping': '🛍️',
  'Bills & Utilities': '⚡', 'Utilities': '⚡', 'Rent & Housing': '🏠', 'Rent/Housing': '🏠',
  'Health': '💊', 'Entertainment': '🎬', 'Travel': '✈️', 'Education': '📚', 'Other': '📌',
};

const FORBIDDEN_KEYS = new Set(['__proto__', 'constructor', 'prototype']);

// ── Exact Paise Arithmetic & Indian Rupee Formatting (Zero Float Errors) ──────
/**
 * Parse rupee input string/number to exact integer paise (no float drift).
 * Returns null if invalid or > 2 decimal places.
 */
function parseRupeesToPaise(input, opts = {}) {
  const { allowNegative = false, allowZero = false } = opts;
  if (input === null || input === undefined) return null;
  const raw = String(input).trim().replace(/[₹,\s]/g, '');
  if (!raw || !/^[+-]?(?:\d+(?:\.\d{1,2})?|\.\d{1,2})$/.test(raw)) return null;

  const neg = raw.startsWith('-');
  if (neg && !allowNegative) return null;

  const unsigned = raw.replace(/^[+-]/, '');
  const [wholeRaw, fracRaw = ''] = unsigned.split('.');
  const whole = Number(wholeRaw || '0');
  const frac = Number(fracRaw.padEnd(2, '0'));
  if (!Number.isSafeInteger(whole) || !Number.isSafeInteger(frac)) return null;

  const absPaise = whole * 100 + frac;
  if (!Number.isSafeInteger(absPaise) || absPaise > MAX_PAISE) return null;
  if (absPaise === 0 && !allowZero) return null;

  return neg && absPaise > 0 ? -absPaise : absPaise;
}

/**
 * Format integer paise as Indian Rupees: e.g. 12500050 -> "₹1,25,000.50".
 */
function formatINR(paise) {
  const n = Number.isFinite(paise) ? Math.trunc(paise) : 0;
  const sign = n < 0 ? '-' : '';
  const abs = Math.abs(n);
  const rupees = Math.floor(abs / 100);
  const p = String(abs % 100).padStart(2, '0');
  return `${sign}₹${IN_NUMBER_FMT.format(rupees)}.${p}`;
}

/**
 * Format integer paise as plain decimal string for inputs/CSV: e.g. 12500050 -> "125000.50".
 */
function paiseToInputStr(paise) {
  const n = Number.isFinite(paise) ? Math.trunc(paise) : 0;
  const sign = n < 0 ? '-' : '';
  const abs = Math.abs(n);
  const rupees = Math.floor(abs / 100);
  const p = String(abs % 100).padStart(2, '0');
  return `${sign}${rupees}.${p}`;
}

// ── Authoritative State (always synced with SQL backend; CSRF kept in memory) ──
let csrfToken = '';
let S = resetStateObj();

function resetStateObj() {
  return {
    userId: null,
    setupDone: false,
    period: 'monthly',
    limitPaise: 1000000, // ₹10,000.00
    balancePaise: 0,
    alertThreshold: 80,
    notifInApp: true,
    notifBrowser: false,
    alertFired: {},
    catBudgetsPaise: {},
    needsCurrencyReview: false,
    legacyCurrency: null,
    legacyLimitAmount: null,
    legacyBalance: null,
    catObjs: [],
    transactions: [],
    filteredTx: null,
  };
}

let dashPeriod = null;
let dashOffset = 0;
let rptPeriod = null;
let rptOffset = 0;
let txFilterType = 'all';
let isSavingTx = false;
let currentClientReqId = null;
let lastSyncAt = 0;

// ── Safe DOM Helpers (DOM APIs & textContent only) ────────────────────────────
/**
 * Build a DOM element safely using textContent and explicit attributes/listeners.
 */
function makeEl(tag, attrs, ...children) {
  const node = document.createElement(tag);
  if (attrs) {
    for (const [k, v] of Object.entries(attrs)) {
      if (v === undefined || v === null) continue;
      if (k === 'className') node.className = v;
      else if (k === 'text') node.textContent = String(v);
      else if (k === 'value') node.value = String(v);
      else if (k === 'style' && typeof v === 'object') Object.assign(node.style, v);
      else if (k === 'dataset' && typeof v === 'object') Object.assign(node.dataset, v);
      else node.setAttribute(k, String(v));
    }
  }
  for (const child of children) {
    if (child === null || child === undefined || child === false) continue;
    node.appendChild(typeof child === 'string' ? document.createTextNode(child) : child);
  }
  return node;
}

function hasOwn(obj, key) {
  return Boolean(obj) && !FORBIDDEN_KEYS.has(key) && Object.prototype.hasOwnProperty.call(obj, key);
}

function sanitizeAlertFiredMap(raw) {
  const clean = {};
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return clean;
  for (const [k, v] of Object.entries(raw)) {
    if (FORBIDDEN_KEYS.has(k) || !k) continue;
    if (v === true || v === false) clean[k] = v;
  }
  return clean;
}

function sanitizeCatBudgetsMap(raw) {
  const clean = {};
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return clean;
  for (const [k, v] of Object.entries(raw)) {
    if (FORBIDDEN_KEYS.has(k) || !k) continue;
    const n = Number(v);
    if (Number.isSafeInteger(n) && n > 0) clean[k] = n;
  }
  return clean;
}

function catColor(cat) {
  const i = S.catObjs.findIndex(c => c.name.toLowerCase() === String(cat).toLowerCase());
  return CAT_COLORS[(i < 0 ? 0 : i) % CAT_COLORS.length];
}
function catEmoji(cat) {
  return hasOwn(CAT_EMOJI, String(cat)) ? CAT_EMOJI[String(cat)] : '📝';
}
function todayStr() {
  const d = new Date();
  return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')}`;
}

function periodRange(period, offset = 0) {
  const now = new Date();
  let start, end;
  if (period === 'weekly') {
    const base = new Date(now.getFullYear(), now.getMonth(), now.getDate() - now.getDay() + offset * 7);
    start = new Date(base.getFullYear(), base.getMonth(), base.getDate(), 0, 0, 0, 0);
    end = new Date(start.getFullYear(), start.getMonth(), start.getDate() + 6, 23, 59, 59, 999);
  } else if (period === 'monthly') {
    start = new Date(now.getFullYear(), now.getMonth() + offset, 1, 0, 0, 0, 0);
    end = new Date(start.getFullYear(), start.getMonth() + 1, 0, 23, 59, 59, 999);
  } else {
    const yr = now.getFullYear() + offset;
    start = new Date(yr, 0, 1, 0, 0, 0, 0);
    end = new Date(yr, 11, 31, 23, 59, 59, 999);
  }
  return { start, end };
}

function txInPeriod(tx, period, offset = 0) {
  const { start, end } = periodRange(period, offset);
  const d = new Date(tx.date + 'T12:00:00');
  return d >= start && d <= end;
}

function periodLabel(period, offset = 0) {
  const { start, end } = periodRange(period, offset);
  if (period === 'yearly') return String(start.getFullYear());
  if (period === 'monthly') return start.toLocaleDateString('en-IN', { month: 'short', year: 'numeric' });
  const o = { month: 'short', day: 'numeric' };
  return `${start.toLocaleDateString('en-IN', o)} – ${end.toLocaleDateString('en-IN', o)}`;
}

function formatDate(str) {
  if (!str) return '';
  return new Date(str + 'T12:00:00').toLocaleDateString('en-IN', { month: 'short', day: 'numeric', year: 'numeric' });
}

function getPeriodKey(period) {
  const { start } = periodRange(period, 0);
  return `${period}:${start.getFullYear()}-${String(start.getMonth() + 1).padStart(2, '0')}-${String(start.getDate()).padStart(2, '0')}`;
}

// ── UI Feedback: Toasts & Sync Indicator ──────────────────────────────────────
function toast(msg, type = 'info', ms = 4500) {
  const c = document.getElementById('toasts');
  const closeBtn = makeEl('button', { type: 'button', className: 'toast-close', 'aria-label': 'Dismiss', text: '✕' });
  const el = makeEl('div', { className: `toast ${type}` }, makeEl('span', { text: String(msg ?? '') }), closeBtn);
  closeBtn.addEventListener('click', () => el.remove());
  c.appendChild(el);
  setTimeout(() => el?.remove(), ms);
}

function setSyncState(mode) {
  const dot = document.getElementById('sync-dot');
  const lbl = document.getElementById('sync-label');
  if (!dot || !lbl) return;
  dot.className = 'sync-dot' + (mode === 'syncing' ? ' syncing' : mode === 'error' ? ' error' : '');
  lbl.textContent = mode === 'syncing' ? 'Syncing…' : mode === 'error' ? 'Sync issue' : 'Synced';
}

// ── API Client ────────────────────────────────────────────────────────────────
async function api(method, path, body) {
  const headers = { 'Content-Type': 'application/json' };
  if (csrfToken && method !== 'GET' && method !== 'HEAD') {
    headers['X-CSRF-Token'] = csrfToken;
  }
  const opts = { method, credentials: 'same-origin', headers };
  if (body !== undefined) opts.body = JSON.stringify(body);

  let res, data;
  try {
    res = await fetch(path, opts);
    data = await res.json();
  } catch {
    setSyncState('error');
    throw new Error('Network error. Please check your connection and try again.');
  }

  if (res.status === 401) {
    csrfToken = '';
    S = resetStateObj();
    showAuthScreen();
    throw new Error('Your session expired. Please log in again.');
  }
  if (!res.ok) {
    throw new Error(data.error || `Server error (${res.status})`);
  }
  return data;
}

async function btnAction(btn, fn) {
  const orig = btn.textContent;
  btn.disabled = true;
  btn.textContent = 'Please wait…';
  try {
    await fn();
  } catch (e) {
    toast(e.message, 'error');
  } finally {
    btn.disabled = false;
    btn.textContent = orig;
  }
}

// ── Sync User Data from Server ────────────────────────────────────────────────
async function loadUserData() {
  setSyncState('syncing');
  try {
    const [settings, cats, txs] = await Promise.all([
      api('GET', '/api/settings'),
      api('GET', '/api/categories'),
      api('GET', '/api/transactions'),
    ]);
    S.setupDone = settings.setupDone;
    S.period = settings.period;
    S.limitPaise = Number(settings.limitPaise);
    S.balancePaise = Number(settings.balancePaise);
    S.alertThreshold = settings.alertThreshold;
    S.notifInApp = settings.notifInApp;
    S.notifBrowser = settings.notifBrowser;
    S.alertFired = sanitizeAlertFiredMap(settings.alertFired);
    S.catBudgetsPaise = sanitizeCatBudgetsMap(settings.catBudgetsPaise);
    S.needsCurrencyReview = Boolean(settings.needsCurrencyReview);
    S.legacyCurrency = settings.legacyCurrency || null;
    S.legacyLimitAmount = settings.legacyLimitAmount || null;
    S.legacyBalance = settings.legacyBalance || null;
    S.catObjs = Array.isArray(cats) ? cats : [];
    S.transactions = Array.isArray(txs) ? txs : [];
    lastSyncAt = Date.now();
    setSyncState('ok');
  } catch (err) {
    setSyncState('error');
    throw err;
  }
}

async function manualSync() {
  if (!S.userId) return;
  try {
    await loadUserData();
    await loadFilteredTransactions();
    renderMainApp(true);
    toast('Synced with server.', 'ok', 2500);
  } catch (e) {
    toast(e.message, 'error');
  }
}

document.addEventListener('visibilitychange', () => {
  if (document.visibilityState === 'visible' && S.userId && S.setupDone && Date.now() - lastSyncAt > 10000) {
    loadUserData()
      .then(() => {
        if (hasActiveTxFilters()) return loadFilteredTransactions();
        S.filteredTx = null;
      })
      .then(() => renderMainApp(true))
      .catch(() => {});
  }
});

// ── Auth Flows ────────────────────────────────────────────────────────────────
function showAuthScreen() {
  document.getElementById('global-loader').style.display = 'none';
  document.getElementById('auth-screen').style.display = 'flex';
  document.getElementById('setup-screen').style.display = 'none';
  document.getElementById('app').style.display = 'none';
  document.getElementById('alert-banner').replaceChildren();
  document.getElementById('review-banner').replaceChildren();
}

function switchAuthTab(tab) {
  const isLogin = tab === 'login';
  document.getElementById('tab-login').classList.toggle('active', isLogin);
  document.getElementById('tab-register').classList.toggle('active', !isLogin);
  document.getElementById('tab-login').setAttribute('aria-selected', String(isLogin));
  document.getElementById('tab-register').setAttribute('aria-selected', String(!isLogin));
  document.getElementById('panel-login').classList.toggle('active', isLogin);
  document.getElementById('panel-register').classList.toggle('active', !isLogin);
  document.getElementById('login-err').classList.remove('show');
  document.getElementById('reg-err').classList.remove('show');
}

function togglePw(inputId, btn) {
  const inp = document.getElementById(inputId);
  const show = inp.type === 'password';
  inp.type = show ? 'text' : 'password';
  btn.textContent = show ? 'Hide' : 'Show';
  btn.setAttribute('aria-label', show ? 'Hide password' : 'Show password');
}

async function afterSignInFlow() {
  if (hasUnimportedLocalData()) {
    checkForLocalImport(false);
    return;
  }
  if (!S.setupDone) {
    startSetupWizard();
    return;
  }
  showScreen('dashboard');
  renderMainApp();
}

async function doLogout() {
  try {
    await api('POST', '/api/auth/logout');
  } catch {}
  csrfToken = '';
  S = resetStateObj();
  dashPeriod = null;
  dashOffset = 0;
  rptPeriod = null;
  rptOffset = 0;
  ['d-recent', 'd-cats', 'tx-list', 'b-cat-list', 'set-cats-list', 'alert-banner', 'review-banner', 'pie-legend', 'bar-chart', 'rpt-summary'].forEach(id => {
    const el = document.getElementById(id);
    if (el) el.replaceChildren();
  });
  document.getElementById('login-uid').value = '';
  document.getElementById('login-pw').value = '';
  document.getElementById('reg-uid').value = '';
  document.getElementById('reg-pw').value = '';
  document.getElementById('login-err').classList.remove('show');
  document.getElementById('reg-err').classList.remove('show');
  showAuthScreen();
}

// ── Local Browser Data Migration / Import ─────────────────────────────────────
function getOldLocalData() {
  try {
    const raw = localStorage.getItem('spendwise_v2');
    if (!raw) return null;
    const parsed = JSON.parse(raw);
    if (!parsed || typeof parsed !== 'object') return null;
    return parsed;
  } catch {
    return null;
  }
}

function getImportTrackMap() {
  try {
    const parsed = JSON.parse(localStorage.getItem('spendwise_imported_users') || '{}');
    return parsed && typeof parsed === 'object' && !Array.isArray(parsed) ? parsed : {};
  } catch {
    return {};
  }
}

function hasUnimportedLocalData(includeSkipped = false) {
  const old = getOldLocalData();
  if (!old) return false;
  const hasContent = (Array.isArray(old.transactions) && old.transactions.length > 0) || Boolean(old.setupDone);
  if (!hasContent) return false;
  const track = getImportTrackMap();
  if (!S.userId) return false;
  if (includeSkipped) return hasOwn(track, S.userId) ? track[S.userId] !== 'imported' : true;
  return !hasOwn(track, S.userId);
}

let openedFromSettings = false;
function checkForLocalImport(fromSettings) {
  openedFromSettings = Boolean(fromSettings);
  const old = getOldLocalData();
  if (!old) {
    if (!S.setupDone) startSetupWizard();
    return;
  }
  const txs = Array.isArray(old.transactions) ? old.transactions : [];
  const cats = Array.isArray(old.categories) ? old.categories : [];
  const localCur = String(old.currency || 'INR').toUpperCase();
  const foreignTxCount = txs.filter(t => String(t.currency || localCur).toUpperCase() !== 'INR').length;
  const hasNonInr = localCur !== 'INR' || foreignTxCount > 0;

  const listEl = document.getElementById('import-summary-list');
  listEl.replaceChildren(
    makeEl('li', null, makeEl('strong', { text: String(txs.length) }), ` recorded transaction${txs.length === 1 ? '' : 's'}`),
    makeEl('li', null, makeEl('strong', { text: String(cats.length) }), ` spending categor${cats.length === 1 ? 'y' : 'ies'}`),
    makeEl('li', { text: `Budget settings (${localCur}, ${String(old.period || 'monthly')} limit ${String(old.limit || '10000')})` })
  );

  const warnBox = document.getElementById('import-foreign-warn');
  if (hasNonInr) {
    warnBox.style.display = 'flex';
    document.getElementById('import-foreign-warn-text').textContent =
      `Your saved local data includes non-INR values (${localCur}). Importing will preserve their original values and flag them for review so you can confirm or enter their exact Indian rupee (₹) amounts.`;
  } else {
    warnBox.style.display = 'none';
  }

  document.getElementById('import-include-settings').checked = !S.setupDone;
  openModal('import-modal');
}

async function doImport() {
  const btn = document.getElementById('import-btn');
  await btnAction(btn, async () => {
    const old = getOldLocalData();
    if (!old) return;
    const importSettings = document.getElementById('import-include-settings').checked;
    const result = await api('POST', '/api/import', {
      transactions: Array.isArray(old.transactions) ? old.transactions : [],
      categories: Array.isArray(old.categories) ? old.categories : [],
      settings: old,
      importSettings,
    });
    const track = getImportTrackMap();
    if (S.userId && !FORBIDDEN_KEYS.has(S.userId)) {
      track[S.userId] = 'imported';
      localStorage.setItem('spendwise_imported_users', JSON.stringify(track));
    }
    closeModal('import-modal');
    await loadUserData();
    const parts = [`Imported ${result.imported} transaction${result.imported === 1 ? '' : 's'}`];
    if (result.flaggedForReview > 0) parts.push(`${result.flaggedForReview} flagged for INR review`);
    if (result.skipped > 0) parts.push(`${result.skipped} duplicate${result.skipped === 1 ? '' : 's'} skipped`);
    toast(parts.join(' · ') + '.', result.flaggedForReview > 0 ? 'info' : 'ok');

    if (openedFromSettings) {
      renderMainApp();
    } else if (!S.setupDone) {
      startSetupWizard();
    } else {
      showScreen('dashboard');
      renderMainApp();
    }
  });
}

function skipImport() {
  const track = getImportTrackMap();
  if (S.userId && !FORBIDDEN_KEYS.has(S.userId)) {
    track[S.userId] = 'skipped';
    localStorage.setItem('spendwise_imported_users', JSON.stringify(track));
  }
  closeModal('import-modal');
  if (openedFromSettings) return;
  if (!S.setupDone) startSetupWizard();
  else {
    showScreen('dashboard');
    renderMainApp();
  }
}

// ── Deliberate Non-INR Review Flow ────────────────────────────────────────────
function renderReviewBanner() {
  const banner = document.getElementById('review-banner');
  if (!banner) return;
  const flaggedTxs = S.transactions.filter(t => t.needsCurrencyReview);
  const totalFlagged = flaggedTxs.length + (S.needsCurrencyReview ? 1 : 0);
  if (totalFlagged === 0) {
    banner.replaceChildren();
    return;
  }

  const descParts = [];
  if (flaggedTxs.length) descParts.push(`${flaggedTxs.length} transaction${flaggedTxs.length === 1 ? '' : 's'}`);
  if (S.needsCurrencyReview) descParts.push(`budget settings (${S.legacyCurrency || 'previous currency'})`);
  const desc = `${descParts.join(' and ')} were previously recorded in another currency and are excluded from rupee totals until reviewed.`;

  const reviewBtn = makeEl('button', { type: 'button', className: 'alert-link', text: 'Review & confirm in ₹ →' });
  reviewBtn.addEventListener('click', openReviewModal);

  const item = makeEl(
    'div',
    { className: 'alert-item info', role: 'status' },
    makeEl('div', { className: 'alert-icon', 'aria-hidden': 'true', text: '₹' }),
    makeEl(
      'div',
      { style: { flex: '1', minWidth: '0' } },
      makeEl('div', { style: { fontWeight: '700', fontSize: '14px', marginBottom: '3px' }, text: 'Review non-INR records before treating as rupees' }),
      makeEl('div', { style: { fontSize: '13px', lineHeight: '1.5' }, text: desc }),
      makeEl('div', { className: 'alert-links' }, reviewBtn)
    )
  );
  banner.replaceChildren(item);
}

function openReviewModal() {
  const wrap = document.getElementById('review-items-wrap');
  const errEl = document.getElementById('review-err');
  errEl.classList.remove('show');
  const nodes = [];

  if (S.needsCurrencyReview) {
    const legCur = S.legacyCurrency || 'non-INR';
    const legLim = S.legacyLimitAmount || paiseToInputStr(S.limitPaise);
    const legBal = S.legacyBalance || paiseToInputStr(S.balancePaise);

    const limInput = makeEl('input', {
      className: 'field-input',
      type: 'number',
      step: '0.01',
      min: '0.01',
      id: 'rev-limit',
      value: paiseToInputStr(S.limitPaise),
      inputmode: 'decimal',
    });
    const balInput = makeEl('input', {
      className: 'field-input',
      type: 'number',
      step: '0.01',
      id: 'rev-balance',
      value: paiseToInputStr(S.balancePaise),
      inputmode: 'decimal',
    });
    const confirmSettingsBtn = makeEl('button', {
      type: 'button',
      className: 'btn btn-primary btn-sm',
      text: 'Confirm budget settings in ₹',
    });
    confirmSettingsBtn.addEventListener('click', () => confirmSettingsReview(confirmSettingsBtn));

    nodes.push(makeEl(
      'div',
      { className: 'review-row' },
      makeEl(
        'div',
        { style: { display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: '8px', flexWrap: 'wrap' } },
        makeEl('strong', { text: `Budget settings (${legCur})` }),
        makeEl('span', { className: 'badge badge-warn', text: 'Needs review' })
      ),
      makeEl('div', {
        style: { fontSize: '12.5px', color: 'var(--muted)' },
        text: `Original values — Limit: ${legLim} ${S.legacyCurrency || ''}, Balance: ${legBal} ${S.legacyCurrency || ''}`,
      }),
      makeEl(
        'div',
        { style: { display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '8px' } },
        makeEl('div', { className: 'field-group' }, makeEl('label', { className: 'field-label', for: 'rev-limit', text: 'Spending limit (₹)' }), limInput),
        makeEl('div', { className: 'field-group' }, makeEl('label', { className: 'field-label', for: 'rev-balance', text: 'Starting balance (₹)' }), balInput)
      ),
      confirmSettingsBtn
    ));
  }

  const flaggedTxs = S.transactions.filter(t => t.needsCurrencyReview);
  flaggedTxs.forEach(t => {
    const titleLabel = t.note || t.category;
    const amtInput = makeEl('input', {
      className: 'field-input amount-input',
      type: 'number',
      step: '0.01',
      min: '0.01',
      value: paiseToInputStr(t.amountPaise),
      inputmode: 'decimal',
      'aria-label': `Rupee amount for ${titleLabel}`,
    });
    const confirmBtn = makeEl('button', { type: 'button', className: 'btn btn-primary btn-sm', text: 'Confirm ₹' });
    confirmBtn.addEventListener('click', () => confirmTxReview(t.id, amtInput, confirmBtn));
    const delBtn = makeEl('button', { type: 'button', className: 'btn btn-danger btn-sm', text: 'Delete' });
    delBtn.addEventListener('click', () => deleteReviewedTx(t.id, delBtn));

    nodes.push(makeEl(
      'div',
      { className: 'review-row' },
      makeEl(
        'div',
        { style: { display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: '8px', flexWrap: 'wrap' } },
        makeEl('span', null, makeEl('strong', { text: titleLabel }), ` · ${formatDate(t.date)}`),
        makeEl('span', { className: 'badge badge-warn', text: `${t.originalCurrency || 'Foreign'} ${t.originalAmount || paiseToInputStr(t.amountPaise)}` })
      ),
      makeEl(
        'div',
        { style: { display: 'flex', gap: '8px', alignItems: 'center', flexWrap: 'wrap' } },
        makeEl('div', { className: 'amount-wrap', style: { flex: '1', minWidth: '140px' } }, makeEl('span', { className: 'amount-currency', text: '₹' }), amtInput),
        confirmBtn,
        delBtn
      )
    ));
  });

  if (!nodes.length) {
    wrap.replaceChildren(makeEl('div', { style: { color: 'var(--ok)', fontSize: '14px' }, text: '✓ All records are confirmed in Indian rupees (₹).' }));
  } else {
    wrap.replaceChildren(...nodes);
  }
  openModal('review-modal');
}

async function confirmSettingsReview(btn) {
  const errEl = document.getElementById('review-err');
  errEl.classList.remove('show');
  const limitPaise = parseRupeesToPaise(document.getElementById('rev-limit').value, { allowNegative: false, allowZero: false });
  const balancePaise = parseRupeesToPaise(document.getElementById('rev-balance').value, { allowNegative: true, allowZero: true });
  if (!limitPaise) {
    errEl.textContent = 'Spending limit must be positive (up to 2 decimal places for paise).';
    errEl.classList.add('show');
    return;
  }
  if (balancePaise === null) {
    errEl.textContent = 'Starting balance must be valid (up to 2 decimal places for paise).';
    errEl.classList.add('show');
    return;
  }
  await btnAction(btn, async () => {
    await api('PUT', '/api/settings', { limitPaise, balancePaise, confirmCurrencyReview: true });
    await loadUserData();
    renderMainApp();
    openReviewModal();
    toast('Budget settings confirmed in ₹.', 'ok', 2800);
  });
}

async function confirmTxReview(txId, inp, btn) {
  const errEl = document.getElementById('review-err');
  errEl.classList.remove('show');
  const amountPaise = parseRupeesToPaise(inp.value, { allowNegative: false, allowZero: false });
  if (!amountPaise) {
    errEl.textContent = 'Enter a positive rupee amount (up to 2 decimal places for paise).';
    errEl.classList.add('show');
    return;
  }
  await btnAction(btn, async () => {
    await api('POST', `/api/transactions/${encodeURIComponent(txId)}/review-inr`, { amountPaise });
    await loadUserData();
    if (hasActiveTxFilters()) await loadFilteredTransactions();
    else S.filteredTx = null;
    renderMainApp();
    openReviewModal();
    toast('Transaction confirmed in ₹.', 'ok', 2800);
  });
}

async function deleteReviewedTx(txId, btn) {
  await btnAction(btn, async () => {
    await api('DELETE', `/api/transactions/${encodeURIComponent(txId)}`);
    await loadUserData();
    if (hasActiveTxFilters()) await loadFilteredTransactions();
    else S.filteredTx = null;
    renderMainApp();
    openReviewModal();
    toast('Transaction deleted.', 'ok', 2800);
  });
}

// ── First-Time Setup Wizard (4 Steps — INR only) ──────────────────────────────
let setupStep = 1;
const SETUP_TOTAL = 4;
const setupExtraCats = [];

function startSetupWizard() {
  setupStep = 1;
  setupExtraCats.length = 0;
  document.getElementById('s-cats-list').replaceChildren();
  document.getElementById('s-limit').value = paiseToInputStr(S.limitPaise || 1000000);
  document.getElementById('s-balance').value = S.balancePaise ? paiseToInputStr(S.balancePaise) : '';
  document.getElementById('setup-err').classList.remove('show');
  updateSetupUI();
  document.getElementById('global-loader').style.display = 'none';
  document.getElementById('setup-screen').style.display = 'flex';
}

function updateSetupUI() {
  document.getElementById('setup-step-label').textContent = `Step ${setupStep} of ${SETUP_TOTAL}`;
  const dotsEl = document.getElementById('step-dots');
  dotsEl.replaceChildren();
  for (let i = 1; i <= SETUP_TOTAL; i++) {
    const d = document.createElement('div');
    d.className = 'step-dot' + (i <= setupStep ? ' done' : '');
    dotsEl.appendChild(d);
  }
  document.querySelectorAll('.setup-step').forEach(el => el.classList.remove('active'));
  document.getElementById(`setup-${setupStep}`).classList.add('active');
  document.getElementById('s-back').style.visibility = setupStep > 1 ? 'visible' : 'hidden';
  document.getElementById('s-skip').style.display = setupStep === SETUP_TOTAL ? 'inline-flex' : 'none';
  document.getElementById('s-next').textContent = setupStep === SETUP_TOTAL ? 'Finish setup →' : 'Continue →';
  document.getElementById('setup-err').classList.remove('show');
}

function pickSetupLimit(rupees) {
  document.getElementById('s-limit').value = String(rupees);
  document.querySelectorAll('#s-limit-presets .toggle-btn').forEach(b => {
    const num = parseInt(b.textContent.replace(/[₹,]/g, ''), 10);
    b.classList.toggle('active', num === rupees);
  });
}

async function onSetupBrowserToggle(cb) {
  const statusEl = document.getElementById('s-browser-status');
  if (!cb.checked) {
    statusEl.textContent = '';
    return;
  }
  if (!('Notification' in window)) {
    statusEl.textContent = 'Browser notifications are not supported on this device. In-app alerts will be used instead.';
    cb.checked = false;
    return;
  }
  if (Notification.permission === 'default') {
    const perm = await Notification.requestPermission();
    if (perm !== 'granted') {
      statusEl.textContent = 'Permission was not granted. In-app alerts will continue working normally.';
      cb.checked = false;
      return;
    }
  } else if (Notification.permission === 'denied') {
    statusEl.textContent = 'Notifications are blocked in your browser settings. In-app alerts will still notify you.';
    cb.checked = false;
    return;
  }
  statusEl.textContent = '✓ Browser notifications enabled.';
}

function setupBack() {
  if (setupStep > 1) {
    setupStep--;
    updateSetupUI();
  }
}

function setupSkip() {
  finishSetup(true);
}

function setupNext() {
  const errEl = document.getElementById('setup-err');
  errEl.classList.remove('show');

  if (setupStep === 1) {
    const paise = parseRupeesToPaise(document.getElementById('s-limit').value, { allowNegative: false, allowZero: false });
    if (!paise) {
      errEl.textContent = 'Enter a spending limit greater than ₹0.00 (up to 2 decimal places for paise).';
      errEl.classList.add('show');
      return;
    }
  }
  if (setupStep === 2) {
    const active = document.querySelector('#s-thresh-grp .toggle-btn.active');
    if (active && active.dataset.val === 'custom') {
      const pct = parseInt(document.getElementById('s-custom-pct').value, 10);
      if (!Number.isInteger(pct) || pct < 1 || pct > 200) {
        errEl.textContent = 'Please enter a whole percentage between 1 and 200.';
        errEl.classList.add('show');
        return;
      }
    }
  }
  if (setupStep < SETUP_TOTAL) {
    setupStep++;
    updateSetupUI();
  } else {
    finishSetup(false);
  }
}

function getSetupThreshold() {
  const a = document.querySelector('#s-thresh-grp .toggle-btn.active');
  if (!a) return 80;
  if (a.dataset.val === 'custom') return parseInt(document.getElementById('s-custom-pct').value, 10) || 80;
  return parseInt(a.dataset.val, 10) || 80;
}

function setupAddCat() {
  const inp = document.getElementById('s-new-cat');
  const v = inp.value.trim();
  if (!v) return;
  if (!setupExtraCats.some(c => c.toLowerCase() === v.toLowerCase())) {
    setupExtraCats.push(v);
  }
  inp.value = '';
  renderSetupCats();
}

function renderSetupCats() {
  const listEl = document.getElementById('s-cats-list');
  const chips = setupExtraCats.map((c, i) => {
    const rmBtn = makeEl('button', {
      type: 'button',
      style: { background: 'none', border: 'none', color: 'inherit', cursor: 'pointer', fontSize: '14px', padding: '0 2px' },
      'aria-label': `Remove ${c}`,
      text: '✕',
    });
    rmBtn.addEventListener('click', () => setupRemoveCat(i));
    return makeEl('span', { className: 'chip active' }, `${c} `, rmBtn);
  });
  listEl.replaceChildren(...chips);
}
function setupRemoveCat(i) { setupExtraCats.splice(i, 1); renderSetupCats(); }

async function finishSetup(skippedLast) {
  const btn = document.getElementById('s-next');
  const skipBtn = document.getElementById('s-skip');
  const errEl = document.getElementById('setup-err');
  errEl.classList.remove('show');

  const limitPaise = parseRupeesToPaise(document.getElementById('s-limit').value, { allowNegative: false, allowZero: false });
  if (!limitPaise) {
    errEl.textContent = 'Enter a valid spending limit in rupees and paise.';
    errEl.classList.add('show');
    return;
  }

  let balancePaise = 0;
  if (!skippedLast) {
    const rawBal = document.getElementById('s-balance').value.trim();
    if (rawBal !== '') {
      const parsed = parseRupeesToPaise(rawBal, { allowNegative: true, allowZero: true });
      if (parsed === null) {
        errEl.textContent = 'Starting balance must be in rupees and paise (at most 2 decimal places).';
        errEl.classList.add('show');
        return;
      }
      balancePaise = parsed;
    }
  }

  const orig = btn.textContent;
  btn.disabled = true;
  skipBtn.disabled = true;
  btn.textContent = 'Saving…';
  try {
    const period = document.querySelector('#s-period-grp .toggle-btn.active')?.dataset.val || 'monthly';
    await api('PUT', '/api/settings', {
      setupDone: true,
      period,
      limitPaise,
      balancePaise,
      alertThreshold: getSetupThreshold(),
      notifInApp: document.getElementById('s-inapp').checked,
      notifBrowser: document.getElementById('s-browser').checked,
    });

    if (!skippedLast) {
      for (const name of setupExtraCats) {
        try { await api('POST', '/api/categories', { name }); } catch {}
      }
    }

    await loadUserData();
    document.getElementById('setup-screen').style.display = 'none';
    showScreen('dashboard');
    renderMainApp();
    toast('All set! Your rupee budget is ready.', 'ok', 3500);
  } catch (e) {
    errEl.textContent = e.message;
    errEl.classList.add('show');
  } finally {
    btn.disabled = false;
    skipBtn.disabled = false;
    btn.textContent = orig;
  }
}

// ── Main App Render & Navigation ──────────────────────────────────────────────
function renderMainApp(skipAlerts = false) {
  document.getElementById('global-loader').style.display = 'none';
  document.getElementById('auth-screen').style.display = 'none';
  document.getElementById('setup-screen').style.display = 'none';
  document.getElementById('app').style.display = 'block';

  document.getElementById('sidebar-user').textContent = `User: ${S.userId}`;
  document.getElementById('set-user-id').textContent = S.userId || '';
  document.getElementById('set-import-row').style.display = hasUnimportedLocalData(true) ? 'flex' : 'none';

  const flaggedCount = S.transactions.filter(t => t.needsCurrencyReview).length + (S.needsCurrencyReview ? 1 : 0);
  document.getElementById('set-review-row').style.display = flaggedCount > 0 ? 'flex' : 'none';
  document.getElementById('set-review-sub').textContent = `${flaggedCount} item${flaggedCount === 1 ? '' : 's'} recorded in another currency need review`;

  renderReviewBanner();
  populateFilterCategories();
  syncSettingsUI();
  updateDashboard();
  renderTransactions();
  renderBudgets();
  if (currentScreen === 'reports') renderReports();
  if (!skipAlerts) checkAlerts();
}

let currentScreen = 'dashboard';
function showScreen(name) {
  currentScreen = name;
  document.querySelectorAll('.screen').forEach(s => s.classList.remove('active'));
  document.getElementById(`screen-${name}`).classList.add('active');

  document.querySelectorAll('.nav-item, .bnav-item').forEach(el => {
    const active = el.dataset.screen === name;
    el.classList.toggle('active', active);
    if (active) el.setAttribute('aria-current', 'page');
    else el.removeAttribute('aria-current');
  });

  const titles = {
    dashboard: 'Dashboard',
    transactions: 'Transactions',
    budgets: 'Budgets',
    reports: 'Reports',
    settings: 'Settings',
  };
  document.getElementById('topbar-title').textContent = hasOwn(titles, name) ? titles[name] : name;

  if (name === 'reports') renderReports();
  if (name === 'budgets') renderBudgets();
  if (name === 'settings') syncSettingsUI();
  if (name === 'transactions') renderTransactions();
}

// ── Dashboard (Exact Paise Calculations) ──────────────────────────────────────
function setPeriodView(p) {
  dashPeriod = p;
  dashOffset = 0;
  updateDashboard();
}

function shiftDashOffset(delta) {
  dashOffset = delta === 0 ? 0 : dashOffset + delta;
  updateDashboard();
}

function confirmedInrTx() {
  return S.transactions.filter(t => !t.needsCurrencyReview);
}

function updateDashboard() {
  if (!S.userId) return;
  const period = dashPeriod || S.period;
  document.querySelectorAll('[data-vp]').forEach(b => b.classList.toggle('active', b.dataset.vp === period));
  document.getElementById('period-label').textContent = periodLabel(period, dashOffset);

  const inrTx = confirmedInrTx();
  const periodTx = inrTx.filter(t => txInPeriod(t, period, dashOffset));
  const incomePaise = periodTx.filter(t => t.type === 'income').reduce((a, t) => a + t.amountPaise, 0);
  const expensesPaise = periodTx.filter(t => t.type === 'expense').reduce((a, t) => a + t.amountPaise, 0);

  const totalIncPaise = inrTx.filter(t => t.type === 'income').reduce((a, t) => a + t.amountPaise, 0);
  const totalExpPaise = inrTx.filter(t => t.type === 'expense').reduce((a, t) => a + t.amountPaise, 0);
  const balancePaise = (S.balancePaise || 0) + totalIncPaise - totalExpPaise;
  const remainingPaise = S.limitPaise - expensesPaise;

  document.getElementById('d-balance').textContent = formatINR(balancePaise);
  document.getElementById('d-income').textContent = formatINR(incomePaise);
  document.getElementById('d-expenses').textContent = formatINR(expensesPaise);
  document.getElementById('d-income-sub').textContent = periodLabel(period, dashOffset);
  document.getElementById('d-expenses-sub').textContent = periodLabel(period, dashOffset);

  const remTitle = document.getElementById('d-rem-title');
  const remVal = document.getElementById('d-remaining');
  const remSub = document.getElementById('d-rem-sub');
  if (remainingPaise >= 0) {
    remTitle.textContent = 'Remaining budget';
    remVal.textContent = formatINR(remainingPaise);
    remVal.style.color = 'var(--ok)';
    remSub.textContent = `of ${formatINR(S.limitPaise)} limit`;
  } else {
    remTitle.textContent = 'Over budget by';
    remVal.textContent = formatINR(Math.abs(remainingPaise));
    remVal.style.color = 'var(--danger)';
    remSub.textContent = `Limit was ${formatINR(S.limitPaise)}`;
  }

  const rawPct = S.limitPaise > 0 ? (expensesPaise / S.limitPaise) * 100 : 0;
  const barPct = Math.min(rawPct, 100);
  const bar = document.getElementById('d-progress');
  bar.style.width = barPct + '%';
  bar.className = 'progress-bar' + (rawPct > 100 ? ' danger' : rawPct >= S.alertThreshold ? ' warn' : '');
  document.getElementById('d-progress-wrap').setAttribute('aria-valuenow', String(Math.round(barPct)));

  let statusText, statusClass, statusIcon;
  if (rawPct > 100) {
    statusText = 'Over budget';
    statusClass = 'danger';
    statusIcon = '!';
  } else if (rawPct >= S.alertThreshold) {
    statusText = 'Near your limit';
    statusClass = 'warn';
    statusIcon = '▲';
  } else {
    statusText = 'On track';
    statusClass = 'ok';
    statusIcon = '✓';
  }

  const periodMatchNote = period !== S.period ? ` (your budget limit is ${S.period})` : '';
  document.getElementById('d-status-text').textContent = `${statusIcon} ${statusText}`;
  document.getElementById('d-status-text').style.color = `var(--${statusClass})`;
  document.getElementById('d-status-meta').textContent = `${rawPct.toFixed(0)}% of ${formatINR(S.limitPaise)} used · ${periodLabel(period, dashOffset)}${periodMatchNote}`;
  document.getElementById('d-status-badge').replaceChildren(
    makeEl('span', { className: `badge badge-${statusClass}`, text: `${statusIcon} ${statusText}` })
  );
  document.getElementById('d-spent-lbl').textContent = `Spent: ${formatINR(expensesPaise)}`;
  document.getElementById('d-limit-lbl').textContent = `Limit: ${formatINR(S.limitPaise)} (${remainingPaise >= 0 ? formatINR(remainingPaise) + ' left' : formatINR(Math.abs(remainingPaise)) + ' over'})`;

  // Recent transactions
  const recent = [...S.transactions].sort((a, b) => new Date(b.date) - new Date(a.date)).slice(0, 5);
  const rEl = document.getElementById('d-recent');
  if (!recent.length) {
    const addBtn = makeEl('button', { type: 'button', className: 'btn btn-primary btn-sm', text: '+ Add transaction' });
    addBtn.addEventListener('click', openAddTransaction);
    rEl.replaceChildren(makeEl(
      'div',
      { className: 'empty-state', style: { padding: '20px 8px' } },
      makeEl('div', { className: 'empty-icon', text: '📋' }),
      makeEl('div', { className: 'empty-title', text: 'No rupee transactions yet' }),
      makeEl('div', { className: 'empty-sub', text: 'Record your first income or expense in ₹ (for example, ₹250.50).' }),
      addBtn
    ));
  } else {
    rEl.replaceChildren(...recent.map(t => {
      const amountNode = t.needsCurrencyReview
        ? makeEl('span', { className: 'badge badge-warn', text: `${t.originalCurrency || 'Review'} ${t.originalAmount || paiseToInputStr(t.amountPaise)}` })
        : makeEl('div', { className: `tx-amount num ${t.type}`, text: `${t.type === 'expense' ? '−' : '+'}${formatINR(t.amountPaise)}` });

      const row = makeEl(
        'div',
        { className: 'tx-row', role: 'button', tabindex: '0' },
        makeEl('div', { className: 'tx-icon', style: { background: `${catColor(t.category)}22` }, text: catEmoji(t.category) }),
        makeEl(
          'div',
          { className: 'tx-info' },
          makeEl('div', { className: 'tx-name', text: t.note || t.category }),
          makeEl('div', { className: 'tx-meta', text: `${formatDate(t.date)} · ${t.category}${t.needsCurrencyReview ? ' · Needs INR review' : ''}` })
        ),
        amountNode
      );
      row.addEventListener('click', () => openEditTx(t.id));
      row.addEventListener('keydown', e => {
        if (e.key === 'Enter') openEditTx(t.id);
      });
      return row;
    }));
  }

  // Category breakdown (exact integer paise)
  const catMap = Object.create(null);
  periodTx.filter(t => t.type === 'expense').forEach(t => {
    const key = String(t.category || 'Other');
    catMap[key] = (catMap[key] || 0) + t.amountPaise;
  });
  const entries = Object.entries(catMap).sort((a, b) => b[1] - a[1]).slice(0, 6);
  const cEl = document.getElementById('d-cats');
  if (!entries.length) {
    cEl.replaceChildren(makeEl('div', {
      style: { color: 'var(--muted)', fontSize: '13.5px', padding: '24px 0', textAlign: 'center' },
      text: 'No expenses recorded in this period.',
    }));
  } else {
    cEl.replaceChildren(...entries.map(([cat, amtPaise]) => {
      const p = expensesPaise > 0 ? Math.round((amtPaise / expensesPaise) * 100) : 0;
      return makeEl(
        'div',
        { className: 'cat-row' },
        makeEl(
          'div',
          { style: { display: 'flex', justifyContent: 'space-between', marginBottom: '5px', fontSize: '13px', gap: '8px' } },
          makeEl('span', { style: { fontWeight: '600', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }, text: `${catEmoji(cat)} ${cat}` }),
          makeEl('span', { className: 'num', style: { color: 'var(--muted)', flexShrink: '0' }, text: `${formatINR(amtPaise)} · ${p}%` })
        ),
        makeEl(
          'div',
          { className: 'progress-wrap', style: { height: '7px' } },
          makeEl('div', { className: 'progress-bar', style: { width: `${p}%`, background: catColor(cat) } })
        )
      );
    }));
  }
}

// ── Transactions Screen (Server-Side Parameterized Search/Filter/Sort) ────────
function populateFilterCategories() {
  const sel = document.getElementById('tx-filter-cat');
  if (!sel) return;
  const prev = sel.value || 'all';
  sel.replaceChildren(
    makeEl('option', { value: 'all', text: 'All categories' }),
    ...S.catObjs.map(c => makeEl('option', { value: c.name, text: c.name }))
  );
  if ([...sel.options].some(o => o.value === prev)) sel.value = prev;
}

function hasActiveTxFilters() {
  const q = (document.getElementById('tx-search')?.value || '').trim();
  const cat = document.getElementById('tx-filter-cat')?.value || 'all';
  const from = document.getElementById('tx-filter-from')?.value || '';
  const to = document.getElementById('tx-filter-to')?.value || '';
  const sort = document.getElementById('tx-sort')?.value || 'date:desc';
  return Boolean(q || txFilterType !== 'all' || cat !== 'all' || from || to || sort !== 'date:desc');
}

function setTxFilter(f) {
  txFilterType = f;
  document.querySelectorAll('.filter-row .chip').forEach(c => c.classList.toggle('active', c.dataset.f === f));
  loadFilteredTransactions();
}

function clearTxSearch() {
  document.getElementById('tx-search').value = '';
  loadFilteredTransactions();
}

function resetTxFilters() {
  txFilterType = 'all';
  document.querySelectorAll('.filter-row .chip').forEach(c => c.classList.toggle('active', c.dataset.f === 'all'));
  document.getElementById('tx-search').value = '';
  document.getElementById('tx-filter-cat').value = 'all';
  document.getElementById('tx-filter-from').value = '';
  document.getElementById('tx-filter-to').value = '';
  document.getElementById('tx-sort').value = 'date:desc';
  S.filteredTx = null;
  renderTransactions();
}

let searchDebounceTimer;
function debouncedLoadTransactions() {
  clearTimeout(searchDebounceTimer);
  searchDebounceTimer = setTimeout(loadFilteredTransactions, 200);
}

async function loadFilteredTransactions() {
  if (!S.userId) return;
  const active = hasActiveTxFilters();
  document.getElementById('tx-clear-filters').style.display = active ? 'inline-flex' : 'none';
  if (!active) {
    S.filteredTx = null;
    renderTransactions();
    return;
  }

  const params = new URLSearchParams();
  const q = document.getElementById('tx-search').value.trim();
  const cat = document.getElementById('tx-filter-cat').value;
  const from = document.getElementById('tx-filter-from').value;
  const to = document.getElementById('tx-filter-to').value;
  const [sortBy, sortDir] = (document.getElementById('tx-sort').value || 'date:desc').split(':');

  if (q) params.set('q', q);
  if (txFilterType !== 'all') params.set('type', txFilterType);
  if (cat !== 'all') params.set('category', cat);
  if (from) params.set('from', from);
  if (to) params.set('to', to);
  if (sortBy) params.set('sortBy', sortBy);
  if (sortDir) params.set('sortDir', sortDir);

  try {
    setSyncState('syncing');
    S.filteredTx = await api('GET', `/api/transactions?${params.toString()}`);
    setSyncState('ok');
    renderTransactions();
  } catch (e) {
    toast(e.message, 'error');
  }
}

function renderTransactions() {
  if (!S.userId) return;
  const active = hasActiveTxFilters();
  document.getElementById('tx-clear-filters').style.display = active ? 'inline-flex' : 'none';

  const txs = S.filteredTx !== null ? S.filteredTx : S.transactions;
  document.getElementById('tx-count-label').textContent = `${txs.length} transaction${txs.length === 1 ? '' : 's'}${active ? ' matching filters' : ''}`;

  const el = document.getElementById('tx-list');
  if (!txs.length) {
    if (active) {
      const clearBtn = makeEl('button', { type: 'button', className: 'btn btn-ghost btn-sm', text: 'Clear filters' });
      clearBtn.addEventListener('click', resetTxFilters);
      el.replaceChildren(makeEl(
        'div',
        { className: 'empty-state' },
        makeEl('div', { className: 'empty-icon', text: '🔍' }),
        makeEl('div', { className: 'empty-title', text: 'No matching transactions' }),
        makeEl('div', { className: 'empty-sub', text: 'Try adjusting your search or date/category filters.' }),
        clearBtn
      ));
    } else {
      const addBtn = makeEl('button', { type: 'button', className: 'btn btn-primary btn-sm', text: '+ Add first transaction' });
      addBtn.addEventListener('click', openAddTransaction);
      el.replaceChildren(makeEl(
        'div',
        { className: 'empty-state' },
        makeEl('div', { className: 'empty-icon', text: '₹' }),
        makeEl('div', { className: 'empty-title', text: 'No rupee transactions yet' }),
        makeEl('div', { className: 'empty-sub', text: 'Add an income or expense entry in rupees and paise (for example, ₹250.50).' }),
        addBtn
      ));
    }
    return;
  }

  const sortVal = document.getElementById('tx-sort')?.value || 'date:desc';
  const groupByDate = sortVal.startsWith('date:');

  if (!groupByDate) {
    el.replaceChildren(...txs.map(renderTxRowNode));
    return;
  }

  const grouped = Object.create(null);
  txs.forEach(t => {
    const dk = String(t.date || '');
    if (!grouped[dk]) grouped[dk] = [];
    grouped[dk].push(t);
  });
  const keys = Object.keys(grouped).sort((a, b) => sortVal === 'date:asc' ? a.localeCompare(b) : b.localeCompare(a));

  const fragment = document.createDocumentFragment();
  keys.forEach(date => {
    fragment.appendChild(makeEl('div', {
      style: { margin: '12px 0 6px', fontSize: '11px', fontWeight: '700', letterSpacing: '0.08em', textTransform: 'uppercase', color: 'var(--muted)' },
      text: formatDate(date),
    }));
    grouped[date].forEach(t => fragment.appendChild(renderTxRowNode(t)));
  });
  el.replaceChildren(fragment);
}

function renderTxRowNode(t) {
  const amtNode = t.needsCurrencyReview
    ? makeEl('span', { className: 'badge badge-warn', text: `Needs review (${t.originalCurrency || ''} ${t.originalAmount || paiseToInputStr(t.amountPaise)})` })
    : makeEl('div', { className: `tx-amount num ${t.type}`, text: `${t.type === 'expense' ? '−' : '+'}${formatINR(t.amountPaise)}` });

  const editBtn = makeEl('button', { type: 'button', className: 'btn btn-icon', 'aria-label': 'Edit transaction', title: 'Edit', text: '✏️' });
  editBtn.addEventListener('click', e => {
    e.stopPropagation();
    openEditTx(t.id);
  });

  const delBtn = makeEl('button', { type: 'button', className: 'btn btn-icon', 'aria-label': 'Delete transaction', title: 'Delete', text: '🗑️' });
  delBtn.addEventListener('click', e => {
    e.stopPropagation();
    askDeleteTx(t.id);
  });

  const row = makeEl(
    'div',
    { className: `tx-list-item${t.needsCurrencyReview ? ' needs-review' : ''}`, role: 'button', tabindex: '0' },
    makeEl('div', { className: 'tx-icon', style: { background: `${catColor(t.category)}22` }, text: catEmoji(t.category) }),
    makeEl(
      'div',
      { className: 'tx-info' },
      makeEl('div', { className: 'tx-name', text: t.note || t.category }),
      makeEl('div', { className: 'tx-meta', text: `${t.category} · ${formatDate(t.date)}${t.needsCurrencyReview ? ' · Review required before counting in ₹' : ' · INR'}` })
    ),
    makeEl(
      'div',
      { className: 'tx-right' },
      amtNode,
      makeEl('div', { className: 'tx-actions' }, editBtn, delBtn)
    )
  );
  row.addEventListener('click', () => openEditTx(t.id));
  row.addEventListener('keydown', e => {
    if (e.key === 'Enter') openEditTx(t.id);
  });
  return row;
}

// ── Add / Edit Transaction Modal (INR only) ───────────────────────────────────
let editTxId = null;
let txType = 'expense';

function setTxType(t) {
  txType = t;
  document.getElementById('type-expense').classList.toggle('active', t === 'expense');
  document.getElementById('type-income').classList.toggle('active', t === 'income');
}

function populateCategorySelect(selected) {
  const sel = document.getElementById('tx-category');
  const names = S.catObjs.map(c => c.name);
  if (selected && !names.includes(selected)) names.push(selected);
  sel.replaceChildren(...names.map(name => makeEl('option', { value: name, text: name })));
  if (selected) sel.value = selected;
}

function openAddTransaction() {
  editTxId = null;
  currentClientReqId = Date.now().toString(36) + '-' + Math.random().toString(36).slice(2);
  setTxType('expense');
  document.getElementById('tx-modal-title').textContent = 'Add transaction (₹)';
  document.getElementById('tx-form').reset();
  document.getElementById('tx-date').value = todayStr();
  document.getElementById('tx-amount-err').classList.remove('show');
  document.getElementById('tx-review-notice').style.display = 'none';
  document.getElementById('tx-review-notice').replaceChildren();
  document.getElementById('tx-modal-del-btn').style.display = 'none';
  populateCategorySelect();
  openModal('tx-modal');
  setTimeout(() => document.getElementById('tx-amount').focus(), 220);
}

function openEditTx(id) {
  const t = S.transactions.find(item => item.id === id) || (S.filteredTx || []).find(item => item.id === id);
  if (!t) return;
  editTxId = id;
  currentClientReqId = null;
  setTxType(t.type);
  document.getElementById('tx-modal-title').textContent = t.needsCurrencyReview ? 'Review & save in ₹' : 'Edit transaction (₹)';
  document.getElementById('tx-amount').value = paiseToInputStr(t.amountPaise);
  document.getElementById('tx-date').value = t.date;
  document.getElementById('tx-note').value = t.note || '';
  document.getElementById('tx-amount-err').classList.remove('show');
  document.getElementById('tx-modal-del-btn').style.display = 'inline-flex';
  const notice = document.getElementById('tx-review-notice');
  if (t.needsCurrencyReview) {
    notice.style.display = 'flex';
    notice.replaceChildren(
      makeEl('span', { text: '⚠️' }),
      makeEl(
        'span',
        null,
        'Originally saved in ',
        makeEl('strong', { text: t.originalCurrency || 'another currency' }),
        ` (${t.originalAmount || paiseToInputStr(t.amountPaise)}). Confirm or update the rupee (₹) amount below before saving.`
      )
    );
  } else {
    notice.style.display = 'none';
    notice.replaceChildren();
  }
  populateCategorySelect(t.category);
  openModal('tx-modal');
}

async function saveTx(e) {
  e.preventDefault();
  if (isSavingTx) return;

  const amountPaise = parseRupeesToPaise(document.getElementById('tx-amount').value, { allowNegative: false, allowZero: false });
  const dateVal = document.getElementById('tx-date').value;
  const errEl = document.getElementById('tx-amount-err');
  errEl.classList.remove('show');

  if (!amountPaise) {
    errEl.textContent = 'Enter a positive amount in rupees and paise (for example, 250.50), with at most 2 decimal places.';
    errEl.classList.add('show');
    return;
  }
  if (!dateVal) {
    errEl.textContent = 'Please select a date.';
    errEl.classList.add('show');
    return;
  }

  const btn = document.getElementById('tx-save-btn');
  const payload = {
    type: txType,
    amountPaise,
    category: document.getElementById('tx-category').value,
    date: dateVal,
    note: document.getElementById('tx-note').value.trim(),
    ...(editTxId ? { confirmCurrencyReview: true } : { clientRequestId: currentClientReqId }),
  };

  isSavingTx = true;
  const orig = btn.textContent;
  btn.disabled = true;
  btn.textContent = 'Saving…';
  setSyncState('syncing');

  try {
    if (editTxId) {
      await api('PUT', `/api/transactions/${encodeURIComponent(editTxId)}`, payload);
    } else {
      await api('POST', '/api/transactions', payload);
    }
    await loadUserData();
    if (hasActiveTxFilters()) await loadFilteredTransactions();
    else S.filteredTx = null;

    closeModal('tx-modal');
    renderMainApp();
    toast(editTxId ? 'Transaction updated in ₹.' : 'Transaction saved in ₹.', 'ok', 2800);
  } catch (err) {
    setSyncState('error');
    errEl.textContent = err.message;
    errEl.classList.add('show');
  } finally {
    isSavingTx = false;
    btn.disabled = false;
    btn.textContent = orig;
  }
}

let deleteTxId = null;
function askDeleteTx(id) {
  deleteTxId = id;
  openModal('delete-modal');
}
function deleteFromEditModal() {
  if (!editTxId) return;
  closeModal('tx-modal');
  askDeleteTx(editTxId);
}
async function confirmDeleteTx() {
  const btn = document.getElementById('del-confirm-btn');
  await btnAction(btn, async () => {
    setSyncState('syncing');
    await api('DELETE', `/api/transactions/${encodeURIComponent(deleteTxId)}`);
    await loadUserData();
    if (hasActiveTxFilters()) await loadFilteredTransactions();
    else S.filteredTx = null;
    closeModal('delete-modal');
    renderMainApp();
    toast('Transaction deleted.', 'ok', 2800);
  });
}

// ── Budgets Screen ────────────────────────────────────────────────────────────
function renderBudgets() {
  if (!S.userId) return;
  const periodTx = confirmedInrTx().filter(t => txInPeriod(t, S.period, 0));
  const expensesPaise = periodTx.filter(t => t.type === 'expense').reduce((a, t) => a + t.amountPaise, 0);
  const rawPct = S.limitPaise > 0 ? (expensesPaise / S.limitPaise) * 100 : 0;
  const barPct = Math.min(rawPct, 100);
  const remainingPaise = S.limitPaise - expensesPaise;

  document.getElementById('b-period-title').textContent = `Overall ${S.period} budget (${periodLabel(S.period, 0)} · INR)`;
  document.getElementById('b-spent-big').textContent = formatINR(expensesPaise);
  document.getElementById('b-limit-lbl').textContent = formatINR(S.limitPaise);
  document.getElementById('b-remaining').textContent = remainingPaise < 0
    ? `Over budget by ${formatINR(Math.abs(remainingPaise))} · Alert threshold at ${S.alertThreshold}%`
    : `${formatINR(remainingPaise)} remaining · Alert threshold at ${S.alertThreshold}%`;

  const bar = document.getElementById('b-overall-bar');
  bar.style.width = barPct + '%';
  bar.className = 'progress-bar' + (rawPct > 100 ? ' danger' : rawPct >= S.alertThreshold ? ' warn' : '');

  const sc = rawPct > 100 ? 'danger' : rawPct >= S.alertThreshold ? 'warn' : 'ok';
  const si = rawPct > 100 ? '!' : rawPct >= S.alertThreshold ? '▲' : '✓';
  const st = rawPct > 100 ? 'Over budget' : rawPct >= S.alertThreshold ? 'Near limit' : 'On track';
  document.getElementById('b-badge').replaceChildren(
    makeEl('span', { className: `badge badge-${sc}`, text: `${si} ${st} (${rawPct.toFixed(0)}%)` })
  );

  const catMap = Object.create(null);
  periodTx.filter(t => t.type === 'expense').forEach(t => {
    const key = String(t.category || 'Other');
    catMap[key] = (catMap[key] || 0) + t.amountPaise;
  });

  const listEl = document.getElementById('b-cat-list');
  if (!S.catObjs.length) {
    listEl.replaceChildren(makeEl(
      'div',
      { className: 'card' },
      makeEl('div', { style: { color: 'var(--muted)', fontSize: '13.5px' }, text: 'No categories configured yet. Add categories in Settings.' })
    ));
    return;
  }

  listEl.replaceChildren(...S.catObjs.map(co => {
    const cat = co.name;
    const spentPaise = catMap[cat] || 0;
    const budgetPaise = hasOwn(S.catBudgetsPaise, cat) ? S.catBudgetsPaise[cat] : 0;
    const cp = budgetPaise > 0 ? (spentPaise / budgetPaise) * 100 : null;
    const cBar = cp !== null ? Math.min(cp, 100) : 0;
    const color = catColor(cat);
    const cBadge = cp === null
      ? makeEl('span', { style: { fontSize: '12px', color: 'var(--muted)' }, text: 'No category limit' })
      : makeEl('span', {
          className: `badge ${cp > 100 ? 'badge-danger' : cp >= S.alertThreshold ? 'badge-warn' : 'badge-ok'}`,
          text: `${cp > 100 ? '!' : cp >= S.alertThreshold ? '▲' : '✓'} ${cp.toFixed(0)}%`,
        });

    const header = makeEl(
      'div',
      { style: { display: 'flex', alignItems: 'center', gap: '12px', marginBottom: budgetPaise ? '10px' : '0' } },
      makeEl('div', {
        style: { width: '36px', height: '36px', borderRadius: '10px', background: `${color}22`, display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: '16px', flexShrink: '0' },
        text: catEmoji(cat),
      }),
      makeEl(
        'div',
        { style: { flex: '1', minWidth: '0' } },
        makeEl('div', { style: { fontWeight: '600', fontSize: '14px' }, text: cat }),
        makeEl('div', { className: 'num', style: { fontSize: '12.5px', color: 'var(--muted)' }, text: `Spent: ${formatINR(spentPaise)}${budgetPaise ? ' / ' + formatINR(budgetPaise) : ''}` })
      ),
      cBadge
    );

    const card = makeEl('div', { className: 'card card-sm', style: { marginBottom: '10px' } }, header);
    if (budgetPaise) {
      const innerBar = makeEl('div', {
        className: `progress-bar ${cp > 100 ? 'danger' : cp >= S.alertThreshold ? 'warn' : ''}`,
        style: { width: `${cBar}%` },
      });
      if (cp < S.alertThreshold) innerBar.style.background = color;
      card.appendChild(makeEl('div', { className: 'progress-wrap', style: { height: '8px' } }, innerBar));
    }
    return card;
  }));
}

function openCatBudgetModal() {
  const wrap = document.getElementById('catb-items');
  wrap.replaceChildren(...S.catObjs.map(co => {
    const existingPaise = hasOwn(S.catBudgetsPaise, co.name) ? S.catBudgetsPaise[co.name] : 0;
    const inp = makeEl('input', {
      className: 'field-input amount-input',
      id: `cb-${co.id}`,
      type: 'number',
      value: existingPaise ? paiseToInputStr(existingPaise) : '',
      placeholder: 'No limit',
      min: '0.01',
      step: '0.01',
      inputmode: 'decimal',
    });
    inp.dataset.cat = co.name;
    return makeEl(
      'div',
      { className: 'field-group' },
      makeEl('label', { className: 'field-label', for: `cb-${co.id}`, text: `${co.name} (₹)` }),
      makeEl('div', { className: 'amount-wrap' }, makeEl('span', { className: 'amount-currency', text: '₹' }), inp)
    );
  }));
  openModal('catbudget-modal');
}

async function saveCatBudgets() {
  const btn = document.getElementById('catb-save-btn');
  const next = {};
  let invalid = false;
  document.querySelectorAll('#catb-items input[data-cat]').forEach(inp => {
    const raw = inp.value.trim();
    if (!raw) return;
    const p = parseRupeesToPaise(raw, { allowNegative: false, allowZero: false });
    if (!p || FORBIDDEN_KEYS.has(inp.dataset.cat)) invalid = true;
    else next[inp.dataset.cat] = p;
  });
  if (invalid) {
    toast('Category limits must be positive amounts in rupees and paise (at most 2 decimals).', 'error');
    return;
  }
  await btnAction(btn, async () => {
    setSyncState('syncing');
    await api('PUT', '/api/settings', { catBudgetsPaise: next });
    S.catBudgetsPaise = next;
    setSyncState('ok');
    closeModal('catbudget-modal');
    renderBudgets();
    toast('Category budgets saved in ₹.', 'ok', 2800);
  });
}

// ── Reports Screen ────────────────────────────────────────────────────────────
function setRptPeriod(p) {
  rptPeriod = p;
  rptOffset = 0;
  renderReports();
}
function shiftRptOffset(delta) {
  rptOffset = delta === 0 ? 0 : rptOffset + delta;
  renderReports();
}

function renderReports() {
  if (!S.userId) return;
  const period = rptPeriod || S.period;
  document.querySelectorAll('[data-rp]').forEach(b => b.classList.toggle('active', b.dataset.rp === period));
  document.getElementById('rpt-period-label').textContent = periodLabel(period, rptOffset);

  const ptx = confirmedInrTx().filter(t => txInPeriod(t, period, rptOffset));
  const incomePaise = ptx.filter(t => t.type === 'income').reduce((a, t) => a + t.amountPaise, 0);
  const expensesPaise = ptx.filter(t => t.type === 'expense').reduce((a, t) => a + t.amountPaise, 0);
  const netPaise = incomePaise - expensesPaise;

  const lblStyle = { fontSize: '11px', fontWeight: '700', letterSpacing: '.08em', textTransform: 'uppercase', color: 'var(--muted)', marginBottom: '4px' };
  document.getElementById('rpt-summary').replaceChildren(
    makeEl('div', null, makeEl('div', { style: lblStyle, text: 'Income' }), makeEl('div', { className: 'num', style: { fontSize: '22px', fontWeight: '800', color: 'var(--ok)' }, text: formatINR(incomePaise) })),
    makeEl('div', null, makeEl('div', { style: lblStyle, text: 'Expenses' }), makeEl('div', { className: 'num', style: { fontSize: '22px', fontWeight: '800', color: 'var(--danger)' }, text: formatINR(expensesPaise) })),
    makeEl('div', null, makeEl('div', { style: lblStyle, text: `Net (${ptx.length} entries)` }), makeEl('div', { className: 'num', style: { fontSize: '22px', fontWeight: '800', color: netPaise >= 0 ? 'var(--ok)' : 'var(--danger)' }, text: formatINR(netPaise) }))
  );

  const catMap = Object.create(null);
  ptx.filter(t => t.type === 'expense').forEach(t => {
    const key = String(t.category || 'Other');
    catMap[key] = (catMap[key] || 0) + t.amountPaise;
  });
  const entries = Object.entries(catMap).sort((a, b) => b[1] - a[1]);
  drawPie(entries, expensesPaise);
  drawBar(ptx, period, rptOffset);
  document.getElementById('bar-label').textContent = period === 'yearly' ? 'Monthly breakdown (₹)' : period === 'monthly' ? 'Weekly breakdown (₹)' : 'Daily breakdown (₹)';
}

function drawPie(entries, totalPaise) {
  const canvas = document.getElementById('pie-canvas');
  if (!canvas) return;
  const dpr = window.devicePixelRatio || 1;
  const size = 188;
  canvas.style.width = size + 'px';
  canvas.style.height = size + 'px';
  canvas.width = size * dpr;
  canvas.height = size * dpr;

  const ctx = canvas.getContext('2d');
  ctx.scale(dpr, dpr);
  ctx.clearRect(0, 0, size, size);

  if (!entries.length || totalPaise <= 0) {
    ctx.fillStyle = 'rgba(255,255,255,0.08)';
    ctx.beginPath();
    ctx.arc(size / 2, size / 2, size / 2 - 8, 0, Math.PI * 2);
    ctx.fill();
    ctx.beginPath();
    ctx.arc(size / 2, size / 2, (size / 2 - 8) * 0.56, 0, Math.PI * 2);
    ctx.fillStyle = '#1a2030';
    ctx.fill();
    ctx.fillStyle = 'rgba(255,255,255,0.45)';
    ctx.font = '600 13px system-ui';
    ctx.textAlign = 'center';
    ctx.textBaseline = 'middle';
    ctx.fillText('No expenses', size / 2, size / 2);
    document.getElementById('pie-legend').replaceChildren(
      makeEl('div', { style: { textAlign: 'center', color: 'var(--muted)', fontSize: '13px' }, text: 'No rupee expenses recorded in this period.' })
    );
    return;
  }

  let ang = -Math.PI / 2;
  const cx = size / 2, cy = size / 2, r = size / 2 - 6;
  entries.forEach(([, amtPaise], i) => {
    const sl = (amtPaise / totalPaise) * Math.PI * 2;
    ctx.beginPath();
    ctx.moveTo(cx, cy);
    ctx.arc(cx, cy, r, ang, ang + sl);
    ctx.closePath();
    ctx.fillStyle = CAT_COLORS[i % CAT_COLORS.length];
    ctx.fill();
    ang += sl;
  });

  ctx.beginPath();
  ctx.arc(cx, cy, r * 0.58, 0, Math.PI * 2);
  ctx.fillStyle = '#1a2030';
  ctx.fill();
  ctx.fillStyle = '#edf0f7';
  const totalText = formatINR(totalPaise);
  ctx.font = totalText.length > 12 ? '700 11px system-ui' : '700 13px system-ui';
  ctx.textAlign = 'center';
  ctx.textBaseline = 'middle';
  ctx.fillText(totalText, cx, cy);

  document.getElementById('pie-legend').replaceChildren(...entries.map(([cat, amtPaise], i) => {
    const p = ((amtPaise / totalPaise) * 100).toFixed(0);
    return makeEl(
      'div',
      { className: 'pie-legend-item' },
      makeEl('div', { className: 'pie-swatch', style: { background: CAT_COLORS[i % CAT_COLORS.length] } }),
      makeEl('span', { style: { overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }, text: cat }),
      makeEl('span', { className: 'num', style: { marginLeft: 'auto', color: 'var(--muted)', flexShrink: '0' }, text: `${formatINR(amtPaise)} (${p}%)` })
    );
  }));
}

function drawBar(txs, period, offset = 0) {
  const c = document.getElementById('bar-chart');
  if (!c) return;
  const { start } = periodRange(period, offset);
  const labels = [];
  const groups = [];

  if (period === 'weekly') {
    const days = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];
    for (let i = 0; i < 7; i++) {
      const d = new Date(start.getFullYear(), start.getMonth(), start.getDate() + i);
      labels.push(days[d.getDay()]);
      const ds = `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')}`;
      groups.push(txs.filter(t => t.date === ds));
    }
  } else if (period === 'monthly') {
    const daysInMonth = new Date(start.getFullYear(), start.getMonth() + 1, 0).getDate();
    const weeks = Math.ceil(daysInMonth / 7);
    for (let w = 0; w < weeks; w++) {
      labels.push(`Wk ${w + 1}`);
      const ws = new Date(start.getFullYear(), start.getMonth(), 1 + w * 7, 0, 0, 0);
      const we = new Date(start.getFullYear(), start.getMonth(), Math.min(daysInMonth, 7 + w * 7), 23, 59, 59);
      groups.push(txs.filter(t => {
        const d = new Date(t.date + 'T12:00:00');
        return d >= ws && d <= we;
      }));
    }
  } else {
    const months = ['J', 'F', 'M', 'A', 'M', 'J', 'J', 'A', 'S', 'O', 'N', 'D'];
    for (let m = 0; m < 12; m++) {
      labels.push(months[m]);
      groups.push(txs.filter(t => new Date(t.date + 'T12:00:00').getMonth() === m));
    }
  }

  const exp = groups.map(g => g.filter(t => t.type === 'expense').reduce((a, t) => a + t.amountPaise, 0));
  const inc = groups.map(g => g.filter(t => t.type === 'income').reduce((a, t) => a + t.amountPaise, 0));
  const max = Math.max(...exp, ...inc, 1);

  c.replaceChildren(...labels.map((l, i) => makeEl(
    'div',
    { className: 'bar-col' },
    makeEl(
      'div',
      { className: 'bar-pair' },
      makeEl('div', { className: 'bar', style: { height: `${Math.max(2, Math.round((exp[i] / max) * 100))}%` }, title: `Expenses: ${formatINR(exp[i])}` }),
      makeEl('div', { className: 'bar income-bar', style: { height: `${Math.max(2, Math.round((inc[i] / max) * 100))}%` }, title: `Income: ${formatINR(inc[i])}` })
    ),
    makeEl('div', { className: 'bar-label', text: l })
  )));
}

// ── Settings Screen ───────────────────────────────────────────────────────────
function syncSettingsUI() {
  if (!S.userId) return;
  document.getElementById('set-period').value = S.period;
  document.getElementById('set-limit').value = paiseToInputStr(S.limitPaise);
  document.getElementById('set-limit-sub').textContent = `${formatINR(S.limitPaise)} per ${S.period.replace('ly', '')}`;
  document.getElementById('set-balance').value = paiseToInputStr(S.balancePaise);
  document.getElementById('set-inapp').checked = S.notifInApp;
  document.getElementById('set-browser').checked = S.notifBrowser;
  document.getElementById('set-threshold').value = S.alertThreshold;
  renderSettingsCats();
  checkNotifPerm();
}

async function saveRupeeSetting(which, rawVal) {
  if (which === 'limit') {
    const p = parseRupeesToPaise(rawVal, { allowNegative: false, allowZero: false });
    if (!p) {
      toast('Spending limit must be greater than ₹0.00 (up to 2 decimal places for paise).', 'error');
      syncSettingsUI();
      return;
    }
    await saveSetting('limitPaise', p);
  } else if (which === 'balance') {
    const p = parseRupeesToPaise(rawVal, { allowNegative: true, allowZero: true });
    if (p === null) {
      toast('Starting balance must be in rupees and paise (up to 2 decimal places).', 'error');
      syncSettingsUI();
      return;
    }
    await saveSetting('balancePaise', p);
  }
}

async function saveSetting(key, value) {
  if (value === undefined || value === null || Number.isNaN(value)) {
    syncSettingsUI();
    return;
  }
  if (key === 'alertThreshold' && (value < 1 || value > 200)) {
    toast('Alert threshold must be between 1 and 200%.', 'error');
    syncSettingsUI();
    return;
  }

  const prev = S[key];
  const prevAlerts = S.alertFired;
  const resetAlerts = key === 'limitPaise' || key === 'period' || key === 'alertThreshold';

  S[key] = value;
  if (resetAlerts) S.alertFired = {};

  setSyncState('syncing');
  try {
    await api('PUT', '/api/settings', {
      [key]: value,
      ...(resetAlerts ? { alertFired: {} } : {}),
    });
    setSyncState('ok');
    syncSettingsUI();
    updateDashboard();
    renderBudgets();
    if (resetAlerts) checkAlerts();
    toast('Setting updated.', 'ok', 2200);
  } catch (e) {
    S[key] = prev;
    S.alertFired = prevAlerts;
    setSyncState('error');
    syncSettingsUI();
    toast(e.message, 'error');
  }
}

function checkNotifPerm() {
  const sub = document.getElementById('set-notif-sub');
  const cb = document.getElementById('set-browser');
  if (!('Notification' in window)) {
    sub.textContent = 'Browser notifications are unavailable here. In-app alerts remain active.';
    cb.disabled = true;
    return;
  }
  cb.disabled = false;
  if (Notification.permission === 'denied') {
    sub.textContent = 'Blocked by browser. To enable, open your browser site settings for this page and allow Notifications. In-app alerts remain active.';
  } else if (Notification.permission === 'granted') {
    sub.textContent = S.notifBrowser ? 'Enabled and permitted ✓' : 'Permission granted — toggle on to enable push alerts.';
  } else {
    sub.textContent = 'Requires permission prompt when enabled.';
  }
}

async function toggleBrowserNotif(checked) {
  if (checked && !('Notification' in window)) {
    document.getElementById('set-browser').checked = false;
    checkNotifPerm();
    return;
  }
  if (checked && Notification.permission === 'default') {
    const perm = await Notification.requestPermission();
    if (perm !== 'granted') {
      document.getElementById('set-browser').checked = false;
      checkNotifPerm();
      toast('Browser notification permission was not granted. In-app alerts will still work.', 'info');
      return;
    }
  } else if (checked && Notification.permission === 'denied') {
    document.getElementById('set-browser').checked = false;
    checkNotifPerm();
    toast('Notifications are blocked in your browser settings. Allow Notifications in site permissions to enable.', 'info');
    return;
  }
  await saveSetting('notifBrowser', checked);
}

function renderSettingsCats() {
  const el = document.getElementById('set-cats-list');
  if (!el) return;
  el.replaceChildren(...S.catObjs.map(co => {
    const rmBtn = makeEl('button', {
      type: 'button',
      className: 'btn btn-icon',
      style: { width: '32px', height: '32px', minHeight: '32px' },
      'aria-label': `Remove ${co.name}`,
      text: '✕',
    });
    rmBtn.addEventListener('click', () => removeCategoryAPI(co.id, co.name));
    return makeEl(
      'div',
      { style: { display: 'flex', alignItems: 'center', gap: '10px', padding: '9px 0', borderBottom: '1px solid var(--border)' } },
      makeEl('div', { style: { width: '10px', height: '10px', borderRadius: '50%', background: catColor(co.name), flexShrink: '0' } }),
      makeEl('span', { style: { flex: '1', fontSize: '14px' }, text: `${catEmoji(co.name)} ${co.name}` }),
      rmBtn
    );
  }));
}

async function addCategoryAPI() {
  const inp = document.getElementById('set-new-cat');
  const name = inp.value.trim();
  if (!name) return;
  try {
    setSyncState('syncing');
    const r = await api('POST', '/api/categories', { name });
    S.catObjs.push({ id: r.id, name: r.name });
    inp.value = '';
    setSyncState('ok');
    renderSettingsCats();
    populateFilterCategories();
    renderBudgets();
    toast(`Category "${r.name}" added.`, 'ok', 2800);
  } catch (e) {
    setSyncState('error');
    toast(e.message, 'error');
  }
}

async function removeCategoryAPI(id, name) {
  try {
    setSyncState('syncing');
    await api('DELETE', `/api/categories/${encodeURIComponent(id)}`);
    S.catObjs = S.catObjs.filter(c => c.id !== id);
    setSyncState('ok');
    renderSettingsCats();
    populateFilterCategories();
    renderBudgets();
    toast(`Category "${name}" removed.`, 'ok', 2800);
  } catch (e) {
    setSyncState('error');
    toast(e.message, 'error');
  }
}

function exportCSV() {
  const rows = [['Date', 'Type', 'Category', 'Amount', 'Currency', 'Status', 'Note']];
  S.transactions.forEach(t => {
    if (t.needsCurrencyReview) {
      rows.push([
        t.date, t.type, t.category,
        t.originalAmount || paiseToInputStr(t.amountPaise),
        t.originalCurrency || 'UNKNOWN',
        'Needs INR review',
        t.note || '',
      ]);
    } else {
      rows.push([
        t.date, t.type, t.category,
        paiseToInputStr(t.amountPaise),
        'INR',
        'Confirmed INR',
        t.note || '',
      ]);
    }
  });
  const csv = rows.map(r => r.map(v => `"${String(v).replace(/"/g, '""')}"`).join(',')).join('\n');
  const a = document.createElement('a');
  a.href = URL.createObjectURL(new Blob([csv], { type: 'text/csv;charset=utf-8' }));
  a.download = `spendwise-inr-${todayStr()}.csv`;
  a.click();
}

function openDeleteAccountModal() {
  document.getElementById('del-acc-pw').value = '';
  document.getElementById('del-acc-err').classList.remove('show');
  openModal('reset-modal');
}

async function doDeleteAccount() {
  const pw = document.getElementById('del-acc-pw').value;
  const errEl = document.getElementById('del-acc-err');
  errEl.classList.remove('show');
  if (!pw) {
    errEl.textContent = 'Please enter your password to confirm.';
    errEl.classList.add('show');
    return;
  }
  const btn = document.getElementById('del-acc-btn');
  const orig = btn.textContent;
  btn.disabled = true;
  btn.textContent = 'Deleting…';
  try {
    await api('DELETE', '/api/auth/account', { password: pw });
    closeModal('reset-modal');
    csrfToken = '';
    S = resetStateObj();
    showAuthScreen();
    toast('Your account and all data have been permanently deleted.', 'info');
  } catch (e) {
    errEl.textContent = e.message;
    errEl.classList.add('show');
  } finally {
    btn.disabled = false;
    btn.textContent = orig;
  }
}

// ── Overspending Alerts (INR, exact paise) ────────────────────────────────────
function checkAlerts() {
  if (!S.userId || S.limitPaise <= 0) return;

  const pKey = getPeriodKey(S.period);
  const pLabel = `${S.period} (${periodLabel(S.period, 0)})`;
  const ptx = confirmedInrTx().filter(t => txInPeriod(t, S.period, 0));
  const expensesPaise = ptx.filter(t => t.type === 'expense').reduce((a, t) => a + t.amountPaise, 0);
  const pct = (expensesPaise / S.limitPaise) * 100;
  const remainingPaise = Math.max(S.limitPaise - expensesPaise, 0);

  const overKey = `${pKey}:over`;
  const threshKey = `${pKey}:t${S.alertThreshold}`;

  const currentKeys = {};
  for (const [k, v] of Object.entries(S.alertFired || {})) {
    if (!FORBIDDEN_KEYS.has(k) && k.startsWith(pKey + ':') && typeof v === 'boolean') {
      currentKeys[k] = v;
    }
  }

  let changed = Object.keys(currentKeys).length !== Object.keys(S.alertFired || {}).length;
  S.alertFired = currentKeys;

  if (expensesPaise > S.limitPaise && !hasOwn(S.alertFired, overKey)) {
    S.alertFired[overKey] = true;
    changed = true;
    const msg = `You've exceeded your ${pLabel} budget limit of ${formatINR(S.limitPaise)}. Total spent: ${formatINR(expensesPaise)} (${formatINR(expensesPaise - S.limitPaise)} over, ${formatINR(0)} remaining). You can review recent entries or update your limit anytime.`;
    dispatchBudgetAlert('danger', 'Over budget', msg);
  } else if (pct >= S.alertThreshold && expensesPaise <= S.limitPaise && !hasOwn(S.alertFired, threshKey)) {
    S.alertFired[threshKey] = true;
    changed = true;
    const msg = `You've reached ${pct.toFixed(0)}% of your ${pLabel} budget: ${formatINR(expensesPaise)} spent out of ${formatINR(S.limitPaise)}, with ${formatINR(remainingPaise)} remaining.`;
    dispatchBudgetAlert('warn', 'Approaching budget limit', msg);
  }

  if (changed) {
    api('PUT', '/api/settings', { alertFired: S.alertFired }).catch(() => {});
  }
}

function dispatchBudgetAlert(type, title, msg) {
  const browserPermitted = 'Notification' in window && Notification.permission === 'granted';
  if (S.notifInApp || (S.notifBrowser && !browserPermitted)) {
    showInAppAlert(type, title, msg);
  }
  if (S.notifBrowser && browserPermitted) {
    try {
      new Notification(`${title} — SpendWise`, { body: msg });
    } catch {}
  }
}

function showInAppAlert(type, title, msg) {
  const banner = document.getElementById('alert-banner');
  const budgetsBtn = makeEl('button', { type: 'button', className: 'alert-link', text: 'View Budgets →' });
  budgetsBtn.addEventListener('click', () => showScreen('budgets'));
  const txBtn = makeEl('button', { type: 'button', className: 'alert-link', text: 'View Transactions →' });
  txBtn.addEventListener('click', () => showScreen('transactions'));
  const closeBtn = makeEl('button', { type: 'button', className: 'alert-close', 'aria-label': 'Dismiss alert', text: '✕' });

  const el = makeEl(
    'div',
    { className: `alert-item${type === 'danger' ? ' danger' : ''}`, role: 'status' },
    makeEl('div', { className: 'alert-icon', 'aria-hidden': 'true', text: type === 'danger' ? '!' : '▲' }),
    makeEl(
      'div',
      { style: { flex: '1', minWidth: '0' } },
      makeEl('div', { style: { fontWeight: '700', fontSize: '14px', marginBottom: '3px' }, text: title }),
      makeEl('div', { style: { fontSize: '13px', color: 'var(--text)', lineHeight: '1.5' }, text: msg }),
      makeEl('div', { className: 'alert-links' }, budgetsBtn, txBtn)
    ),
    closeBtn
  );
  closeBtn.addEventListener('click', () => el.remove());
  banner.prepend(el);
}

// ── Modal Helpers ─────────────────────────────────────────────────────────────
function openModal(id) {
  document.getElementById(id).classList.add('open');
  document.body.style.overflow = 'hidden';
}
function closeModal(id) {
  document.getElementById(id).classList.remove('open');
  document.body.style.overflow = '';
}

// ── Event Bindings (Strict CSP — Zero Inline Handlers) ────────────────────────
function bindEventListeners() {
  // Auth
  document.querySelectorAll('[data-auth-tab]').forEach(btn => {
    btn.addEventListener('click', () => switchAuthTab(btn.dataset.authTab));
  });
  document.querySelectorAll('[data-pw-target]').forEach(btn => {
    btn.addEventListener('click', () => togglePw(btn.dataset.pwTarget, btn));
  });

  document.getElementById('reg-pw').addEventListener('input', function () {
    const v = this.value;
    const hint = document.getElementById('reg-pw-hint');
    if (!v) {
      hint.className = 'field-hint';
      hint.replaceChildren(
        'Rule: ',
        makeEl('strong', { text: 'At least 8 characters (8–72), English letters (A–Z, a–z) and numbers (0–9) only.' }),
        ' No spaces or special characters.'
      );
      this.classList.remove('err');
      return;
    }
    const ok = /^[a-zA-Z0-9]{8,72}$/.test(v);
    const onlyAlnum = /^[a-zA-Z0-9]*$/.test(v);
    if (ok) {
      hint.className = 'field-hint ok';
      hint.textContent = '✓ Password meets all rules.';
      this.classList.remove('err');
    } else if (!onlyAlnum) {
      hint.className = 'field-hint bad';
      hint.textContent = 'Only English letters (A–Z, a–z) and numbers (0–9) are allowed. Remove spaces and special characters.';
      this.classList.add('err');
    } else if (v.length < 8) {
      hint.className = 'field-hint';
      hint.textContent = `${8 - v.length} more character${8 - v.length === 1 ? '' : 's'} needed (letters and numbers only).`;
      this.classList.remove('err');
    } else {
      hint.className = 'field-hint bad';
      hint.textContent = 'Password cannot exceed 72 characters.';
      this.classList.add('err');
    }
  });

  document.getElementById('login-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const btn = document.getElementById('login-btn');
    const errEl = document.getElementById('login-err');
    errEl.classList.remove('show');
    const userId = document.getElementById('login-uid').value.trim();
    const password = document.getElementById('login-pw').value;
    if (!userId || !password) {
      errEl.textContent = 'Please enter both your user ID and password.';
      errEl.classList.add('show');
      return;
    }
    const orig = btn.textContent;
    btn.disabled = true;
    btn.textContent = 'Logging in…';
    try {
      const res = await api('POST', '/api/auth/login', { userId, password });
      csrfToken = res.csrfToken || '';
      S.userId = res.userId;
      document.getElementById('login-pw').value = '';
      document.getElementById('auth-screen').style.display = 'none';
      await loadUserData();
      await afterSignInFlow();
    } catch (err) {
      errEl.textContent = err.message;
      errEl.classList.add('show');
    } finally {
      btn.disabled = false;
      btn.textContent = orig;
    }
  });

  document.getElementById('register-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const btn = document.getElementById('register-btn');
    const errEl = document.getElementById('reg-err');
    errEl.classList.remove('show');

    const userId = document.getElementById('reg-uid').value.trim();
    const password = document.getElementById('reg-pw').value;

    if (!/^[a-zA-Z0-9_]{3,30}$/.test(userId)) {
      errEl.textContent = 'User ID must be 3–30 characters using only letters, numbers, or underscores.';
      errEl.classList.add('show');
      return;
    }
    if (!/^[a-zA-Z0-9]{8,72}$/.test(password)) {
      errEl.textContent = 'Password must be 8–72 characters using only English letters (A–Z, a–z) and numbers (0–9). No spaces or special characters.';
      errEl.classList.add('show');
      return;
    }

    const orig = btn.textContent;
    btn.disabled = true;
    btn.textContent = 'Creating account…';
    try {
      const res = await api('POST', '/api/auth/register', { userId, password });
      csrfToken = res.csrfToken || '';
      S.userId = res.userId;
      document.getElementById('reg-pw').value = '';
      document.getElementById('auth-screen').style.display = 'none';
      await loadUserData();
      await afterSignInFlow();
    } catch (err) {
      errEl.textContent = err.message;
      errEl.classList.add('show');
    } finally {
      btn.disabled = false;
      btn.textContent = orig;
    }
  });

  // Setup Wizard
  document.querySelectorAll('#s-limit-presets [data-limit]').forEach(btn => {
    btn.addEventListener('click', () => pickSetupLimit(Number(btn.dataset.limit)));
  });
  document.querySelectorAll('#s-period-grp .toggle-btn, #s-thresh-grp .toggle-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      const grp = btn.closest('.toggle-group');
      grp.querySelectorAll('.toggle-btn').forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      if (grp.id === 's-thresh-grp') {
        document.getElementById('s-custom-wrap').style.display = btn.dataset.val === 'custom' ? 'block' : 'none';
      }
    });
  });
  document.getElementById('s-browser').addEventListener('change', function () {
    onSetupBrowserToggle(this);
  });
  document.getElementById('s-new-cat').addEventListener('keydown', e => {
    if (e.key === 'Enter') { e.preventDefault(); setupAddCat(); }
  });
  document.getElementById('s-add-cat-btn').addEventListener('click', setupAddCat);
  document.getElementById('s-back').addEventListener('click', setupBack);
  document.getElementById('s-skip').addEventListener('click', setupSkip);
  document.getElementById('s-next').addEventListener('click', setupNext);

  // Import & Review Modals
  document.getElementById('import-btn').addEventListener('click', doImport);
  document.querySelectorAll('[data-skip-import]').forEach(btn => {
    btn.addEventListener('click', skipImport);
  });
  document.querySelectorAll('[data-close-modal]').forEach(btn => {
    btn.addEventListener('click', () => closeModal(btn.dataset.closeModal));
  });
  document.querySelectorAll('.modal-overlay').forEach(overlay => {
    overlay.addEventListener('click', e => {
      if (e.target === overlay) closeModal(overlay.id);
    });
  });

  // Navigation & Global Actions
  document.querySelectorAll('.js-logout-btn').forEach(btn => {
    btn.addEventListener('click', doLogout);
  });
  document.querySelectorAll('.nav-item[data-screen], .bnav-item[data-screen]').forEach(btn => {
    btn.addEventListener('click', () => showScreen(btn.dataset.screen));
  });
  document.querySelectorAll('[data-nav-screen]').forEach(btn => {
    btn.addEventListener('click', () => showScreen(btn.dataset.navScreen));
  });
  document.querySelectorAll('.js-open-add-tx').forEach(btn => {
    btn.addEventListener('click', openAddTransaction);
  });
  document.getElementById('sync-btn').addEventListener('click', manualSync);

  // Dashboard
  document.querySelectorAll('[data-vp]').forEach(btn => {
    btn.addEventListener('click', () => setPeriodView(btn.dataset.vp));
  });
  document.querySelectorAll('[data-dash-offset]').forEach(btn => {
    btn.addEventListener('click', () => shiftDashOffset(Number(btn.dataset.dashOffset)));
  });

  // Transactions Filters
  document.getElementById('tx-search').addEventListener('input', debouncedLoadTransactions);
  document.getElementById('tx-search-clear').addEventListener('click', clearTxSearch);
  document.querySelectorAll('.filter-row .chip[data-f]').forEach(btn => {
    btn.addEventListener('click', () => setTxFilter(btn.dataset.f));
  });
  ['tx-filter-cat', 'tx-filter-from', 'tx-filter-to', 'tx-sort'].forEach(id => {
    document.getElementById(id).addEventListener('change', loadFilteredTransactions);
  });
  document.getElementById('tx-clear-filters').addEventListener('click', resetTxFilters);

  // Budgets
  document.getElementById('b-set-cat-limits-btn').addEventListener('click', openCatBudgetModal);
  document.getElementById('catb-save-btn').addEventListener('click', saveCatBudgets);

  // Reports
  document.querySelectorAll('[data-rp]').forEach(btn => {
    btn.addEventListener('click', () => setRptPeriod(btn.dataset.rp));
  });
  document.querySelectorAll('[data-rpt-offset]').forEach(btn => {
    btn.addEventListener('click', () => shiftRptOffset(Number(btn.dataset.rptOffset)));
  });
  window.addEventListener('resize', () => {
    if (currentScreen === 'reports' && S.userId) renderReports();
  });

  // Settings
  document.getElementById('set-period').addEventListener('change', function () {
    saveSetting('period', this.value);
  });
  document.getElementById('set-limit').addEventListener('change', function () {
    saveRupeeSetting('limit', this.value);
  });
  document.getElementById('set-balance').addEventListener('change', function () {
    saveRupeeSetting('balance', this.value);
  });
  document.getElementById('set-threshold').addEventListener('change', function () {
    saveSetting('alertThreshold', parseInt(this.value, 10));
  });
  document.getElementById('set-inapp').addEventListener('change', function () {
    saveSetting('notifInApp', this.checked);
  });
  document.getElementById('set-browser').addEventListener('change', function () {
    toggleBrowserNotif(this.checked);
  });
  document.getElementById('set-add-cat-btn').addEventListener('click', addCategoryAPI);
  document.getElementById('set-new-cat').addEventListener('keydown', e => {
    if (e.key === 'Enter') { e.preventDefault(); addCategoryAPI(); }
  });
  document.getElementById('set-review-btn').addEventListener('click', openReviewModal);
  document.getElementById('set-import-btn').addEventListener('click', () => checkForLocalImport(true));
  document.getElementById('set-export-btn').addEventListener('click', exportCSV);
  document.getElementById('set-del-acc-btn').addEventListener('click', openDeleteAccountModal);

  // Transaction & Account Modals
  document.getElementById('tx-form').addEventListener('submit', saveTx);
  document.getElementById('type-expense').addEventListener('click', () => setTxType('expense'));
  document.getElementById('type-income').addEventListener('click', () => setTxType('income'));
  document.getElementById('tx-modal-del-btn').addEventListener('click', deleteFromEditModal);
  document.getElementById('del-confirm-btn').addEventListener('click', confirmDeleteTx);
  document.getElementById('del-acc-btn').addEventListener('click', doDeleteAccount);

  // Global keyboard Escape closes modals
  document.addEventListener('keydown', e => {
    if (e.key === 'Escape') {
      document.querySelectorAll('.modal-overlay.open').forEach(m => m.classList.remove('open'));
      document.body.style.overflow = '';
    }
  });
}

// ── Boot ──────────────────────────────────────────────────────────────────────
bindEventListeners();

(async function boot() {
  try {
    const me = await api('GET', '/api/auth/me');
    if (me.authenticated) {
      csrfToken = me.csrfToken || '';
      S.userId = me.userId;
      await loadUserData();
      await afterSignInFlow();
    } else {
      showAuthScreen();
    }
  } catch (e) {
    const retryBtn = makeEl('button', { type: 'button', className: 'btn btn-primary', style: { marginTop: '8px' }, text: 'Retry' });
    retryBtn.addEventListener('click', () => location.reload());
    document.getElementById('global-loader').replaceChildren(
      makeEl('div', { className: 'logo-icon', style: { width: '48px', height: '48px', fontSize: '24px', borderRadius: '14px' }, text: '₹' }),
      makeEl('div', { style: { fontSize: '16px', fontWeight: '700' }, text: 'Cannot connect to server' }),
      makeEl('div', { style: { fontSize: '13px', color: 'var(--muted)', maxWidth: '300px', textAlign: 'center' }, text: e.message }),
      retryBtn
    );
  }
})();
