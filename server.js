'use strict';

// ═══════════════════════════════════════════════════════════════════════════
//  SpendWise — server.js (INR-only, exact integer paise SQL storage)
//  Express + node:sqlite (DatabaseSync) + bcryptjs + express-session
//  All SQL operations use parameterized statements; identifiers use allowlists.
// ═══════════════════════════════════════════════════════════════════════════

const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const { DatabaseSync } = require('node:sqlite');
const path = require('path');
const crypto = require('crypto');
const fs = require('fs');

const DEFAULT_CATEGORIES = [
  'Food & Dining', 'Groceries', 'Transport', 'Shopping', 'Bills & Utilities',
  'Rent & Housing', 'Health', 'Entertainment', 'Education', 'Other',
];

const APP_CURRENCY = 'INR';
const VALID_PERIODS = new Set(['weekly', 'monthly', 'yearly']);
const VALID_TX_TYPES = new Set(['income', 'expense']);

// Max 1,000 crore rupees = 1e12 paise (safely inside JS MAX_SAFE_INTEGER 9e15)
const MAX_PAISE = 1_000_000_000_000;
const DEFAULT_LIMIT_PAISE = 1_000_000; // ₹10,000.00

// Fixed server-side allowlists for dynamic sorting identifiers
const TX_SORT_COLUMNS = new Map([
  ['date', 'date'],
  ['amount', 'amount_paise'],
  ['category', 'category'],
  ['created', 'created_at'],
]);
const TX_SORT_DIRS = new Map([
  ['asc', 'ASC'],
  ['desc', 'DESC'],
]);

// Valid bcrypt hash used for constant-time login failure when user does not exist
const DUMMY_HASH = '$2a$12$R9h/cIPz0gi.URNNX3kh2OPST9/PgBkqquzi.Ss7KIUgO2t0jWMUW';
const SALT_ROUNDS = 12;
const SESSION_TTL_MS = 7 * 24 * 60 * 60 * 1000;

/**
 * Parse a rupee input (number or string like "1,25,000.50" or "250.5")
 * into exact integer paise without floating-point rounding drift.
 * Returns null if invalid or if > 2 decimal places are provided.
 */
function parseRupeesToPaise(input, opts = {}) {
  const { allowNegative = false, allowZero = false } = opts;
  if (input === null || input === undefined) return null;

  let raw;
  if (typeof input === 'number') {
    if (!Number.isFinite(input)) return null;
    raw = String(input);
  } else if (typeof input === 'string') {
    raw = input.trim().replace(/[₹,\s]/g, '');
  } else {
    return null;
  }

  if (!raw || !/^[+-]?(?:\d+(?:\.\d{1,2})?|\.\d{1,2})$/.test(raw)) {
    return null;
  }

  const neg = raw.startsWith('-');
  if (neg && !allowNegative) return null;

  const unsigned = raw.replace(/^[+-]/, '');
  const [wholeRaw, fracRaw = ''] = unsigned.split('.');
  const wholeStr = wholeRaw || '0';
  const fracStr = fracRaw.padEnd(2, '0');

  const whole = Number(wholeStr);
  const frac = Number(fracStr);
  if (!Number.isSafeInteger(whole) || !Number.isSafeInteger(frac)) return null;

  const absPaise = whole * 100 + frac;
  if (!Number.isSafeInteger(absPaise) || absPaise > MAX_PAISE) return null;
  if (absPaise === 0 && !allowZero) return null;

  return neg && absPaise > 0 ? -absPaise : absPaise;
}

/**
 * Validate an explicit integer paise input or fallback decimal rupee field.
 */
function resolvePaiseInput(paiseVal, rupeeVal, opts = {}) {
  const { allowNegative = false, allowZero = false } = opts;
  if (paiseVal !== undefined) {
    if (typeof paiseVal !== 'number' || !Number.isSafeInteger(paiseVal)) return null;
    if (!allowNegative && paiseVal < 0) return null;
    if (!allowZero && paiseVal === 0) return null;
    if (Math.abs(paiseVal) > MAX_PAISE) return null;
    return paiseVal;
  }
  if (rupeeVal !== undefined) {
    return parseRupeesToPaise(rupeeVal, opts);
  }
  return undefined;
}

/**
 * Convert integer paise to exact 2-decimal string (e.g. 12500050 -> "125000.50").
 */
function paiseToDecimalString(paise) {
  const n = Math.trunc(paise);
  const sign = n < 0 ? '-' : '';
  const abs = Math.abs(n);
  const rupees = Math.floor(abs / 100);
  const p = String(abs % 100).padStart(2, '0');
  return `${sign}${rupees}.${p}`;
}

/**
 * Custom SQLite-backed express-session Store using node:sqlite parameterized queries.
 */
class SQLiteSessionStore extends session.Store {
  constructor(db) {
    super();
    this.db = db;
    this.stmtGet = db.prepare('SELECT sess FROM sessions WHERE sid = ? AND expire > ?');
    this.stmtSet = db.prepare(`
      INSERT INTO sessions (sid, sess, expire)
      VALUES (?, ?, ?)
      ON CONFLICT(sid) DO UPDATE SET sess = excluded.sess, expire = excluded.expire
    `);
    this.stmtDestroy = db.prepare('DELETE FROM sessions WHERE sid = ?');
    this.stmtTouch = db.prepare('UPDATE sessions SET expire = ? WHERE sid = ?');
    this.stmtPrune = db.prepare('DELETE FROM sessions WHERE expire <= ?');

    const timer = setInterval(() => {
      try { this.stmtPrune.run(Date.now()); } catch {}
    }, 15 * 60 * 1000);
    if (typeof timer.unref === 'function') timer.unref();
  }

  _getExpire(sess) {
    if (sess && sess.cookie && sess.cookie.expires) {
      const t = new Date(sess.cookie.expires).getTime();
      if (Number.isFinite(t)) return t;
    }
    return Date.now() + SESSION_TTL_MS;
  }

  get(sid, cb) {
    try {
      const row = this.stmtGet.get(sid, Date.now());
      if (!row) return cb(null, null);
      return cb(null, JSON.parse(row.sess));
    } catch (err) {
      return cb(err);
    }
  }

  set(sid, sess, cb) {
    try {
      this.stmtSet.run(sid, JSON.stringify(sess), this._getExpire(sess));
      return cb && cb(null);
    } catch (err) {
      return cb && cb(err);
    }
  }

  destroy(sid, cb) {
    try {
      this.stmtDestroy.run(sid);
      return cb && cb(null);
    } catch (err) {
      return cb && cb(err);
    }
  }

  touch(sid, sess, cb) {
    try {
      this.stmtTouch.run(this._getExpire(sess), sid);
      return cb && cb(null);
    } catch (err) {
      return cb && cb(err);
    }
  }
}

// ── Validation & sanitization helpers ─────────────────────────────────────────
function validateUserId(s) {
  return typeof s === 'string' && /^[a-zA-Z0-9_]{3,30}$/.test(s);
}

/** Required password rule: English letters & digits only, 8–72 chars (no spaces/special chars). */
function validatePassword(s) {
  return typeof s === 'string' && /^[a-zA-Z0-9]{8,72}$/.test(s);
}

function sanitize(s, max) {
  if (typeof s !== 'string') return '';
  return s
    .normalize('NFC')
    .replace(/[\u0000-\u001F\u007F]/g, '')
    .trim()
    .slice(0, max);
}

/**
 * Sanitize user-authored text before storing in SQLite:
 * strips script/style blocks, HTML angle-bracket tags, and control characters.
 */
function sanitizeStoredText(s, max) {
  if (typeof s !== 'string') return '';
  return s
    .normalize('NFC')
    .replace(/\u0000/g, '')
    .replace(/[\u0001-\u001F\u007F]/g, ' ')
    .replace(/<script\b[^>]*>[\s\S]*?(?:<\/script>|$)/gi, '')
    .replace(/<style\b[^>]*>[\s\S]*?(?:<\/style>|$)/gi, '')
    .replace(/<[a-zA-Z!?/][^>]*>/g, '')
    .replace(/<[a-zA-Z!?/][^>]*$/g, '')
    .replace(/[<>]/g, '')
    .replace(/\s+/g, ' ')
    .trim()
    .slice(0, max);
}

function parseTrustProxy(val) {
  if (val === undefined || val === null || val === '' || val === false || val === 'false') {
    return false;
  }
  if (val === true || val === 'true') return true;
  if (typeof val === 'number') {
    return Number.isInteger(val) && val > 0 ? val : false;
  }
  const s = String(val).trim();
  if (/^\d+$/.test(s)) {
    const n = Number(s);
    return n > 0 ? n : false;
  }
  if (s.includes(',')) {
    const list = s.split(',').map(p => p.trim()).filter(Boolean);
    return list.length ? list : false;
  }
  return s;
}

function getClientIp(req) {
  return req.ip || req.socket?.remoteAddress || 'unknown';
}

function isHttpsRequest(req) {
  // Relies on Express's req.secure so X-Forwarded-Proto is honored ONLY when trust proxy is enabled.
  return Boolean(req.secure);
}

/**
 * Zero-dependency fixed-window rate limiter with bounded memory and RateLimit-* headers.
 */
function createRateLimiter({ windowMs, max, keyFn, onLimit }) {
  const buckets = new Map();
  const MAX_BUCKETS = 10_000;

  const timer = setInterval(() => {
    const now = Date.now();
    for (const [k, v] of buckets.entries()) {
      if (v.resetAt <= now) buckets.delete(k);
    }
  }, Math.max(30_000, Math.min(windowMs, 5 * 60_000)));
  if (typeof timer.unref === 'function') timer.unref();

  return function rateLimitMiddleware(req, res, next) {
    const now = Date.now();
    const key = String(keyFn(req) || 'unknown');
    let entry = buckets.get(key);

    if (!entry || entry.resetAt <= now) {
      if (!entry && buckets.size >= MAX_BUCKETS) {
        // Evict oldest bucket to keep memory bounded under key-flood attacks
        const firstKey = buckets.keys().next().value;
        if (firstKey !== undefined) buckets.delete(firstKey);
      }
      entry = { count: 0, resetAt: now + windowMs };
      buckets.set(key, entry);
    }

    entry.count += 1;
    const remaining = Math.max(0, max - entry.count);
    const resetSec = Math.max(1, Math.ceil((entry.resetAt - now) / 1000));

    res.setHeader('RateLimit-Limit', String(max));
    res.setHeader('RateLimit-Remaining', String(remaining));
    res.setHeader('RateLimit-Reset', String(resetSec));

    if (entry.count > max) {
      res.setHeader('Retry-After', String(resetSec));
      if (typeof onLimit === 'function') onLimit(req, key, entry.count);
      return res.status(429).json({
        error: 'Too many requests. Please wait a moment and try again.',
      });
    }

    next();
  };
}

function isDate(s) {
  if (typeof s !== 'string' || !/^\d{4}-\d{2}-\d{2}$/.test(s)) return false;
  const [y, m, d] = s.split('-').map(Number);
  const dt = new Date(Date.UTC(y, m - 1, d));
  return dt.getUTCFullYear() === y && dt.getUTCMonth() === m - 1 && dt.getUTCDate() === d;
}

function escapeLike(s) {
  return s.replace(/[\\%_]/g, ch => '\\' + ch);
}

function safeJsonParse(raw, fallback) {
  try {
    const parsed = JSON.parse(raw);
    return parsed && typeof parsed === 'object' && !Array.isArray(parsed) ? parsed : fallback;
  } catch {
    return fallback;
  }
}

function formatTxRow(row) {
  return {
    id: row.id,
    type: row.type,
    amountPaise: Number(row.amount_paise),
    amountDecimal: paiseToDecimalString(row.amount_paise),
    currency: APP_CURRENCY,
    category: row.category,
    date: row.date,
    note: row.note,
    needsCurrencyReview: row.needs_currency_review === 1,
    originalCurrency: row.original_currency || null,
    originalAmount: row.original_amount || null,
    created_at: row.created_at,
  };
}

function loadSessionSecret(dataDir) {
  if (process.env.SESSION_SECRET) return process.env.SESSION_SECRET;
  const secretFile = path.join(dataDir, '.session-secret');
  try {
    const existing = fs.readFileSync(secretFile, 'utf8').trim();
    if (existing.length >= 32) return existing;
  } catch {}
  const fresh = crypto.randomBytes(64).toString('hex');
  try { fs.writeFileSync(secretFile, fresh, { mode: 0o600 }); } catch {}
  return fresh;
}

/**
 * Initialize schema and perform safe, idempotent migration from any legacy
 * multi-currency / floating-point schema into fixed-precision integer paise (INR-only).
 * Non-INR existing records are preserved and flagged needs_currency_review = 1
 * instead of being silently relabeled as rupees.
 */
function initDatabase(db) {
  db.exec('PRAGMA journal_mode = WAL');
  db.exec('PRAGMA foreign_keys = ON');

  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id            INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id       TEXT    NOT NULL UNIQUE COLLATE NOCASE,
      password_hash TEXT    NOT NULL,
      created_at    TEXT    NOT NULL DEFAULT (datetime('now')),
      updated_at    TEXT    NOT NULL DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS sessions (
      sid    TEXT    PRIMARY KEY,
      sess   TEXT    NOT NULL,
      expire INTEGER NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_sessions_expire ON sessions(expire);

    CREATE TABLE IF NOT EXISTS categories (
      id          INTEGER PRIMARY KEY AUTOINCREMENT,
      user_pk     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      name        TEXT    NOT NULL COLLATE NOCASE,
      sort_order  INTEGER NOT NULL DEFAULT 0,
      created_at  TEXT    NOT NULL DEFAULT (datetime('now')),
      UNIQUE(user_pk, name)
    );
    CREATE INDEX IF NOT EXISTS idx_cats_user ON categories(user_pk, sort_order);
  `);

  // Settings table (check if legacy schema exists)
  const settingsTable = db.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name='settings'").get();
  if (!settingsTable) {
    db.exec(`
      CREATE TABLE settings (
        id                    INTEGER PRIMARY KEY AUTOINCREMENT,
        user_pk               INTEGER NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,
        setup_done            INTEGER NOT NULL DEFAULT 0,
        currency              TEXT    NOT NULL DEFAULT 'INR' CHECK(currency = 'INR'),
        period                TEXT    NOT NULL DEFAULT 'monthly',
        limit_paise           INTEGER NOT NULL DEFAULT ${DEFAULT_LIMIT_PAISE} CHECK(limit_paise > 0),
        balance_paise         INTEGER NOT NULL DEFAULT 0,
        alert_threshold       INTEGER NOT NULL DEFAULT 80,
        notif_in_app          INTEGER NOT NULL DEFAULT 1,
        notif_browser         INTEGER NOT NULL DEFAULT 0,
        alert_fired           TEXT    NOT NULL DEFAULT '{}',
        cat_budgets_paise     TEXT    NOT NULL DEFAULT '{}',
        needs_currency_review INTEGER NOT NULL DEFAULT 0,
        legacy_currency       TEXT,
        legacy_limit_amount   TEXT,
        legacy_balance        TEXT,
        updated_at            TEXT    NOT NULL DEFAULT (datetime('now'))
      );
    `);
  } else {
    const sCols = new Set(db.prepare('PRAGMA table_info(settings)').all().map(c => c.name));
    if (!sCols.has('limit_paise')) {
      const rows = db.prepare('SELECT * FROM settings').all();
      db.exec('PRAGMA foreign_keys = OFF');
      db.exec('BEGIN IMMEDIATE');
      try {
        db.exec(`
          CREATE TABLE settings_inr_new (
            id                    INTEGER PRIMARY KEY AUTOINCREMENT,
            user_pk               INTEGER NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,
            setup_done            INTEGER NOT NULL DEFAULT 0,
            currency              TEXT    NOT NULL DEFAULT 'INR' CHECK(currency = 'INR'),
            period                TEXT    NOT NULL DEFAULT 'monthly',
            limit_paise           INTEGER NOT NULL DEFAULT ${DEFAULT_LIMIT_PAISE} CHECK(limit_paise > 0),
            balance_paise         INTEGER NOT NULL DEFAULT 0,
            alert_threshold       INTEGER NOT NULL DEFAULT 80,
            notif_in_app          INTEGER NOT NULL DEFAULT 1,
            notif_browser         INTEGER NOT NULL DEFAULT 0,
            alert_fired           TEXT    NOT NULL DEFAULT '{}',
            cat_budgets_paise     TEXT    NOT NULL DEFAULT '{}',
            needs_currency_review INTEGER NOT NULL DEFAULT 0,
            legacy_currency       TEXT,
            legacy_limit_amount   TEXT,
            legacy_balance        TEXT,
            updated_at            TEXT    NOT NULL DEFAULT (datetime('now'))
          );
        `);

        const ins = db.prepare(`
          INSERT INTO settings_inr_new (
            id, user_pk, setup_done, currency, period, limit_paise, balance_paise,
            alert_threshold, notif_in_app, notif_browser, alert_fired, cat_budgets_paise,
            needs_currency_review, legacy_currency, legacy_limit_amount, legacy_balance, updated_at
          ) VALUES (?, ?, ?, 'INR', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `);

        for (const r of rows) {
          const setupDone = sCols.has('setup_done') ? (r.setup_done ? 1 : 0) : 1;
          const oldCur = String(r.currency || 'INR').toUpperCase();
          const isForeign = oldCur !== 'INR' && setupDone === 1;

          const parsedLim = parseRupeesToPaise(
            r.limit_amount !== undefined ? Number(r.limit_amount).toFixed(2) : '10000.00'
          ) || DEFAULT_LIMIT_PAISE;

          const parsedBal = parseRupeesToPaise(
            r.balance !== undefined ? Number(r.balance).toFixed(2) : '0.00',
            { allowNegative: true, allowZero: true }
          ) ?? 0;

          const oldBudgets = safeJsonParse(r.cat_budgets || '{}', {});
          const newBudgets = {};
          for (const [k, v] of Object.entries(oldBudgets)) {
            const p = parseRupeesToPaise(Number(v).toFixed(2));
            if (p && p > 0) newBudgets[k] = p;
          }

          ins.run(
            r.id, r.user_pk, setupDone, r.period || 'monthly',
            parsedLim, parsedBal,
            r.alert_threshold || 80,
            r.notif_in_app !== undefined ? (r.notif_in_app ? 1 : 0) : 1,
            r.notif_browser ? 1 : 0,
            r.alert_fired || '{}',
            JSON.stringify(newBudgets),
            isForeign ? 1 : 0,
            isForeign ? oldCur : null,
            isForeign && r.limit_amount !== undefined ? String(r.limit_amount) : null,
            isForeign && r.balance !== undefined ? String(r.balance) : null,
            r.updated_at || new Date().toISOString(),
          );
        }

        db.exec('DROP TABLE settings');
        db.exec('ALTER TABLE settings_inr_new RENAME TO settings');
        db.exec('COMMIT');
      } catch (err) {
        try { db.exec('ROLLBACK'); } catch {}
        throw err;
      } finally {
        db.exec('PRAGMA foreign_keys = ON');
      }
    }
  }

  // Transactions table (check if legacy schema exists)
  const txTable = db.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name='transactions'").get();
  if (!txTable) {
    db.exec(`
      CREATE TABLE transactions (
        id                    TEXT    NOT NULL,
        user_pk               INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        type                  TEXT    NOT NULL CHECK(type IN ('income','expense')),
        amount_paise          INTEGER NOT NULL CHECK(amount_paise > 0),
        currency              TEXT    NOT NULL DEFAULT 'INR' CHECK(currency = 'INR'),
        category              TEXT    NOT NULL DEFAULT 'Other',
        date                  TEXT    NOT NULL,
        note                  TEXT    NOT NULL DEFAULT '',
        source_id             TEXT,
        needs_currency_review INTEGER NOT NULL DEFAULT 0,
        original_currency     TEXT,
        original_amount       TEXT,
        created_at            TEXT    NOT NULL DEFAULT (datetime('now')),
        updated_at            TEXT    NOT NULL DEFAULT (datetime('now')),
        PRIMARY KEY (user_pk, id)
      );
      CREATE INDEX idx_tx_user_date ON transactions(user_pk, date DESC);
      CREATE UNIQUE INDEX idx_tx_user_source ON transactions(user_pk, source_id) WHERE source_id IS NOT NULL;
    `);
  } else {
    const tCols = new Set(db.prepare('PRAGMA table_info(transactions)').all().map(c => c.name));
    if (!tCols.has('amount_paise')) {
      const rows = db.prepare('SELECT * FROM transactions').all();
      db.exec('PRAGMA foreign_keys = OFF');
      db.exec('BEGIN IMMEDIATE');
      try {
        db.exec(`
          CREATE TABLE transactions_inr_new (
            id                    TEXT    NOT NULL,
            user_pk               INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            type                  TEXT    NOT NULL CHECK(type IN ('income','expense')),
            amount_paise          INTEGER NOT NULL CHECK(amount_paise > 0),
            currency              TEXT    NOT NULL DEFAULT 'INR' CHECK(currency = 'INR'),
            category              TEXT    NOT NULL DEFAULT 'Other',
            date                  TEXT    NOT NULL,
            note                  TEXT    NOT NULL DEFAULT '',
            source_id             TEXT,
            needs_currency_review INTEGER NOT NULL DEFAULT 0,
            original_currency     TEXT,
            original_amount       TEXT,
            created_at            TEXT    NOT NULL DEFAULT (datetime('now')),
            updated_at            TEXT    NOT NULL DEFAULT (datetime('now')),
            PRIMARY KEY (user_pk, id)
          );
        `);

        const ins = db.prepare(`
          INSERT INTO transactions_inr_new (
            id, user_pk, type, amount_paise, currency, category, date, note, source_id,
            needs_currency_review, original_currency, original_amount, created_at, updated_at
          ) VALUES (?, ?, ?, ?, 'INR', ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `);

        for (const r of rows) {
          const oldCur = String(r.currency || 'INR').toUpperCase();
          const isForeign = oldCur !== 'INR';
          const amtPaise = parseRupeesToPaise(Number(r.amount).toFixed(2)) || 100;
          ins.run(
            r.id, r.user_pk, r.type, amtPaise,
            r.category || 'Other', r.date, r.note || '',
            tCols.has('source_id') ? r.source_id : null,
            isForeign ? 1 : 0,
            isForeign ? oldCur : null,
            isForeign ? String(r.amount) : null,
            r.created_at || new Date().toISOString(),
            r.updated_at || new Date().toISOString(),
          );
        }

        db.exec('DROP TABLE transactions');
        db.exec('ALTER TABLE transactions_inr_new RENAME TO transactions');
        db.exec('CREATE INDEX idx_tx_user_date ON transactions(user_pk, date DESC)');
        db.exec('CREATE UNIQUE INDEX idx_tx_user_source ON transactions(user_pk, source_id) WHERE source_id IS NOT NULL');
        db.exec('COMMIT');
      } catch (err) {
        try { db.exec('ROLLBACK'); } catch {}
        throw err;
      } finally {
        db.exec('PRAGMA foreign_keys = ON');
      }
    }
  }
}

/**
 * Create the configured Express application and SQLite connection.
 */
function createApp(options = {}) {
  const dataDir = options.dataDir || __dirname;
  const dbPath = options.dbPath || path.join(dataDir, 'spendwise.db');
  const sessionSecret = options.sessionSecret || loadSessionSecret(dataDir);

  const db = new DatabaseSync(dbPath);
  initDatabase(db);

  function withTransaction(fn) {
    db.exec('BEGIN IMMEDIATE');
    try {
      const result = fn();
      db.exec('COMMIT');
      return result;
    } catch (err) {
      try { db.exec('ROLLBACK'); } catch {}
      throw err;
    }
  }

  const emitLog = typeof options.logger === 'function'
    ? options.logger
    : (entry) => {
        if (!options.quiet) console.log(JSON.stringify(entry));
      };

  function logEvent(level, event, details = {}) {
    emitLog({ ts: new Date().toISOString(), level, event, ...details });
  }

  const app = express();
  app.disable('x-powered-by');
  // Never trust forwarded headers unless explicitly enabled via options.trustProxy or TRUST_PROXY.
  // When using TRUST_PROXY behind a reverse proxy, bind/firewall Node so direct client traffic cannot bypass the proxy.
  const trustProxy = options.trustProxy !== undefined
    ? parseTrustProxy(options.trustProxy)
    : parseTrustProxy(process.env.TRUST_PROXY);
  app.set('trust proxy', trustProxy);

  const enforceHttps = options.enforceHttps ?? (
    process.env.ENFORCE_HTTPS === 'true'
      ? true
      : process.env.ENFORCE_HTTPS === 'false'
        ? false
        : process.env.NODE_ENV === 'production'
  );

  // Security headers & HTTPS enforcement
  app.use((req, res, next) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'SAMEORIGIN');
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
    res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
    res.setHeader(
      'Content-Security-Policy',
      "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; connect-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'self'; form-action 'self'"
    );

    const https = isHttpsRequest(req);
    if (https || enforceHttps) {
      res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
    }

    if (enforceHttps && !https) {
      logEvent('warn', 'security.https_rejected', { method: req.method, path: req.path, ip: getClientIp(req) });
      if ((req.method === 'GET' || req.method === 'HEAD') && !req.path.startsWith('/api')) {
        const host = req.get('host') || '';
        if (/^[a-zA-Z0-9.-]+(:\d+)?$/.test(host)) {
          return res.redirect(301, `https://${host}${req.originalUrl}`);
        }
      }
      return res.status(403).json({ error: 'HTTPS is required for this request.' });
    }

    next();
  });

  app.use(express.static(path.join(__dirname, 'public')));

  // JSON parser with tight payload limit + clean JSON error responses
  app.use(express.json({ limit: '512kb' }));
  app.use((err, req, res, next) => {
    if (!err) return next();
    if (err.type === 'entity.too.large') {
      logEvent('warn', 'security.payload_too_large', { path: req.path, ip: getClientIp(req) });
      return res.status(413).json({ error: 'Request payload is too large.' });
    }
    if (err instanceof SyntaxError && err.status === 400 && 'body' in err) {
      logEvent('warn', 'security.malformed_json', { path: req.path, ip: getClientIp(req) });
      return res.status(400).json({ error: 'Malformed JSON payload.' });
    }
    return next(err);
  });

  // Reject non-object JSON bodies (arrays/primitives/null) on mutations
  app.use('/api', (req, res, next) => {
    if (req.method === 'POST' || req.method === 'PUT' || req.method === 'PATCH' || req.method === 'DELETE') {
      if (req.body === undefined) {
        req.body = {};
      } else if (typeof req.body !== 'object' || req.body === null || Array.isArray(req.body)) {
        return res.status(400).json({ error: 'Request body must be a JSON object.' });
      }
    }
    next();
  });

  app.use(session({
    store: new SQLiteSessionStore(db),
    name: 'sw.sid',
    secret: sessionSecret,
    resave: false,
    saveUninitialized: false,
    rolling: true,
    cookie: {
      httpOnly: true,
      sameSite: 'strict',
      secure: enforceHttps ? true : 'auto',
      maxAge: SESSION_TTL_MS,
    },
  }));

  // Structured API request & latency monitoring (never logs passwords or tokens)
  app.use('/api', (req, res, next) => {
    const startMs = Date.now();
    res.on('finish', () => {
      const durationMs = Date.now() - startMs;
      const level = res.statusCode >= 500 ? 'error' : res.statusCode >= 400 ? 'warn' : 'info';
      logEvent(level, 'http.api', {
        method: req.method,
        path: req.path,
        status: res.statusCode,
        durationMs,
        ip: getClientIp(req),
        userPk: req.session?.userPk ?? null,
      });
    });
    next();
  });

  // Rate limiters
  const apiLimitCfg = options.apiRateLimit || { windowMs: 60_000, max: 120 };
  const authLimitCfg = options.authRateLimit || { windowMs: 15 * 60_000, max: 10 };

  if (!options.disableRateLimit) {
    const apiLimiter = createRateLimiter({
      windowMs: apiLimitCfg.windowMs,
      max: apiLimitCfg.max,
      keyFn: (req) => (req.session?.userPk ? `u:${req.session.userPk}` : `ip:${getClientIp(req)}`),
      onLimit: (req) => logEvent('warn', 'security.rate_limit_exceeded', { scope: 'api', path: req.path, ip: getClientIp(req) }),
    });
    const authLimiter = createRateLimiter({
      windowMs: authLimitCfg.windowMs,
      max: authLimitCfg.max,
      keyFn: (req) => `auth:${getClientIp(req)}`,
      onLimit: (req) => logEvent('warn', 'security.rate_limit_exceeded', { scope: 'auth', path: req.path, ip: getClientIp(req) }),
    });
    app.use('/api', apiLimiter);
    app.use('/api/auth/login', authLimiter);
    app.use('/api/auth/register', authLimiter);
    app.use('/api/auth/account', authLimiter);
  }

  function ensureCsrfToken(req) {
    if (!req.session.csrfToken) {
      req.session.csrfToken = crypto.randomBytes(32).toString('hex');
    }
    return req.session.csrfToken;
  }

  function requireAuth(req, res, next) {
    if (!req.session || !req.session.userPk) {
      return res.status(401).json({ error: 'Not signed in.' });
    }
    const exists = db.prepare('SELECT id FROM users WHERE id = ?').get(req.session.userPk);
    if (!exists) {
      req.session.destroy(() => {});
      return res.status(401).json({ error: 'Session is no longer valid. Please sign in again.' });
    }
    next();
  }

  function requireCsrf(req, res, next) {
    if (req.method === 'GET' || req.method === 'HEAD' || req.method === 'OPTIONS') {
      return next();
    }
    const expected = req.session && req.session.csrfToken;
    const provided = req.get('X-CSRF-Token');
    if (!expected || typeof provided !== 'string') {
      logEvent('warn', 'security.csrf_rejected', { reason: 'missing', path: req.path, ip: getClientIp(req), userPk: req.session?.userPk ?? null });
      return res.status(403).json({ error: 'Invalid or missing CSRF token. Please refresh and try again.' });
    }
    const a = Buffer.from(expected);
    const b = Buffer.from(provided);
    if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
      logEvent('warn', 'security.csrf_rejected', { reason: 'mismatch', path: req.path, ip: getClientIp(req), userPk: req.session?.userPk ?? null });
      return res.status(403).json({ error: 'Invalid CSRF token. Please refresh and try again.' });
    }
    next();
  }

  // ═════════════════════════════════════════════════════════════════════════
  //  AUTH
  // ═════════════════════════════════════════════════════════════════════════

  app.get('/api/auth/me', (req, res) => {
    if (!req.session || !req.session.userPk) {
      return res.json({ authenticated: false });
    }
    const user = db.prepare('SELECT id, user_id FROM users WHERE id = ?').get(req.session.userPk);
    if (!user) {
      req.session.destroy(() => {});
      return res.json({ authenticated: false });
    }
    const csrfToken = ensureCsrfToken(req);
    res.json({ authenticated: true, userId: user.user_id, csrfToken });
  });

  app.post('/api/auth/register', async (req, res) => {
    try {
      const userId = sanitize(req.body?.userId, 30);
      const password = typeof req.body?.password === 'string' ? req.body.password : '';

      if (!validateUserId(userId)) {
        logEvent('warn', 'auth.register.rejected', { reason: 'invalid_user_id', ip: getClientIp(req) });
        return res.status(400).json({
          error: 'User ID must be 3–30 characters using only letters, numbers, or underscores.',
        });
      }
      if (!validatePassword(password)) {
        logEvent('warn', 'auth.register.rejected', { reason: 'invalid_password_rule', userId, ip: getClientIp(req) });
        return res.status(400).json({
          error: 'Password must be 8–72 characters using only English letters (A–Z, a–z) and numbers (0–9). Spaces and special characters are not allowed.',
        });
      }

      const taken = db.prepare('SELECT id FROM users WHERE user_id = ? COLLATE NOCASE').get(userId);
      if (taken) {
        logEvent('warn', 'auth.register.rejected', { reason: 'duplicate_user_id', userId, ip: getClientIp(req) });
        return res.status(409).json({ error: 'That user ID is already taken. Please choose another.' });
      }

      const hash = await bcrypt.hash(password, SALT_ROUNDS);

      let newPk;
      try {
        newPk = withTransaction(() => {
          const r = db.prepare('INSERT INTO users (user_id, password_hash) VALUES (?, ?)').run(userId, hash);
          const pk = Number(r.lastInsertRowid);
          db.prepare("INSERT INTO settings (user_pk, setup_done, currency, limit_paise, balance_paise) VALUES (?, 0, 'INR', ?, 0)").run(pk, DEFAULT_LIMIT_PAISE);
          const ins = db.prepare('INSERT INTO categories (user_pk, name, sort_order) VALUES (?, ?, ?)');
          DEFAULT_CATEGORIES.forEach((c, i) => ins.run(pk, c, i));
          return pk;
        });
      } catch (err) {
        if (String(err.message).includes('UNIQUE')) {
          const raceTaken = db.prepare('SELECT id FROM users WHERE user_id = ? COLLATE NOCASE').get(userId);
          if (raceTaken) {
            return res.status(409).json({ error: 'That user ID is already taken. Please choose another.' });
          }
        }
        throw err;
      }

      req.session.regenerate(err => {
        if (err) return res.status(500).json({ error: 'Could not start session.' });
        req.session.userPk = newPk;
        req.session.userId = userId;
        const csrfToken = ensureCsrfToken(req);
        logEvent('info', 'auth.register.success', { userPk: newPk, userId, ip: getClientIp(req) });
        res.status(201).json({ ok: true, userId, csrfToken });
      });
    } catch (e) {
      logEvent('error', 'auth.register.error', { message: e.message, ip: getClientIp(req) });
      res.status(500).json({ error: 'Server error. Please try again.' });
    }
  });

  app.post('/api/auth/login', async (req, res) => {
    try {
      const userId = sanitize(req.body?.userId, 30);
      const password = typeof req.body?.password === 'string' ? req.body.password : '';

      if (!userId || !password) {
        logEvent('warn', 'auth.login.failed', { reason: 'missing_credentials', ip: getClientIp(req) });
        return res.status(401).json({ error: 'Invalid user ID or password.' });
      }

      const user = db.prepare('SELECT id, user_id, password_hash FROM users WHERE user_id = ? COLLATE NOCASE').get(userId);

      let match = false;
      try {
        match = await bcrypt.compare(password, user ? user.password_hash : DUMMY_HASH);
      } catch {
        match = false;
      }

      if (!user || !match) {
        logEvent('warn', 'auth.login.failed', { reason: 'invalid_credentials', userId, ip: getClientIp(req) });
        return res.status(401).json({ error: 'Invalid user ID or password.' });
      }

      req.session.regenerate(err => {
        if (err) return res.status(500).json({ error: 'Could not start session.' });
        req.session.userPk = Number(user.id);
        req.session.userId = user.user_id;
        const csrfToken = ensureCsrfToken(req);
        logEvent('info', 'auth.login.success', { userPk: Number(user.id), userId: user.user_id, ip: getClientIp(req) });
        res.json({ ok: true, userId: user.user_id, csrfToken });
      });
    } catch (e) {
      logEvent('error', 'auth.login.error', { message: e.message, ip: getClientIp(req) });
      res.status(500).json({ error: 'Server error. Please try again.' });
    }
  });

  app.post('/api/auth/logout', (req, res) => {
    if (req.session && req.session.userPk) {
      const expected = req.session.csrfToken;
      const provided = req.get('X-CSRF-Token');
      if (expected && typeof provided === 'string') {
        const a = Buffer.from(expected);
        const b = Buffer.from(provided);
        if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
          logEvent('warn', 'security.csrf_rejected', { reason: 'logout_mismatch', ip: getClientIp(req) });
          return res.status(403).json({ error: 'Invalid CSRF token.' });
        }
      } else if (expected) {
        logEvent('warn', 'security.csrf_rejected', { reason: 'logout_missing', ip: getClientIp(req) });
        return res.status(403).json({ error: 'Missing CSRF token.' });
      }
    }
    const uid = req.session?.userPk ?? null;
    req.session.destroy(() => {
      res.clearCookie('sw.sid');
      logEvent('info', 'auth.logout', { userPk: uid, ip: getClientIp(req) });
      res.json({ ok: true });
    });
  });

  app.delete('/api/auth/account', requireAuth, requireCsrf, async (req, res) => {
    try {
      const password = typeof req.body?.password === 'string' ? req.body.password : '';
      const user = db.prepare('SELECT id, password_hash FROM users WHERE id = ?').get(req.session.userPk);
      if (!user) return res.status(404).json({ error: 'Account not found.' });

      const match = await bcrypt.compare(password, user.password_hash);
      if (!match) {
        logEvent('warn', 'auth.account_delete.failed', { userPk: req.session.userPk, ip: getClientIp(req) });
        return res.status(403).json({ error: 'Password did not match. Account was not deleted.' });
      }

      const deletedPk = req.session.userPk;
      db.prepare('DELETE FROM users WHERE id = ?').run(deletedPk);
      req.session.destroy(() => {
        res.clearCookie('sw.sid');
        logEvent('info', 'auth.account_deleted', { userPk: deletedPk, ip: getClientIp(req) });
        res.json({ ok: true });
      });
    } catch (e) {
      logEvent('error', 'auth.account_delete.error', { message: e.message, ip: getClientIp(req) });
      res.status(500).json({ error: 'Could not delete account.' });
    }
  });

  // ═════════════════════════════════════════════════════════════════════════
  //  SETTINGS (INR only, integer paise)
  // ═════════════════════════════════════════════════════════════════════════

  app.get('/api/settings', requireAuth, (req, res) => {
    const s = db.prepare('SELECT * FROM settings WHERE user_pk = ?').get(req.session.userPk);
    if (!s) return res.status(404).json({ error: 'Settings not found.' });
    res.json({
      setupDone: s.setup_done === 1,
      currency: APP_CURRENCY,
      period: s.period,
      limitPaise: Number(s.limit_paise),
      balancePaise: Number(s.balance_paise),
      alertThreshold: Number(s.alert_threshold),
      notifInApp: s.notif_in_app === 1,
      notifBrowser: s.notif_browser === 1,
      alertFired: safeJsonParse(s.alert_fired, {}),
      catBudgetsPaise: safeJsonParse(s.cat_budgets_paise, {}),
      needsCurrencyReview: s.needs_currency_review === 1,
      legacyCurrency: s.legacy_currency || null,
      legacyLimitAmount: s.legacy_limit_amount || null,
      legacyBalance: s.legacy_balance || null,
    });
  });

  app.put('/api/settings', requireAuth, requireCsrf, (req, res) => {
    const {
      setupDone, currency, period,
      limitPaise, limit,
      balancePaise, balance,
      alertThreshold, notifInApp, notifBrowser, alertFired,
      catBudgetsPaise, catBudgets,
      confirmCurrencyReview,
    } = req.body;

    if (currency !== undefined && String(currency).toUpperCase() !== APP_CURRENCY) {
      return res.status(400).json({ error: 'Only Indian rupees (INR) are supported.' });
    }
    if (setupDone !== undefined && typeof setupDone !== 'boolean') {
      return res.status(400).json({ error: 'Invalid setupDone value.' });
    }
    if (period !== undefined && !VALID_PERIODS.has(period)) {
      return res.status(400).json({ error: 'Invalid budget period.' });
    }

    const nextLimitPaise = resolvePaiseInput(limitPaise, limit, { allowNegative: false, allowZero: false });
    if (nextLimitPaise === null) {
      return res.status(400).json({ error: 'Spending limit must be a positive amount in rupees and paise (at most 2 decimal places).' });
    }

    const nextBalancePaise = resolvePaiseInput(balancePaise, balance, { allowNegative: true, allowZero: true });
    if (nextBalancePaise === null) {
      return res.status(400).json({ error: 'Starting balance must be a valid amount in rupees and paise (at most 2 decimal places).' });
    }

    if (alertThreshold !== undefined && (!Number.isInteger(alertThreshold) || alertThreshold < 1 || alertThreshold > 200)) {
      return res.status(400).json({ error: 'Alert threshold must be a whole number between 1 and 200.' });
    }

    let nextCatBudgets;
    const rawBudgets = catBudgetsPaise !== undefined ? catBudgetsPaise : catBudgets;
    if (rawBudgets !== undefined) {
      if (!rawBudgets || typeof rawBudgets !== 'object' || Array.isArray(rawBudgets)) {
        return res.status(400).json({ error: 'Invalid category budgets.' });
      }
      nextCatBudgets = {};
      for (const [k, v] of Object.entries(rawBudgets)) {
        if (k === '__proto__' || k === 'constructor' || k === 'prototype') {
          return res.status(400).json({ error: 'Invalid category name in budgets.' });
        }
        const cleanKey = sanitizeStoredText(k, 50);
        if (!cleanKey) {
          return res.status(400).json({ error: 'Invalid category name in budgets.' });
        }
        const p = catBudgetsPaise !== undefined
          ? resolvePaiseInput(v, undefined, { allowNegative: false, allowZero: false })
          : parseRupeesToPaise(v, { allowNegative: false, allowZero: false });
        if (p === null) {
          return res.status(400).json({ error: 'Each category budget must be a positive amount in rupees and paise (at most 2 decimal places).' });
        }
        nextCatBudgets[cleanKey] = p;
      }
    }

    let nextAlertFired;
    if (alertFired !== undefined) {
      if (!alertFired || typeof alertFired !== 'object' || Array.isArray(alertFired)) {
        return res.status(400).json({ error: 'Invalid alertFired payload.' });
      }
      const entries = Object.entries(alertFired);
      if (entries.length > 100) {
        return res.status(400).json({ error: 'Too many alertFired entries.' });
      }
      nextAlertFired = {};
      for (const [k, v] of entries) {
        if (k === '__proto__' || k === 'constructor' || k === 'prototype') {
          return res.status(400).json({ error: 'Invalid alertFired key.' });
        }
        const cleanKey = sanitizeStoredText(k, 64);
        if (!cleanKey || typeof v !== 'boolean') {
          return res.status(400).json({ error: 'Invalid alertFired entry.' });
        }
        nextAlertFired[cleanKey] = v;
      }
    }

    const cur = db.prepare('SELECT * FROM settings WHERE user_pk = ?').get(req.session.userPk);
    if (!cur) return res.status(404).json({ error: 'Settings not found.' });

    const clearReview = confirmCurrencyReview === true;

    db.prepare(`
      UPDATE settings SET
        setup_done            = ?,
        currency              = 'INR',
        period                = ?,
        limit_paise           = ?,
        balance_paise         = ?,
        alert_threshold       = ?,
        notif_in_app          = ?,
        notif_browser         = ?,
        alert_fired           = ?,
        cat_budgets_paise     = ?,
        needs_currency_review = ?,
        updated_at            = datetime('now')
      WHERE user_pk = ?
    `).run(
      setupDone !== undefined ? (setupDone ? 1 : 0) : cur.setup_done,
      period !== undefined ? period : cur.period,
      nextLimitPaise !== undefined ? nextLimitPaise : cur.limit_paise,
      nextBalancePaise !== undefined ? nextBalancePaise : cur.balance_paise,
      alertThreshold !== undefined ? alertThreshold : cur.alert_threshold,
      notifInApp !== undefined ? (notifInApp ? 1 : 0) : cur.notif_in_app,
      notifBrowser !== undefined ? (notifBrowser ? 1 : 0) : cur.notif_browser,
      nextAlertFired !== undefined ? JSON.stringify(nextAlertFired) : cur.alert_fired,
      nextCatBudgets !== undefined ? JSON.stringify(nextCatBudgets) : cur.cat_budgets_paise,
      clearReview ? 0 : cur.needs_currency_review,
      req.session.userPk,
    );
    res.json({ ok: true });
  });

  // ═════════════════════════════════════════════════════════════════════════
  //  CATEGORIES
  // ═════════════════════════════════════════════════════════════════════════

  app.get('/api/categories', requireAuth, (req, res) => {
    const cats = db.prepare(
      'SELECT id, name FROM categories WHERE user_pk = ? ORDER BY sort_order ASC, name ASC'
    ).all(req.session.userPk);
    res.json(cats);
  });

  app.post('/api/categories', requireAuth, requireCsrf, (req, res) => {
    const name = sanitizeStoredText(req.body.name, 50);
    if (!name) return res.status(400).json({ error: 'Category name is required.' });
    try {
      const count = db.prepare('SELECT COUNT(*) AS c FROM categories WHERE user_pk = ?').get(req.session.userPk)?.c ?? 0;
      const r = db.prepare('INSERT INTO categories (user_pk, name, sort_order) VALUES (?, ?, ?)').run(req.session.userPk, name, count);
      res.status(201).json({ id: Number(r.lastInsertRowid), name });
    } catch (e) {
      if (String(e.message).includes('UNIQUE')) {
        return res.status(409).json({ error: 'A category with that name already exists.' });
      }
      throw e;
    }
  });

  app.delete('/api/categories/:id', requireAuth, requireCsrf, (req, res) => {
    const id = parseInt(req.params.id, 10);
    if (!Number.isFinite(id)) return res.status(400).json({ error: 'Invalid category ID.' });
    const r = db.prepare('DELETE FROM categories WHERE id = ? AND user_pk = ?').run(id, req.session.userPk);
    if (r.changes === 0) return res.status(404).json({ error: 'Category not found.' });
    res.json({ ok: true });
  });

  // ═════════════════════════════════════════════════════════════════════════
  //  TRANSACTIONS (INR only, exact integer paise)
  // ═════════════════════════════════════════════════════════════════════════

  app.get('/api/transactions', requireAuth, (req, res) => {
    const clauses = ['user_pk = ?'];
    const params = [req.session.userPk];

    const type = sanitize(req.query.type, 16);
    if (type && type !== 'all') {
      if (!VALID_TX_TYPES.has(type)) {
        return res.status(400).json({ error: 'Invalid type filter.' });
      }
      clauses.push('type = ?');
      params.push(type);
    }

    const category = sanitize(req.query.category, 100);
    if (category && category !== 'all') {
      clauses.push('category = ?');
      params.push(category);
    }

    const from = sanitize(req.query.from, 10);
    if (from) {
      if (!isDate(from)) return res.status(400).json({ error: 'Invalid start date filter.' });
      clauses.push('date >= ?');
      params.push(from);
    }

    const to = sanitize(req.query.to, 10);
    if (to) {
      if (!isDate(to)) return res.status(400).json({ error: 'Invalid end date filter.' });
      clauses.push('date <= ?');
      params.push(to);
    }

    const q = sanitize(req.query.q, 100);
    if (q) {
      const pattern = `%${escapeLike(q)}%`;
      clauses.push(
        "(note LIKE ? ESCAPE '\\' OR category LIKE ? ESCAPE '\\' OR (CAST(amount_paise / 100 AS TEXT) || '.' || printf('%02d', amount_paise % 100)) LIKE ? ESCAPE '\\')"
      );
      params.push(pattern, pattern, pattern);
    }

    const sortCol = TX_SORT_COLUMNS.get(sanitize(req.query.sortBy, 20)) || 'date';
    const sortDir = TX_SORT_DIRS.get(sanitize(req.query.sortDir, 10).toLowerCase()) || 'DESC';

    const sql = `
      SELECT id, type, amount_paise, currency, category, date, note,
             needs_currency_review, original_currency, original_amount, created_at
      FROM transactions
      WHERE ${clauses.join(' AND ')}
      ORDER BY ${sortCol} ${sortDir}, created_at DESC
    `;
    const rows = db.prepare(sql).all(...params);
    res.json(rows.map(formatTxRow));
  });

  app.post('/api/transactions', requireAuth, requireCsrf, (req, res) => {
    const { type, amountPaise, amount, currency, category, date, note, clientRequestId } = req.body;

    if (currency !== undefined && String(currency).toUpperCase() !== APP_CURRENCY) {
      return res.status(400).json({ error: 'Only Indian rupees (INR) are supported.' });
    }
    if (!VALID_TX_TYPES.has(type)) {
      return res.status(400).json({ error: 'Type must be income or expense.' });
    }

    const resolvedPaise = resolvePaiseInput(amountPaise, amount, { allowNegative: false, allowZero: false });
    if (!resolvedPaise) {
      return res.status(400).json({
        error: 'Enter a positive amount in rupees and paise (at most 2 decimal places, e.g. 250.50).',
      });
    }

    const cleanCat = sanitizeStoredText(category, 100);
    if (!cleanCat) {
      return res.status(400).json({ error: 'Category is required.' });
    }
    if (!isDate(date)) {
      return res.status(400).json({ error: 'Date must be in YYYY-MM-DD format.' });
    }

    const cleanNote = sanitizeStoredText(note, 500);
    const sourceId = sanitize(clientRequestId, 80) || null;

    if (sourceId) {
      const existing = db.prepare(`
        SELECT id, type, amount_paise, currency, category, date, note,
               needs_currency_review, original_currency, original_amount, created_at
        FROM transactions WHERE user_pk = ? AND source_id = ?
      `).get(req.session.userPk, sourceId);
      if (existing) {
        return res.status(200).json({ ok: true, id: existing.id, transaction: formatTxRow(existing), deduplicated: true });
      }
    }

    const txId = crypto.randomUUID();
    db.prepare(`
      INSERT INTO transactions (id, user_pk, type, amount_paise, currency, category, date, note, source_id, needs_currency_review)
      VALUES (?, ?, ?, ?, 'INR', ?, ?, ?, ?, 0)
    `).run(txId, req.session.userPk, type, resolvedPaise, cleanCat, date, cleanNote, sourceId);

    const created = db.prepare(`
      SELECT id, type, amount_paise, currency, category, date, note,
             needs_currency_review, original_currency, original_amount, created_at
      FROM transactions WHERE user_pk = ? AND id = ?
    `).get(req.session.userPk, txId);

    res.status(201).json({ ok: true, id: txId, transaction: formatTxRow(created) });
  });

  app.put('/api/transactions/:txId', requireAuth, requireCsrf, (req, res) => {
    const txId = sanitize(req.params.txId, 80);
    const cur = db.prepare('SELECT * FROM transactions WHERE id = ? AND user_pk = ?').get(txId, req.session.userPk);
    if (!cur) {
      return res.status(404).json({ error: 'Transaction not found.' });
    }

    const { type, amountPaise, amount, currency, category, date, note, confirmCurrencyReview } = req.body;
    if (currency !== undefined && String(currency).toUpperCase() !== APP_CURRENCY) {
      return res.status(400).json({ error: 'Only Indian rupees (INR) are supported.' });
    }
    if (type !== undefined && !VALID_TX_TYPES.has(type)) {
      return res.status(400).json({ error: 'Invalid transaction type.' });
    }

    const nextPaise = resolvePaiseInput(amountPaise, amount, { allowNegative: false, allowZero: false });
    if (nextPaise === null) {
      return res.status(400).json({
        error: 'Enter a positive amount in rupees and paise (at most 2 decimal places, e.g. 250.50).',
      });
    }

    if (category !== undefined && !sanitizeStoredText(category, 100)) {
      return res.status(400).json({ error: 'Category is required.' });
    }
    if (date !== undefined && !isDate(date)) {
      return res.status(400).json({ error: 'Invalid date format.' });
    }

    // Reviewing/updating an amount or explicitly confirming marks the transaction ready in INR
    const clearReview = confirmCurrencyReview === true || nextPaise !== undefined;

    db.prepare(`
      UPDATE transactions SET
        type                  = ?,
        amount_paise          = ?,
        currency              = 'INR',
        category              = ?,
        date                  = ?,
        note                  = ?,
        needs_currency_review = ?,
        updated_at            = datetime('now')
      WHERE id = ? AND user_pk = ?
    `).run(
      type !== undefined ? type : cur.type,
      nextPaise !== undefined ? nextPaise : cur.amount_paise,
      category !== undefined ? sanitizeStoredText(category, 100) : cur.category,
      date !== undefined ? date : cur.date,
      note !== undefined ? sanitizeStoredText(note, 500) : cur.note,
      clearReview ? 0 : cur.needs_currency_review,
      txId,
      req.session.userPk,
    );

    const updated = db.prepare(`
      SELECT id, type, amount_paise, currency, category, date, note,
             needs_currency_review, original_currency, original_amount, created_at
      FROM transactions WHERE id = ? AND user_pk = ?
    `).get(txId, req.session.userPk);

    res.json({ ok: true, transaction: formatTxRow(updated) });
  });

  app.post('/api/transactions/:txId/review-inr', requireAuth, requireCsrf, (req, res) => {
    const txId = sanitize(req.params.txId, 80);
    const cur = db.prepare('SELECT * FROM transactions WHERE id = ? AND user_pk = ?').get(txId, req.session.userPk);
    if (!cur) return res.status(404).json({ error: 'Transaction not found.' });

    const { amountPaise, amount } = req.body;
    const nextPaise = resolvePaiseInput(amountPaise, amount, { allowNegative: false, allowZero: false });
    if (nextPaise === null) {
      return res.status(400).json({ error: 'Enter a valid rupee amount (up to 2 decimal places).' });
    }

    db.prepare(`
      UPDATE transactions SET
        amount_paise          = ?,
        currency              = 'INR',
        needs_currency_review = 0,
        updated_at            = datetime('now')
      WHERE id = ? AND user_pk = ?
    `).run(nextPaise !== undefined ? nextPaise : cur.amount_paise, txId, req.session.userPk);

    const updated = db.prepare(`
      SELECT id, type, amount_paise, currency, category, date, note,
             needs_currency_review, original_currency, original_amount, created_at
      FROM transactions WHERE id = ? AND user_pk = ?
    `).get(txId, req.session.userPk);

    res.json({ ok: true, transaction: formatTxRow(updated) });
  });

  app.delete('/api/transactions/:txId', requireAuth, requireCsrf, (req, res) => {
    const txId = sanitize(req.params.txId, 80);
    const r = db.prepare('DELETE FROM transactions WHERE id = ? AND user_pk = ?').run(txId, req.session.userPk);
    if (r.changes === 0) {
      return res.status(404).json({ error: 'Transaction not found.' });
    }
    res.json({ ok: true });
  });

  // ═════════════════════════════════════════════════════════════════════════
  //  IMPORT local data (duplicate-safe, flags non-INR entries for review)
  // ═════════════════════════════════════════════════════════════════════════

  app.post('/api/import', requireAuth, requireCsrf, (req, res) => {
    const {
      transactions = [],
      categories = [],
      settings = null,
      importSettings = false,
    } = req.body;

    if (!Array.isArray(transactions) || !Array.isArray(categories)) {
      return res.status(400).json({ error: 'Invalid import format.' });
    }

    const userSettings = db.prepare('SELECT * FROM settings WHERE user_pk = ?').get(req.session.userPk);
    const defaultLocalCur = settings && typeof settings.currency === 'string'
      ? (sanitizeStoredText(settings.currency, 16).toUpperCase() || APP_CURRENCY)
      : APP_CURRENCY;

    let importedTx = 0;
    let flaggedForReview = 0;
    let skippedTx = 0;
    let importedCats = 0;

    withTransaction(() => {
      const addCat = db.prepare('INSERT OR IGNORE INTO categories (user_pk, name, sort_order) VALUES (?, ?, ?)');
      const countCats = db.prepare('SELECT COUNT(*) AS c FROM categories WHERE user_pk = ?');
      const addTx = db.prepare(`
        INSERT OR IGNORE INTO transactions (
          id, user_pk, type, amount_paise, currency, category, date, note,
          source_id, needs_currency_review, original_currency, original_amount
        ) VALUES (?, ?, ?, ?, 'INR', ?, ?, ?, ?, ?, ?, ?)
      `);

      categories.forEach((cat) => {
        const clean = sanitizeStoredText(cat, 50);
        if (!clean) return;
        const c = countCats.get(req.session.userPk)?.c ?? 0;
        const r = addCat.run(req.session.userPk, clean, c);
        if (r.changes > 0) importedCats++;
      });

      transactions.forEach((tx, i) => {
        if (!tx || !VALID_TX_TYPES.has(tx.type)) return;
        const rawAmt = tx.amountPaise !== undefined
          ? Number(tx.amountPaise)
          : parseRupeesToPaise(
              typeof tx.amount === 'number' ? tx.amount.toFixed(2) : String(tx.amount ?? ''),
              { allowNegative: false, allowZero: false }
            );
        if (!rawAmt || !Number.isSafeInteger(rawAmt) || rawAmt <= 0 || rawAmt > MAX_PAISE) return;
        if (!isDate(tx.date)) return;

        const txCur = typeof tx.currency === 'string' && tx.currency.trim()
          ? (sanitizeStoredText(tx.currency, 16).toUpperCase() || defaultLocalCur)
          : defaultLocalCur;
        const isForeign = txCur !== APP_CURRENCY;

        const cleanCat = sanitizeStoredText(tx.category || 'Other', 100) || 'Other';
        const cleanNote = sanitizeStoredText(tx.note || '', 500);
        const fingerprint = crypto
          .createHash('sha256')
          .update(`${tx.id || i}|${tx.type}|${rawAmt}|${txCur}|${cleanCat}|${tx.date}|${cleanNote}`)
          .digest('hex')
          .slice(0, 32);
        const sourceId = `local:${sanitize(tx.id, 64) || fingerprint}`;
        const txId = crypto.randomUUID();

        const origAmtDisplay = tx.amount !== undefined
          ? sanitizeStoredText(String(tx.amount), 40)
          : paiseToDecimalString(rawAmt);

        const r = addTx.run(
          txId, req.session.userPk, tx.type, rawAmt, cleanCat, tx.date, cleanNote,
          sourceId, isForeign ? 1 : 0, isForeign ? txCur : null, isForeign ? origAmtDisplay : null
        );
        if (r.changes > 0) {
          importedTx++;
          if (isForeign) flaggedForReview++;
        } else {
          skippedTx++;
        }
      });

      if (importSettings && settings && typeof settings === 'object' && userSettings) {
        const setCur = typeof settings.currency === 'string' && settings.currency.trim()
          ? (sanitizeStoredText(settings.currency, 16).toUpperCase() || APP_CURRENCY)
          : APP_CURRENCY;
        const isForeignSet = setCur !== APP_CURRENCY;

        const limPaise = settings.limitPaise !== undefined
          ? resolvePaiseInput(settings.limitPaise, undefined)
          : parseRupeesToPaise(
              typeof settings.limit === 'number' ? settings.limit.toFixed(2) : String(settings.limit ?? ''),
              { allowNegative: false, allowZero: false }
            );
        const balPaise = settings.balancePaise !== undefined
          ? resolvePaiseInput(settings.balancePaise, undefined, { allowNegative: true, allowZero: true })
          : parseRupeesToPaise(
              typeof settings.balance === 'number' ? settings.balance.toFixed(2) : String(settings.balance ?? '0'),
              { allowNegative: true, allowZero: true }
            );

        const per = VALID_PERIODS.has(settings.period) ? settings.period : userSettings.period;
        const thr = Number.isInteger(Number(settings.alertThreshold)) && Number(settings.alertThreshold) >= 1 && Number(settings.alertThreshold) <= 200
          ? Number(settings.alertThreshold)
          : userSettings.alert_threshold;

        let validCatBudgets = safeJsonParse(userSettings.cat_budgets_paise, {});
        const srcBudgets = settings.catBudgetsPaise || settings.catBudgets;
        if (srcBudgets && typeof srcBudgets === 'object' && !Array.isArray(srcBudgets)) {
          const merged = { ...validCatBudgets };
          for (const [k, v] of Object.entries(srcBudgets)) {
            if (k === '__proto__' || k === 'constructor' || k === 'prototype') continue;
            const cleanKey = sanitizeStoredText(k, 50);
            if (!cleanKey) continue;
            const p = settings.catBudgetsPaise
              ? resolvePaiseInput(Number(v), undefined)
              : parseRupeesToPaise(typeof v === 'number' ? v.toFixed(2) : String(v));
            if (p && p > 0) merged[cleanKey] = p;
          }
          validCatBudgets = merged;
        }

        db.prepare(`
          UPDATE settings SET
            setup_done            = 1,
            currency              = 'INR',
            period                = ?,
            limit_paise           = ?,
            balance_paise         = ?,
            alert_threshold       = ?,
            notif_in_app          = ?,
            notif_browser         = ?,
            cat_budgets_paise     = ?,
            needs_currency_review = ?,
            legacy_currency       = ?,
            legacy_limit_amount   = ?,
            legacy_balance        = ?,
            updated_at            = datetime('now')
          WHERE user_pk = ?
        `).run(
          per,
          limPaise || userSettings.limit_paise,
          balPaise !== null && balPaise !== undefined ? balPaise : userSettings.balance_paise,
          thr,
          settings.notifInApp !== undefined ? (settings.notifInApp ? 1 : 0) : userSettings.notif_in_app,
          settings.notifBrowser !== undefined ? (settings.notifBrowser ? 1 : 0) : userSettings.notif_browser,
          JSON.stringify(validCatBudgets),
          isForeignSet ? 1 : userSettings.needs_currency_review,
          isForeignSet ? sanitizeStoredText(setCur, 16) : userSettings.legacy_currency,
          isForeignSet && settings.limit !== undefined ? sanitizeStoredText(String(settings.limit), 40) : userSettings.legacy_limit_amount,
          isForeignSet && settings.balance !== undefined ? sanitizeStoredText(String(settings.balance), 40) : userSettings.legacy_balance,
          req.session.userPk,
        );
      }
    });

    res.json({
      ok: true,
      imported: importedTx,
      flaggedForReview,
      skipped: skippedTx,
      importedCategories: importedCats,
    });
  });

  // ── SPA fallback & error handler ──────────────────────────────────────────
  app.get(/^(?!\/api).*/, (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
  });

  app.use((err, req, res, _next) => {
    logEvent('error', 'server.unhandled_error', {
      method: req.method,
      path: req.path,
      message: err?.message || 'Unknown error',
      ip: getClientIp(req),
      userPk: req.session?.userPk ?? null,
    });
    if (res.headersSent) return;
    res.status(500).json({ error: 'Server error. Please try again.' });
  });

  return { app, db };
}

if (require.main === module) {
  const PORT = process.env.PORT || 3000;
  const HOST = process.env.HOST;
  const { app } = createApp();
  const onListen = () => {
    const shownHost = HOST || 'localhost';
    console.log(`\n✅  SpendWise (INR) running → http://${shownHost}:${PORT}\n`);
  };
  if (HOST) app.listen(PORT, HOST, onListen);
  else app.listen(PORT, onListen);
}

module.exports = {
  createApp,
  validatePassword,
  validateUserId,
  parseRupeesToPaise,
  paiseToDecimalString,
  sanitize,
  sanitizeStoredText,
  APP_CURRENCY,
};
