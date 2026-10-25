/**
 * 2FA 驗證器 — Express 伺服器 (Docker 版, v2.0.0)
 *
 * 安全設計（與 worker.js 對齊）：
 * - 嚴格驗證 key 格式（64 位十六進位）
 * - 請求大小上限、記憶體式速率限制
 * - 完整安全標頭（CSP / X-Frame-Options / …）
 * - API 回應一律 no-store
 */
'use strict';

const express = require('express');
const path = require('path');
const Database = require('better-sqlite3');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 3000;
const DB_PATH = process.env.DB_PATH || './data/2fa.db';
// 可選：允許的跨域來源（逗號分隔）；未設定時僅允許同源
const ALLOWED_ORIGIN = process.env.ALLOWED_ORIGIN || '';
// 速率限制（每 IP 每分鐘）
const RATE_LIMIT_READS = parseInt(process.env.RATE_LIMIT_READS || '300', 10);
const RATE_LIMIT_WRITES = parseInt(process.env.RATE_LIMIT_WRITES || '60', 10);

const KEY_RE = /^[a-f0-9]{64}$/;
const SALT_RE = /^[A-Za-z0-9+/=]{8,64}$/;
const MAX_DATA_LENGTH = 2 * 1024 * 1024;

const CSP = "default-src 'self'; script-src 'self' 'sha256-gERs5DaPoPALkgMmhL7Euk0rL2kXQCOlmad6Zl1WSLM='; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; connect-src 'self'; media-src 'self' blob:; object-src 'none'; base-uri 'self'; form-action 'none'; frame-ancestors 'none'";

// Ensure data directory exists
const dataDir = path.dirname(DB_PATH);
if (!fs.existsSync(dataDir)) {
  fs.mkdirSync(dataDir, { recursive: true });
}

// Initialize SQLite database
const db = new Database(DB_PATH);
db.pragma('journal_mode = WAL');

db.exec(`
  CREATE TABLE IF NOT EXISTS data_store (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at INTEGER NOT NULL
  )
`);

const insertStmt = db.prepare(`
  INSERT INTO data_store (key, value, updated_at)
  VALUES (?, ?, ?)
  ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at
`);
const selectStmt = db.prepare('SELECT value FROM data_store WHERE key = ?');
const deleteStmt = db.prepare('DELETE FROM data_store WHERE key = ?');

app.disable('x-powered-by');
// 部署在反向代理（Cloudflare / nginx）後面時正確取得客戶端 IP
app.set('trust proxy', true);

// Body parser with size limit
app.use(express.json({ limit: '2500kb' }));

// ============ 安全標頭 ============
app.use((req, res, next) => {
  res.setHeader('Content-Security-Policy', CSP);
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Permissions-Policy', 'camera=(self), microphone=(), geolocation=(), payment=()');
  next();
});

// ============ CORS（僅同源，或 ALLOWED_ORIGIN 清單） ============
function originAllowed(req) {
  const origin = req.headers.origin;
  if (!origin) return true;
  const host = req.headers.host;
  if (host && origin === `${req.protocol}://${host}`) return true;
  if (ALLOWED_ORIGIN) {
    const list = ALLOWED_ORIGIN.split(',').map(s => s.trim()).filter(Boolean);
    return list.includes(origin);
  }
  return false;
}

app.use((req, res, next) => {
  if (!originAllowed(req)) {
    return res.status(403).json({ error: 'Forbidden' });
  }
  const origin = req.headers.origin;
  if (origin && originAllowed(req)) {
    res.header('Access-Control-Allow-Origin', origin);
    res.header('Access-Control-Allow-Methods', 'GET, PUT, DELETE, OPTIONS');
    res.header('Access-Control-Allow-Headers', 'Content-Type');
    res.header('Access-Control-Max-Age', '86400');
    res.header('Vary', 'Origin');
  }
  if (req.method === 'OPTIONS') {
    return res.sendStatus(204);
  }
  next();
});

// ============ 記憶體式速率限制 ============
const rateBuckets = new Map(); // ip -> { read, write, resetAt }
setInterval(() => {
  const now = Date.now();
  for (const [ip, b] of rateBuckets) {
    if (b.resetAt < now) rateBuckets.delete(ip);
  }
}, 60000).unref();

function rateLimit(req, res, next) {
  const ip = req.headers['cf-connecting-ip'] || req.ip || 'unknown';
  const now = Date.now();
  let bucket = rateBuckets.get(ip);
  if (!bucket || bucket.resetAt < now) {
    bucket = { read: 0, write: 0, resetAt: now + 60000 };
    rateBuckets.set(ip, bucket);
  }
  const isWrite = req.method === 'PUT' || req.method === 'DELETE';
  if (isWrite) bucket.write += 1;
  else bucket.read += 1;
  if (bucket.write > RATE_LIMIT_WRITES || bucket.read > RATE_LIMIT_READS) {
    res.setHeader('Retry-After', '60');
    return res.status(429).json({ error: 'Too many requests' });
  }
  next();
}

// Health check endpoint
app.get('/health', (req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  res.json({ status: 'ok', timestamp: Date.now() });
});

// ============ API ============
app.get('/api/data', rateLimit, (req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  try {
    const key = req.query.key;
    if (!key || typeof key !== 'string' || !KEY_RE.test(key)) {
      return res.status(400).json({ error: 'Invalid key' });
    }
    const row = selectStmt.get(key);
    if (!row) {
      return res.json({ exists: false, data: null });
    }
    return res.json({ exists: true, data: row.value });
  } catch (error) {
    console.error('Database error:', error);
    return res.status(500).json({ error: 'Internal error' });
  }
});

app.put('/api/data', rateLimit, (req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  try {
    const { key, data, salt, version } = req.body || {};

    if (!key || typeof key !== 'string' || !KEY_RE.test(key)) {
      return res.status(400).json({ error: 'Invalid key' });
    }
    if (!data || typeof data !== 'string') {
      return res.status(400).json({ error: 'Missing data' });
    }
    if (data.length > MAX_DATA_LENGTH) {
      return res.status(413).json({ error: 'Payload too large' });
    }
    if (!salt || typeof salt !== 'string' || !SALT_RE.test(salt)) {
      return res.status(400).json({ error: 'Invalid salt' });
    }
    const ver = version === undefined ? 1 : version;
    if (typeof ver !== 'number' || !Number.isInteger(ver) || ver < 1 || ver > 9) {
      return res.status(400).json({ error: 'Invalid version' });
    }

    const stored = JSON.stringify({
      encryptedData: data,
      salt,
      version: ver,
      updatedAt: Date.now(),
    });
    insertStmt.run(key, stored, Date.now());
    return res.json({ success: true });
  } catch (error) {
    console.error('Database error:', error);
    return res.status(500).json({ error: 'Internal error' });
  }
});

app.delete('/api/data', rateLimit, (req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  try {
    const key = req.query.key;
    if (!key || typeof key !== 'string' || !KEY_RE.test(key)) {
      return res.status(400).json({ error: 'Invalid key' });
    }
    deleteStmt.run(key);
    return res.json({ success: true });
  } catch (error) {
    console.error('Database error:', error);
    return res.status(500).json({ error: 'Internal error' });
  }
});

// ============ 靜態檔案 ============
const publicDir = path.join(__dirname, '../public');
app.use(express.static(publicDir, {
  extensions: ['html'],
  setHeaders: (res, filePath) => {
    if (filePath.endsWith('.html')) {
      res.setHeader('Cache-Control', 'no-cache');
    }
  },
}));

// SPA fallback（僅 GET）
app.get('*', (req, res) => {
  res.setHeader('Cache-Control', 'no-cache');
  res.sendFile(path.join(publicDir, 'index.html'));
});

// 404 for non-GET
app.use((req, res) => {
  res.status(404).json({ error: 'Not found' });
});

// Start server
app.listen(PORT, () => {
  console.log(`2FA Authenticator server running on port ${PORT}`);
  console.log(`Database: ${path.resolve(DB_PATH)}`);
});

// Graceful shutdown
function shutdown() {
  console.log('Shutting down...');
  try { db.close(); } catch (e) { /* already closed */ }
  process.exit(0);
}
process.on('SIGTERM', shutdown);
process.on('SIGINT', shutdown);
