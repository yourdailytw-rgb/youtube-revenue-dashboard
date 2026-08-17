/**
 * Dashboard access control.
 *
 * Two ways to configure logins:
 *   DASHBOARD_USERS=alice:pw1,bob:pw2,carol:pw3   per-user accounts
 *   DASHBOARD_PASSWORD=shared                     single shared password (v1)
 *
 * Both can be set; the shared password keeps working so nothing breaks the
 * moment this deploys. Sessions are stored in SQLite rather than a Map, so a
 * deploy or restart no longer logs everyone out.
 */

const crypto = require('crypto');
const config = require('./config');
const { db } = require('./db');

const SESSION_DAYS = 30;
const SESSION_MS = SESSION_DAYS * 24 * 60 * 60 * 1000;

db.exec(`
CREATE TABLE IF NOT EXISTS sessions (
  id         TEXT PRIMARY KEY,
  username   TEXT,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  user_agent TEXT
);
`);

function parseUsers() {
  const users = new Map();
  if (config.DASHBOARD_USERS) {
    for (const entry of config.DASHBOARD_USERS.split(',')) {
      const idx = entry.indexOf(':');
      if (idx === -1) continue;
      const name = entry.slice(0, idx).trim();
      const password = entry.slice(idx + 1).trim();
      if (name && password) users.set(name.toLowerCase(), { name, password });
    }
  }
  return users;
}

const USERS = parseUsers();
const AUTH_REQUIRED = USERS.size > 0 || Boolean(config.DASHBOARD_PASSWORD);

function safeEqual(a = '', b = '') {
  const bufA = Buffer.from(String(a));
  const bufB = Buffer.from(String(b));
  if (bufA.length !== bufB.length) return false;
  return crypto.timingSafeEqual(bufA, bufB);
}

/** Returns a username on success, null on failure. */
function verifyCredentials(username, password) {
  if (username) {
    const user = USERS.get(String(username).trim().toLowerCase());
    if (user && safeEqual(password, user.password)) return user.name;
  }
  // Shared-password fallback: password alone is enough.
  if (config.DASHBOARD_PASSWORD && safeEqual(password, config.DASHBOARD_PASSWORD)) {
    return username ? String(username).trim() : 'shared';
  }
  // Allow a named user to log in without typing their name if the password
  // uniquely identifies them.
  if (!username) {
    const matches = [...USERS.values()].filter((u) => safeEqual(password, u.password));
    if (matches.length === 1) return matches[0].name;
  }
  return null;
}

function createSession(username, userAgent) {
  const id = crypto.randomBytes(32).toString('hex');
  const now = Date.now();
  db.prepare(
    'INSERT INTO sessions (id, username, created_at, expires_at, user_agent) VALUES (?, ?, ?, ?, ?)'
  ).run(id, username, now, now + SESSION_MS, (userAgent || '').slice(0, 200));
  return id;
}

function getSession(id) {
  if (!id) return null;
  const row = db.prepare('SELECT * FROM sessions WHERE id = ?').get(id);
  if (!row) return null;
  if (row.expires_at < Date.now()) {
    db.prepare('DELETE FROM sessions WHERE id = ?').run(id);
    return null;
  }
  return row;
}

function destroySession(id) {
  if (id) db.prepare('DELETE FROM sessions WHERE id = ?').run(id);
}

function purgeExpiredSessions() {
  db.prepare('DELETE FROM sessions WHERE expires_at < ?').run(Date.now());
}

function parseCookies(cookieHeader) {
  const cookies = {};
  if (!cookieHeader) return cookies;
  for (const part of cookieHeader.split(';')) {
    const [key, ...rest] = part.trim().split('=');
    if (key) cookies[key] = decodeURIComponent(rest.join('='));
  }
  return cookies;
}

function sessionCookie(id) {
  const secure = config.RAILWAY_PUBLIC_DOMAIN ? ' Secure;' : '';
  return `dashboard_session=${id}; Path=/; HttpOnly;${secure} SameSite=Lax; Max-Age=${SESSION_DAYS * 86400}`;
}

function currentUser(req) {
  if (!AUTH_REQUIRED) return { username: 'open-access' };
  const cookies = parseCookies(req.headers.cookie);
  const session = getSession(cookies.dashboard_session);
  return session ? { username: session.username, sessionId: session.id } : null;
}

/** Paths reachable without logging in. */
const OPEN_PATHS = ['/login', '/logout', '/auth', '/oauth2callback', '/healthz'];

function middleware(req, res, next) {
  if (!AUTH_REQUIRED) return next();
  if (OPEN_PATHS.some((p) => req.path === p || req.path.startsWith(`${p}/`))) return next();
  if (currentUser(req)) return next();

  if (req.path.startsWith('/api/')) {
    return res.status(401).json({ error: 'Not authenticated' });
  }
  return res.redirect(`/login?next=${encodeURIComponent(req.originalUrl || '/')}`);
}

function loginPageHTML({ error = false, next = '/' } = {}) {
  const showUserField = USERS.size > 0;
  return `<!doctype html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Sign in — YouTube Revenue Dashboard</title>
<style>
  :root { color-scheme: dark; }
  * { box-sizing: border-box; }
  body { margin:0; min-height:100vh; display:grid; place-items:center;
    font-family: ui-sans-serif, system-ui, -apple-system, "Segoe UI", sans-serif;
    background: radial-gradient(1200px 600px at 50% -10%, #1c2333 0%, #0b0e14 60%); color:#e6e9ef; }
  .card { width:min(92vw, 380px); background:#141821; border:1px solid #232936;
    border-radius:16px; padding:32px 28px; box-shadow:0 24px 60px rgba(0,0,0,.45); }
  h1 { font-size:19px; margin:0 0 4px; letter-spacing:-0.02em; }
  p.sub { margin:0 0 24px; color:#8b93a7; font-size:13px; }
  label { display:block; font-size:12px; color:#8b93a7; margin:0 0 6px; font-weight:500; }
  input { width:100%; padding:11px 13px; margin-bottom:16px; border-radius:9px;
    border:1px solid #2a3140; background:#0e1219; color:#e6e9ef; font-size:14px; outline:none; }
  input:focus { border-color:#3b82f6; box-shadow:0 0 0 3px rgba(59,130,246,.15); }
  button { width:100%; padding:11px; border:0; border-radius:9px; background:#3b82f6;
    color:#fff; font-size:14px; font-weight:600; cursor:pointer; }
  button:hover { background:#2f74e8; }
  .error { background:rgba(239,68,68,.12); border:1px solid rgba(239,68,68,.35);
    color:#fca5a5; padding:9px 12px; border-radius:8px; font-size:13px; margin-bottom:16px; }
</style></head>
<body>
  <form class="card" method="POST" action="/login">
    <h1>YouTube Revenue Dashboard</h1>
    <p class="sub">Sign in to continue</p>
    ${error ? '<div class="error">Incorrect credentials — try again.</div>' : ''}
    <input type="hidden" name="next" value="${escapeHtml(next)}">
    ${
      showUserField
        ? '<label for="username">Name</label><input id="username" name="username" autocomplete="username" autofocus>'
        : ''
    }
    <label for="password">Password</label>
    <input id="password" name="password" type="password" autocomplete="current-password" ${
      showUserField ? '' : 'autofocus'
    }>
    <button type="submit">Sign in</button>
  </form>
</body></html>`;
}

function escapeHtml(value = '') {
  return String(value).replace(/[&<>"']/g, (c) => ({
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#39;',
  })[c]);
}

/** Only allow same-origin redirect targets. */
function safeNext(value) {
  if (typeof value !== 'string' || !value.startsWith('/') || value.startsWith('//')) return '/';
  return value;
}

module.exports = {
  AUTH_REQUIRED,
  USERS,
  verifyCredentials,
  createSession,
  getSession,
  destroySession,
  purgeExpiredSessions,
  parseCookies,
  sessionCookie,
  currentUser,
  middleware,
  loginPageHTML,
  safeNext,
};
