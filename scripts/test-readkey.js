/**
 * Jarvis read-only key checks.
 *
 *   node scripts/test-readkey.js
 *
 * Runs the auth middleware in-process against fake requests: the key opens the
 * read routes (GET only) without a session, and nothing else; a wrong key is
 * refused; with no key configured the gate behaves exactly as before.
 */

const fs = require('fs');
const os = require('os');
const path = require('path');
const assert = require('node:assert');

const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ytdash-readkey-'));
process.env.DATA_DIR_OVERRIDE = tmpDir;
process.env.DOTENV_CONFIG_QUIET = 'true';

const KEY = 'k'.repeat(24) + 'Jarvis-read-key-for-tests';

/** Loads auth.js fresh with the given environment (config is read at load time). */
function loadAuth(env) {
  for (const [k, v] of Object.entries(env)) process.env[k] = v;
  for (const mod of ['../server/config', '../server/auth']) delete require.cache[require.resolve(mod)];
  return require('../server/auth');
}

/** Runs the middleware once; returns 'next', or the status code it answered with. */
function run(auth, { method = 'GET', path: p, key, cookie } = {}) {
  const headers = {};
  if (key) headers.authorization = `Bearer ${key}`;
  if (cookie) headers.cookie = cookie;
  const req = { method, path: p, originalUrl: p, headers };
  let outcome = null;
  const res = {
    status(code) { outcome = code; return this; },
    json() { return this; },
    redirect() { outcome = 'redirect'; return this; },
  };
  auth.middleware(req, res, () => { outcome = 'next'; });
  return outcome;
}

let passed = 0;
function test(name, fn) {
  try {
    fn();
    passed++;
    console.log(`  ✓ ${name}`);
  } catch (err) {
    console.error(`  ✗ ${name}\n    ${err.message}`);
    process.exitCode = 1;
  }
}

console.log('Jarvis read-only key');

let auth = loadAuth({ DASHBOARD_PASSWORD: 'test-password', DASHBOARD_USERS: '', JARVIS_READ_KEY: KEY });

test('the key opens every read route with GET, without a session', () => {
  for (const p of ['/api/analytics', '/api/videos', '/api/channels', '/api/estimates', '/api/live-pace', '/api/live-status', '/api/sync/status', '/api/channels/']) {
    assert.strictEqual(run(auth, { path: p, key: KEY }), 'next', p);
  }
});

test('the key never reaches tokens, admin, settings or exports', () => {
  for (const p of ['/api/admin/export-tokens', '/api/admin/storage-status', '/api/allowed-emails', '/api/token-health', '/api/export', '/api/me', '/api/trending', '/']) {
    assert.strictEqual(run(auth, { path: p, key: KEY }), 403, p);
  }
});

test('the key cannot write, even on a read route', () => {
  assert.strictEqual(run(auth, { method: 'POST', path: '/api/analytics', key: KEY }), 403);
  assert.strictEqual(run(auth, { method: 'PATCH', path: '/api/channels', key: KEY }), 403);
  assert.strictEqual(run(auth, { method: 'DELETE', path: '/api/channels/abc', key: KEY }), 403);
  assert.strictEqual(run(auth, { method: 'POST', path: '/api/sync', key: KEY }), 403);
});

test('a wrong key is refused', () => {
  assert.strictEqual(run(auth, { path: '/api/analytics', key: KEY + 'x' }), 401);
  assert.strictEqual(run(auth, { path: '/api/analytics', key: 'short' }), 401);
});

test('without a key the gate is unchanged: a session is still required', () => {
  assert.strictEqual(run(auth, { path: '/api/analytics' }), 401);
  assert.strictEqual(run(auth, { path: '/' }), 'redirect');
  assert.strictEqual(run(auth, { path: '/healthz' }), 'next');
  const id = auth.createSession('lucky', 'test');
  assert.strictEqual(run(auth, { path: '/api/admin/export-tokens', cookie: `dashboard_session=${id}` }), 'next', 'a logged-in user is unaffected');
});

auth = loadAuth({ DASHBOARD_PASSWORD: 'test-password', DASHBOARD_USERS: '', JARVIS_READ_KEY: '' });

test('no key configured: a bearer header changes nothing', () => {
  assert.strictEqual(run(auth, { path: '/api/analytics', key: KEY }), 401);
  assert.strictEqual(run(auth, { path: '/api/admin/export-tokens', key: KEY }), 401);
});

auth = loadAuth({ DASHBOARD_PASSWORD: 'test-password', DASHBOARD_USERS: '', JARVIS_READ_KEY: 'too-short-to-count' });

test('a key under 32 characters is off', () => {
  assert.strictEqual(run(auth, { path: '/api/analytics', key: 'too-short-to-count' }), 401);
});

console.log(`\n${passed} passed${process.exitCode ? ', some FAILED' : ''}`);
fs.rmSync(tmpDir, { recursive: true, force: true });
