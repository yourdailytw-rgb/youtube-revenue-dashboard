/**
 * YouTube Revenue Dashboard v2 — server entry point.
 *
 * Startup sequence:
 *   1. Express middleware (body parsing, auth gate)
 *   2. Routes (login, OAuth, API)
 *   3. Static SPA from client/dist with history fallback
 *   4. Listen
 *   5. Refresh all OAuth tokens, then run a sync in the background
 *   6. Schedule token refresh (6h), health check (12h) and sync (configurable)
 */

const path = require('path');
const fs = require('fs');
const express = require('express');

const config = require('./config');
const auth = require('./auth');
const routes = require('./routes');
const oauth = require('./oauth');
const sync = require('./sync');
const db = require('./db');

const app = express();
app.disable('x-powered-by');
app.set('trust proxy', 1);
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Auth gate runs before everything except the open paths listed in auth.js.
app.use(auth.middleware);
app.use(routes);

const CLIENT_DIST = path.join(config.ROOT, 'client', 'dist');
const hasClientBuild = fs.existsSync(path.join(CLIENT_DIST, 'index.html'));

if (hasClientBuild) {
  app.use(
    express.static(CLIENT_DIST, {
      setHeaders(res, filePath) {
        // Vite fingerprints assets; index.html must never be cached.
        if (filePath.endsWith('index.html')) res.setHeader('Cache-Control', 'no-cache');
        else res.setHeader('Cache-Control', 'public, max-age=31536000, immutable');
      },
    })
  );
  // SPA history fallback (Express 5 dislikes '*' route patterns).
  app.use((req, res, next) => {
    if (req.method !== 'GET' || req.path.startsWith('/api/')) return next();
    res.sendFile(path.join(CLIENT_DIST, 'index.html'));
  });
} else {
  app.use((req, res, next) => {
    if (req.path.startsWith('/api/')) return next();
    res
      .status(503)
      .send(
        '<h1>Client not built</h1><p>Run <code>npm run build</code> (or <code>npm run dev</code> for the Vite dev server).</p>'
      );
  });
}

app.use((err, req, res, _next) => {
  console.error('[error]', err.stack || err.message);
  if (res.headersSent) return;
  res.status(500).json({ error: err.message || 'Internal server error' });
});

const server = app.listen(config.PORT, async () => {
  const base = config.RAILWAY_PUBLIC_DOMAIN
    ? `https://${config.RAILWAY_PUBLIC_DOMAIN}`
    : `http://localhost:${config.PORT}`;

  console.log(`YouTube Revenue Dashboard v2 running at ${base}`);
  console.log(`  data dir : ${config.DATA_DIR}${config.ON_VOLUME ? ' (Railway Volume)' : ''}`);
  console.log(`  database : ${config.DB_FILE}`);
  console.log(`  auth     : ${auth.AUTH_REQUIRED ? `${auth.USERS.size} user(s) + shared password` : 'DISABLED'}`);
  console.log(`  client   : ${hasClientBuild ? 'built' : 'NOT BUILT'}`);

  auth.purgeExpiredSessions();

  await oauth.refreshAllTokens();

  sync.syncAll().catch((err) => console.error('[startup] Initial sync failed:', err.message));

  setInterval(() => {
    oauth.refreshAllTokens().catch((err) => console.error('[refresh] interval failed:', err.message));
  }, config.TOKEN_REFRESH_HOURS * 60 * 60 * 1000);

  setInterval(() => {
    auth.purgeExpiredSessions();
    const health = db.getState('lastSync');
    console.log('[health] last sync:', health ? health.at : 'never');
  }, config.HEALTH_CHECK_HOURS * 60 * 60 * 1000);

  sync.startScheduler();
});

function shutdown(signal) {
  console.log(`\n[${signal}] shutting down`);
  server.close(() => process.exit(0));
  setTimeout(() => process.exit(0), 5000).unref();
}
process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));

module.exports = app;
