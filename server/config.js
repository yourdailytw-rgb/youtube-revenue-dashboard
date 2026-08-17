require('dotenv').config();

const fs = require('fs');
const path = require('path');

const ROOT = path.join(__dirname, '..');

/**
 * Railway mounts a persistent Volume at /data. Everything that must survive a
 * deploy (tokens, the metrics database) lives there. When the volume is absent
 * we fall back to a local ./data directory so local dev behaves the same.
 */
function resolveDataDir() {
  // Used by the test scripts so they never touch the real database.
  if (process.env.DATA_DIR_OVERRIDE) {
    fs.mkdirSync(process.env.DATA_DIR_OVERRIDE, { recursive: true });
    return process.env.DATA_DIR_OVERRIDE;
  }
  try {
    if (fs.existsSync('/data') && fs.statSync('/data').isDirectory()) {
      console.log('[config] Railway Volume detected at /data — using persistent storage');
      return '/data';
    }
  } catch {
    /* /data not available */
  }
  const local = path.join(ROOT, 'data');
  fs.mkdirSync(local, { recursive: true });
  console.warn(`[config] No Railway Volume at /data — using ${local} (NOT persistent on Railway)`);
  return local;
}

const DATA_DIR = resolveDataDir();
const ON_VOLUME = DATA_DIR === '/data';

const config = {
  ROOT,
  DATA_DIR,
  ON_VOLUME,

  PORT: Number(process.env.PORT) || 3000,
  CURRENCY: process.env.CURRENCY || 'SEK',

  // Token storage (3 layers — see server/tokens.js)
  VOLUME_TOKENS_FILE: '/data/tokens.json',
  LOCAL_TOKENS_FILE: path.join(ROOT, 'tokens.json'),
  DB_FILE: path.join(DATA_DIR, 'metrics.db'),

  CLIENT_ID: process.env.CLIENT_ID,
  CLIENT_SECRET: process.env.CLIENT_SECRET,

  SCOPES: [
    'https://www.googleapis.com/auth/yt-analytics.readonly',
    'https://www.googleapis.com/auth/yt-analytics-monetary.readonly',
    'https://www.googleapis.com/auth/youtube.readonly',
  ],

  DASHBOARD_PASSWORD: process.env.DASHBOARD_PASSWORD,
  DASHBOARD_USERS: process.env.DASHBOARD_USERS,

  RAILWAY_API_TOKEN: process.env.RAILWAY_API_TOKEN,
  RAILWAY_SERVICE_ID: process.env.RAILWAY_SERVICE_ID,
  RAILWAY_ENVIRONMENT_ID: process.env.RAILWAY_ENVIRONMENT_ID,
  RAILWAY_PUBLIC_DOMAIN: process.env.RAILWAY_PUBLIC_DOMAIN,

  BACKFILL_START: process.env.BACKFILL_START || '2024-01-01',
  SYNC_REFRESH_DAYS: Number(process.env.SYNC_REFRESH_DAYS) || 14,
  SYNC_INTERVAL_MINUTES: Number(process.env.SYNC_INTERVAL_MINUTES) || 180,
  // How often to snapshot the live cumulative view counter. Needs to be well
  // under an hour so the last snapshot before midnight Pacific lands close to
  // the actual day boundary.
  LIVE_POLL_MINUTES: Number(process.env.LIVE_POLL_MINUTES) || 20,

  // Token refresh cadence, unchanged from v1.
  TOKEN_REFRESH_HOURS: 6,
  HEALTH_CHECK_HOURS: 12,
};

module.exports = config;
