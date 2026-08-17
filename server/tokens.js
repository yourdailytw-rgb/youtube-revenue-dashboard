/**
 * 3-layer OAuth token persistence — ported unchanged in behaviour from v1.
 *
 *   1. Railway Volume  (/data/tokens.json)   primary, survives deploys
 *   2. Local file      (./tokens.json)       secondary / local dev
 *   3. STORED_TOKENS   (base64 env var)      last resort, pushed to Railway API
 *
 * The on-disk shape is IDENTICAL to v1 so an existing /data/tokens.json or
 * STORED_TOKENS backup keeps every connected channel working after this
 * rebuild deploys:
 *
 *   { [channelId]: { tokens, channelTitle, channelThumbnail, connectedAt } }
 *
 * Do NOT remove a layer, and do NOT drop the updateRailwayEnvVar() call from
 * saveTokens() — losing this loses every channel connection.
 */

const fs = require('fs');
const https = require('https');
const config = require('./config');

const VOLUME_TOKENS_FILE = config.VOLUME_TOKENS_FILE;
const LOCAL_TOKENS_FILE = config.LOCAL_TOKENS_FILE;

const TOKENS_FILE = config.ON_VOLUME ? VOLUME_TOKENS_FILE : LOCAL_TOKENS_FILE;

/** Per-channel token health, kept in memory and surfaced at /api/token-health. */
const channelHealth = {};

function readJsonFile(file) {
  if (!fs.existsSync(file)) return null;
  try {
    const data = JSON.parse(fs.readFileSync(file, 'utf-8'));
    return data && Object.keys(data).length > 0 ? data : null;
  } catch (err) {
    console.error(`[tokens] Failed to read ${file}:`, err.message);
    return null;
  }
}

function loadTokens() {
  const primary = readJsonFile(TOKENS_FILE);
  if (primary) return primary;

  const fallbackFile = TOKENS_FILE === VOLUME_TOKENS_FILE ? LOCAL_TOKENS_FILE : VOLUME_TOKENS_FILE;
  const fallback = readJsonFile(fallbackFile);
  if (fallback) {
    console.log(`[tokens] Restored from fallback: ${fallbackFile}`);
    try {
      fs.writeFileSync(TOKENS_FILE, JSON.stringify(fallback, null, 2));
    } catch {
      /* best effort */
    }
    return fallback;
  }

  if (process.env.STORED_TOKENS) {
    try {
      const decoded = JSON.parse(Buffer.from(process.env.STORED_TOKENS, 'base64').toString('utf-8'));
      if (Object.keys(decoded).length > 0) {
        try {
          fs.writeFileSync(TOKENS_FILE, JSON.stringify(decoded, null, 2));
        } catch {
          /* best effort */
        }
        console.log('[tokens] Restored from STORED_TOKENS env var');
        return decoded;
      }
    } catch (err) {
      console.error('[tokens] Failed to parse STORED_TOKENS:', err.message);
    }
  }

  console.warn('[tokens] WARNING: No tokens found anywhere');
  return {};
}

function saveTokens(data) {
  fs.writeFileSync(TOKENS_FILE, JSON.stringify(data, null, 2));

  const secondaryFile = TOKENS_FILE === VOLUME_TOKENS_FILE ? LOCAL_TOKENS_FILE : VOLUME_TOKENS_FILE;
  try {
    fs.writeFileSync(secondaryFile, JSON.stringify(data, null, 2));
  } catch {
    /* secondary is best-effort */
  }

  const encoded = Buffer.from(JSON.stringify(data)).toString('base64');
  updateRailwayEnvVar(encoded);
}

/** Layer 3: push a base64 backup into the Railway STORED_TOKENS env var. */
function updateRailwayEnvVar(base64Tokens) {
  const { RAILWAY_API_TOKEN, RAILWAY_SERVICE_ID, RAILWAY_ENVIRONMENT_ID } = config;
  if (!RAILWAY_API_TOKEN || !RAILWAY_SERVICE_ID || !RAILWAY_ENVIRONMENT_ID) return;

  const query = `mutation($input: VariableCollectionUpsertInput!) {
    variableCollectionUpsert(input: $input)
  }`;
  const variables = {
    input: {
      serviceId: RAILWAY_SERVICE_ID,
      environmentId: RAILWAY_ENVIRONMENT_ID,
      variables: { STORED_TOKENS: base64Tokens },
    },
  };
  const body = JSON.stringify({ query, variables });

  const req = https.request(
    {
      hostname: 'backboard.railway.app',
      path: '/graphql/v2',
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${RAILWAY_API_TOKEN}`,
        'Content-Length': Buffer.byteLength(body),
      },
    },
    (res) => {
      let data = '';
      res.on('data', (chunk) => (data += chunk));
      res.on('end', () => {
        if (res.statusCode === 200) {
          console.log('[railway] STORED_TOKENS env var auto-updated');
        } else {
          console.error('[railway] Failed to update env var:', res.statusCode, data);
        }
      });
    }
  );
  req.on('error', (e) => console.error('[railway] API error:', e.message));
  req.write(body);
  req.end();
}

function exportTokensBase64() {
  return Buffer.from(JSON.stringify(loadTokens())).toString('base64');
}

function storageStatus() {
  const stat = (file) => {
    try {
      if (!fs.existsSync(file)) return { exists: false };
      const data = JSON.parse(fs.readFileSync(file, 'utf-8'));
      return { exists: true, channels: Object.keys(data).length, bytes: fs.statSync(file).size };
    } catch (err) {
      return { exists: true, error: err.message };
    }
  };
  return {
    primary: TOKENS_FILE,
    onVolume: config.ON_VOLUME,
    volumeFile: stat(VOLUME_TOKENS_FILE),
    localFile: stat(LOCAL_TOKENS_FILE),
    storedTokensEnv: process.env.STORED_TOKENS
      ? { present: true, bytes: process.env.STORED_TOKENS.length }
      : { present: false },
    railwayBackupConfigured: Boolean(
      config.RAILWAY_API_TOKEN && config.RAILWAY_SERVICE_ID && config.RAILWAY_ENVIRONMENT_ID
    ),
  };
}

module.exports = {
  TOKENS_FILE,
  channelHealth,
  loadTokens,
  saveTokens,
  updateRailwayEnvVar,
  exportTokensBase64,
  storageStatus,
};
