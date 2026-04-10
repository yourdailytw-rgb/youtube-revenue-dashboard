require('dotenv').config();
const express = require('express');
const { google } = require('googleapis');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const https = require('https');

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const PORT = process.env.PORT || 3000;
const SCOPES = [
  'https://www.googleapis.com/auth/yt-analytics.readonly',
  'https://www.googleapis.com/auth/yt-analytics-monetary.readonly',
  'https://www.googleapis.com/auth/youtube.readonly',
];

// ---------------------------------------------------------------------------
// Token persistence (Railway Volume > local file > env var)
// ---------------------------------------------------------------------------

// Railway Volume path (survives deploys). Mount a volume at /data in Railway.
const VOLUME_TOKENS_FILE = '/data/tokens.json';
const LOCAL_TOKENS_FILE = path.join(__dirname, 'tokens.json');

function getTokensFilePath() {
  try {
    if (fs.existsSync('/data') && fs.statSync('/data').isDirectory()) {
      console.log('[tokens] Railway Volume detected at /data -- using persistent storage');
      return VOLUME_TOKENS_FILE;
    }
  } catch (e) { /* /data not available */ }
  console.warn('[tokens] No Railway Volume at /data -- tokens WILL BE LOST on deploy!');
  return LOCAL_TOKENS_FILE;
}

const TOKENS_FILE = getTokensFilePath();

function loadTokens() {
  // 1. Primary file (volume or local)
  if (fs.existsSync(TOKENS_FILE)) {
    try {
      const data = JSON.parse(fs.readFileSync(TOKENS_FILE, 'utf-8'));
      if (Object.keys(data).length > 0) return data;
    } catch (e) {
      console.error('[tokens] Failed to read ' + TOKENS_FILE + ':', e.message);
    }
  }

  // 2. Fallback to the other file location
  const fallbackFile = TOKENS_FILE === VOLUME_TOKENS_FILE ? LOCAL_TOKENS_FILE : VOLUME_TOKENS_FILE;
  if (fs.existsSync(fallbackFile)) {
    try {
      const data = JSON.parse(fs.readFileSync(fallbackFile, 'utf-8'));
      if (Object.keys(data).length > 0) {
        console.log('[tokens] Restored from fallback: ' + fallbackFile);
        fs.writeFileSync(TOKENS_FILE, JSON.stringify(data, null, 2));
        return data;
      }
    } catch (e) { /* not available */ }
  }

  // 3. STORED_TOKENS env var (last resort)
  if (process.env.STORED_TOKENS) {
    try {
      const data = JSON.parse(Buffer.from(process.env.STORED_TOKENS, 'base64').toString('utf-8'));
      if (Object.keys(data).length > 0) {
        fs.writeFileSync(TOKENS_FILE, JSON.stringify(data, null, 2));
        console.log('[tokens] Restored from STORED_TOKENS env var');
        return data;
      }
    } catch (e) {
      console.error('[tokens] Failed to parse STORED_TOKENS:', e.message);
    }
  }

  console.warn('[tokens] WARNING: No tokens found anywhere');
  return {};
}

// Track channel token health
const channelHealth = {};

function saveTokens(data) {
  // Write to primary location
  fs.writeFileSync(TOKENS_FILE, JSON.stringify(data, null, 2));

  // Also write to secondary location for redundancy
  const secondaryFile = TOKENS_FILE === VOLUME_TOKENS_FILE ? LOCAL_TOKENS_FILE : VOLUME_TOKENS_FILE;
  try { fs.writeFileSync(secondaryFile, JSON.stringify(data, null, 2)); } catch (e) { /* ok */ }

  // Base64 backup to env var
  const encoded = Buffer.from(JSON.stringify(data)).toString('base64');
  console.log('TOKENS_BACKUP_BASE64:', encoded);
  updateRailwayEnvVar(encoded);
}

// ---------------------------------------------------------------------------
// Railway API -- auto-update STORED_TOKENS env var
// ---------------------------------------------------------------------------

function updateRailwayEnvVar(base64Tokens) {
  const railwayToken = process.env.RAILWAY_API_TOKEN;
  const serviceId = process.env.RAILWAY_SERVICE_ID;
  const envId = process.env.RAILWAY_ENVIRONMENT_ID;
  if (!railwayToken || !serviceId || !envId) return;

  const query = `mutation($input: VariableCollectionUpsertInput!) {
    variableCollectionUpsert(input: $input)
  }`;
  const variables = {
    input: {
      serviceId,
      environmentId: envId,
      variables: { STORED_TOKENS: base64Tokens },
    },
  };
  const body = JSON.stringify({ query, variables });

  const req = https.request({
    hostname: 'backboard.railway.app',
    path: '/graphql/v2',
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${railwayToken}`,
      'Content-Length': Buffer.byteLength(body),
    },
  }, (res) => {
    let data = '';
    res.on('data', (chunk) => (data += chunk));
    res.on('end', () => {
      if (res.statusCode === 200) {
        console.log('[railway] STORED_TOKENS env var auto-updated');
      } else {
        console.error('[railway] Failed to update env var:', res.statusCode, data);
      }
    });
  });
  req.on('error', (e) => console.error('[railway] API error:', e.message));
  req.write(body);
  req.end();
}

// ---------------------------------------------------------------------------
// Proactive token refresh -- refresh ALL tokens on startup + every 6 hours
// ---------------------------------------------------------------------------

async function refreshAllTokens() {
  const allTokens = loadTokens();
  if (Object.keys(allTokens).length === 0) {
    console.log('[refresh] No channels to refresh');
    return;
  }

  let refreshed = 0;
  let failed = 0;

  for (const [channelId, data] of Object.entries(allTokens)) {
    if (!data.tokens || !data.tokens.refresh_token) {
      console.warn('[refresh] ' + data.channelTitle + ': no refresh_token, skipping');
      channelHealth[channelId] = { status: 'expired', error: 'No refresh token', lastChecked: new Date().toISOString() };
      failed++;
      continue;
    }

    const oauth2Client = makeOAuth2Client();
    oauth2Client.setCredentials(data.tokens);

    try {
      // Force a token refresh by requesting new credentials
      const { credentials } = await oauth2Client.refreshAccessToken();
      allTokens[channelId].tokens = { ...data.tokens, ...credentials };
      channelHealth[channelId] = { status: 'ok', error: null, lastChecked: new Date().toISOString() };
      console.log('[refresh] ' + data.channelTitle + ': OK (new expiry: ' + new Date(credentials.expiry_date).toISOString() + ')');
      refreshed++;
    } catch (err) {
      const isExpired = err.message.includes('invalid_grant') || err.message.includes('expired') || err.message.includes('revoked');
      channelHealth[channelId] = {
        status: isExpired ? 'expired' : 'error',
        error: err.message,
        lastChecked: new Date().toISOString(),
      };
      console.error('[refresh] ' + data.channelTitle + ': FAILED - ' + err.message);
      failed++;
    }
  }

  // Save updated tokens (with new access tokens)
  if (refreshed > 0) {
    saveTokens(allTokens);
  }

  console.log('[refresh] Done: ' + refreshed + ' refreshed, ' + failed + ' failed out of ' + Object.keys(allTokens).length + ' channels');
}

// ---------------------------------------------------------------------------
// Password protection middleware
// ---------------------------------------------------------------------------

const DASHBOARD_PASSWORD = process.env.DASHBOARD_PASSWORD;

const sessions = new Map();

function generateSessionId() {
  return crypto.randomBytes(32).toString('hex');
}

function parseCookies(cookieHeader) {
  const cookies = {};
  if (!cookieHeader) return cookies;
  cookieHeader.split(';').forEach((c) => {
    const [key, ...rest] = c.trim().split('=');
    if (key) cookies[key] = rest.join('=');
  });
  return cookies;
}

function isAuthenticated(req) {
  if (!DASHBOARD_PASSWORD) return true;
  const cookies = parseCookies(req.headers.cookie);
  const sid = cookies['dashboard_session'];
  return sid && sessions.has(sid);
}

function loginPageHTML(error) {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Login - YouTube Revenue Dashboard</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      background: #0f0f0f;
      color: #f1f1f1;
      display: flex;
      align-items: center;
      justify-content: center;
      min-height: 100vh;
    }
    .login-card {
      background: #1a1a1a;
      border: 1px solid #333;
      border-radius: 12px;
      padding: 40px;
      width: 100%;
      max-width: 400px;
      text-align: center;
    }
    .login-card h1 {
      font-size: 1.5rem;
      margin-bottom: 8px;
    }
    .login-card p {
      color: #aaa;
      margin-bottom: 24px;
      font-size: 0.9rem;
    }
    .login-card input[type="password"] {
      width: 100%;
      padding: 12px 16px;
      background: #0f0f0f;
      border: 1px solid #444;
      border-radius: 8px;
      color: #f1f1f1;
      font-size: 1rem;
      margin-bottom: 16px;
      outline: none;
    }
    .login-card input[type="password"]:focus {
      border-color: #ff4444;
    }
    .login-card button {
      width: 100%;
      padding: 12px;
      background: #ff4444;
      border: none;
      border-radius: 8px;
      color: #fff;
      font-size: 1rem;
      font-weight: 600;
      cursor: pointer;
      transition: background 0.2s;
    }
    .login-card button:hover { background: #cc0000; }
    .error { color: #ff4444; margin-bottom: 16px; font-size: 0.85rem; }
    .logo { font-size: 2rem; margin-bottom: 16px; }
  </style>
</head>
<body>
  <div class="login-card">
    <div class="logo">&#128202;</div>
    <h1>YouTube Revenue Dashboard</h1>
    <p>Enter the password to access the dashboard</p>
    ${error ? '<div class="error">Incorrect password. Try again.</div>' : ''}
    <form method="POST" action="/login">
      <input type="password" name="password" placeholder="Password" autofocus required />
      <button type="submit">Sign In</button>
    </form>
  </div>
</body>
</html>`;
}

app.get('/login', (req, res) => {
  if (isAuthenticated(req)) return res.redirect('/');
  res.send(loginPageHTML(false));
});

app.post('/login', (req, res) => {
  const { password } = req.body;
  if (password === DASHBOARD_PASSWORD) {
    const sid = generateSessionId();
    sessions.set(sid, { created: Date.now() });
    res.setHeader(
      'Set-Cookie',
      `dashboard_session=${sid}; Path=/; HttpOnly; SameSite=Lax; Max-Age=604800`
    );
    return res.redirect('/');
  }
  res.send(loginPageHTML(true));
});

app.get('/logout', (req, res) => {
  const cookies = parseCookies(req.headers.cookie);
  const sid = cookies['dashboard_session'];
  if (sid) sessions.delete(sid);
  res.setHeader('Set-Cookie', 'dashboard_session=; Path=/; Max-Age=0');
  res.redirect('/login');
});

app.use((req, res, next) => {
  if (!DASHBOARD_PASSWORD) return next();
  const openPaths = ['/login', '/auth', '/oauth2callback'];
  if (openPaths.some((p) => req.path.startsWith(p))) return next();
  if (isAuthenticated(req)) return next();
  res.redirect('/login');
});

app.use(express.static(path.join(__dirname, 'public')));

// ---------------------------------------------------------------------------
// OAuth2 client factory
// ---------------------------------------------------------------------------

function getRedirectUri() {
  if (process.env.RAILWAY_PUBLIC_DOMAIN) {
    return `https://${process.env.RAILWAY_PUBLIC_DOMAIN}/oauth2callback`;
  }
  return process.env.REDIRECT_URI || `http://localhost:${PORT}/oauth2callback`;
}

function makeOAuth2Client() {
  return new google.auth.OAuth2(
    process.env.CLIENT_ID,
    process.env.CLIENT_SECRET,
    getRedirectUri()
  );
}

// ---------------------------------------------------------------------------
// Routes -- OAuth flow
// ---------------------------------------------------------------------------

app.get('/auth', (req, res) => {
  const oauth2Client = makeOAuth2Client();
  const url = oauth2Client.generateAuthUrl({
    access_type: 'offline',
    prompt: 'consent',
    scope: SCOPES,
  });
  res.redirect(url);
});

app.get('/oauth2callback', async (req, res) => {
  const { code } = req.query;
  if (!code) return res.status(400).send('Missing authorization code');

  try {
    const oauth2Client = makeOAuth2Client();
    const { tokens } = await oauth2Client.getToken(code);
    console.log('Token scopes granted:', tokens.scope);
    console.log('Has refresh_token:', !!tokens.refresh_token);
    oauth2Client.setCredentials(tokens);

    const youtube = google.youtube({ version: 'v3', auth: oauth2Client });
    const channelRes = await youtube.channels.list({
      part: 'snippet',
      mine: true,
    });
    const channel = channelRes.data.items[0];
    const channelId = channel.id;
    const channelTitle = channel.snippet.title;
    const channelThumbnail = channel.snippet.thumbnails.default.url;

    console.log(`Channel connected: ${channelTitle} (${channelId})`);

    const allTokens = loadTokens();
    allTokens[channelId] = { tokens, channelTitle, channelThumbnail, connectedAt: new Date().toISOString() };
    saveTokens(allTokens);

    channelHealth[channelId] = { status: 'ok', error: null, lastChecked: new Date().toISOString() };

    res.redirect('/?connected=' + encodeURIComponent(channelTitle));
  } catch (err) {
    console.error('OAuth callback error:', err.message);
    if (err.response) console.error('Error details:', JSON.stringify(err.response.data));
    res.status(500).send('Authentication failed: ' + err.message);
  }
});

// ---------------------------------------------------------------------------
// Routes -- API
// ---------------------------------------------------------------------------

app.get('/api/channels', (req, res) => {
  const allTokens = loadTokens();
  const channels = Object.entries(allTokens).map(([id, data]) => ({
    id,
    title: data.channelTitle,
    thumbnail: data.channelThumbnail,
  }));
  res.json(channels);
});

app.delete('/api/channels/:id', (req, res) => {
  const allTokens = loadTokens();
  delete allTokens[req.params.id];
  saveTokens(allTokens);
  res.json({ ok: true });
});

// ---------------------------------------------------------------------------
// Shared helper -- fetches analytics for all channels
// ---------------------------------------------------------------------------

async function fetchAnalyticsForAllChannels({ startDate, endDate, metrics, dimensions, sort, currency, filters, contentTypeFilter }) {
  const allTokens = loadTokens();

  if (Object.keys(allTokens).length === 0) {
    return { channels: [], totals: [] };
  }

  const results = [];
  const valueKey = metrics === 'estimatedRevenue' ? 'revenue' : 'views';

  for (const [channelId, data] of Object.entries(allTokens)) {
    const oauth2Client = makeOAuth2Client();
    oauth2Client.setCredentials(data.tokens);

    oauth2Client.on('tokens', (newTokens) => {
      console.log('[auto-refresh] New tokens received for ' + data.channelTitle);
      const all = loadTokens();
      if (all[channelId]) {
        all[channelId].tokens = { ...all[channelId].tokens, ...newTokens };
        saveTokens(all);
      }
    });

    try {
      const ytAnalytics = google.youtubeAnalytics({
        version: 'v2',
        auth: oauth2Client,
      });

      const queryParams = {
        ids: `channel==${channelId}`,
        startDate,
        endDate,
        metrics,
        dimensions: dimensions || 'day',
        sort: sort || 'day',
      };
      if (currency) queryParams.currency = currency;
      if (filters) queryParams.filters = filters;

      const report = await ytAnalytics.reports.query(queryParams);

      let rows;
      if (contentTypeFilter) {
        const dayMap = {};
        for (const r of (report.data.rows || [])) {
          const date = r[0];
          const cType = r[1];
          const val = r[2];
          if (cType === contentTypeFilter) {
            dayMap[date] = (dayMap[date] || 0) + val;
          }
        }
        rows = Object.entries(dayMap)
          .sort(([a], [b]) => a.localeCompare(b))
          .map(([date, val]) => ({ date, [valueKey]: val }));
      } else {
        rows = (report.data.rows || []).map((r) => ({
          date: r[0],
          [valueKey]: r[1],
        }));
      }

      results.push({
        channelId,
        channelTitle: data.channelTitle,
        channelThumbnail: data.channelThumbnail,
        data: rows,
      });
      channelHealth[channelId] = { status: 'ok', error: null, lastChecked: new Date().toISOString() };
    } catch (err) {
      console.error(`Error fetching ${metrics} for ${data.channelTitle}:`, err.message);
      if (err.response) console.error('Error details:', err.response.status, JSON.stringify(err.response.data));

      const isTokenExpired = err.message.includes('invalid_grant') ||
        err.message.includes('Token has been expired') ||
        err.message.includes('Token has been revoked');

      channelHealth[channelId] = {
        status: isTokenExpired ? 'expired' : 'error',
        error: err.message,
        lastChecked: new Date().toISOString(),
      };

      results.push({
        channelId,
        channelTitle: data.channelTitle,
        channelThumbnail: data.channelThumbnail,
        data: [],
        error: err.message,
        tokenExpired: isTokenExpired,
      });
    }
  }

  const dayMap = {};
  for (const ch of results) {
    for (const row of ch.data) {
      dayMap[row.date] = (dayMap[row.date] || 0) + row[valueKey];
    }
  }
  const totals = Object.entries(dayMap)
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([date, value]) => ({ date, [valueKey]: value }));

  return { channels: results, totals };
}

// ---------------------------------------------------------------------------
// Revenue endpoint
// ---------------------------------------------------------------------------

app.get('/api/revenue', async (req, res) => {
  const startDate = req.query.startDate || '2024-01-01';
  const endDate = req.query.endDate || new Date().toISOString().slice(0, 10);

  const result = await fetchAnalyticsForAllChannels({
    startDate,
    endDate,
    metrics: 'estimatedRevenue',
    dimensions: 'day',
    sort: 'day',
    currency: 'SEK',
  });

  res.json(result);
});

// ---------------------------------------------------------------------------
// Long-form views endpoint (VIDEO_ON_DEMAND)
// ---------------------------------------------------------------------------

app.get('/api/views/longform', async (req, res) => {
  const startDate = req.query.startDate || '2024-01-01';
  const endDate = req.query.endDate || new Date().toISOString().slice(0, 10);

  const result = await fetchAnalyticsForAllChannels({
    startDate,
    endDate,
    metrics: 'views',
    dimensions: 'day,creatorContentType',
    sort: 'day',
    contentTypeFilter: 'videoOnDemand',
  });

  res.json(result);
});

// ---------------------------------------------------------------------------
// Short-form views endpoint (SHORTS)
// ---------------------------------------------------------------------------

app.get('/api/views/shortform', async (req, res) => {
  const startDate = req.query.startDate || '2024-01-01';
  const endDate = req.query.endDate || new Date().toISOString().slice(0, 10);

  const result = await fetchAnalyticsForAllChannels({
    startDate,
    endDate,
    metrics: 'views',
    dimensions: 'day,creatorContentType',
    sort: 'day',
    contentTypeFilter: 'shorts',
  });

  res.json(result);
});

// ---------------------------------------------------------------------------
// Token health check endpoint
// ---------------------------------------------------------------------------
app.get('/api/token-health', async (req, res) => {
  const allTokens = loadTokens();
  const results = [];

  for (const [channelId, data] of Object.entries(allTokens)) {
    if (channelHealth[channelId] && channelHealth[channelId].lastChecked) {
      const age = Date.now() - new Date(channelHealth[channelId].lastChecked).getTime();
      if (age < 5 * 60 * 1000) {
        results.push({
          channelId,
          channelTitle: data.channelTitle,
          ...channelHealth[channelId],
        });
        continue;
      }
    }

    const oauth2Client = makeOAuth2Client();
    oauth2Client.setCredentials(data.tokens);
    try {
      const youtube = google.youtube({ version: 'v3', auth: oauth2Client });
      await youtube.channels.list({ part: 'id', mine: true });
      channelHealth[channelId] = { status: 'ok', error: null, lastChecked: new Date().toISOString() };
    } catch (err) {
      const isTokenExpired = err.message.includes('invalid_grant') ||
        err.message.includes('Token has been expired') ||
        err.message.includes('Token has been revoked');
      channelHealth[channelId] = {
        status: isTokenExpired ? 'expired' : 'error',
        error: err.message,
        lastChecked: new Date().toISOString(),
      };
    }
    results.push({
      channelId,
      channelTitle: data.channelTitle,
      ...channelHealth[channelId],
    });
  }

  const expiredCount = results.filter((r) => r.status === 'expired').length;
  res.json({
    channels: results,
    expiredCount,
    totalCount: results.length,
    storagePath: TOKENS_FILE,
    volumeDetected: TOKENS_FILE === VOLUME_TOKENS_FILE,
  });
});

// ---------------------------------------------------------------------------
// Token refresh (every 6 hours) + health check (every 12 hours)
// ---------------------------------------------------------------------------
setInterval(async () => {
  console.log('[scheduled] Proactive token refresh...');
  await refreshAllTokens();
}, 6 * 60 * 60 * 1000);

setInterval(async () => {
  console.log('[scheduled] Token health check...');
  const allTokens = loadTokens();
  for (const [channelId, data] of Object.entries(allTokens)) {
    const oauth2Client = makeOAuth2Client();
    oauth2Client.setCredentials(data.tokens);
    try {
      const youtube = google.youtube({ version: 'v3', auth: oauth2Client });
      await youtube.channels.list({ part: 'id', mine: true });
      channelHealth[channelId] = { status: 'ok', error: null, lastChecked: new Date().toISOString() };
      console.log('  ' + data.channelTitle + ': OK');
    } catch (err) {
      const isExpired = err.message.includes('invalid_grant') || err.message.includes('expired') || err.message.includes('revoked');
      channelHealth[channelId] = { status: isExpired ? 'expired' : 'error', error: err.message, lastChecked: new Date().toISOString() };
      console.warn('  ' + data.channelTitle + ': ' + (isExpired ? 'EXPIRED' : 'ERROR') + ' - ' + err.message);
    }
  }
}, 12 * 60 * 60 * 1000);

// ---------------------------------------------------------------------------
// Admin: export tokens
// ---------------------------------------------------------------------------
app.get('/api/admin/export-tokens', (req, res) => {
  const allTokens = loadTokens();
  const encoded = Buffer.from(JSON.stringify(allTokens)).toString('base64');
  res.json({
    encoded,
    channelCount: Object.keys(allTokens).length,
    storagePath: TOKENS_FILE,
    volumeDetected: TOKENS_FILE === VOLUME_TOKENS_FILE,
  });
});

// ---------------------------------------------------------------------------
// Storage diagnostics endpoint
// ---------------------------------------------------------------------------
app.get('/api/admin/storage-status', (req, res) => {
  const allTokens = loadTokens();
  const channelNames = Object.values(allTokens).map(d => d.channelTitle);
  const hasRailwayApiVars = !!(process.env.RAILWAY_API_TOKEN && process.env.RAILWAY_SERVICE_ID && process.env.RAILWAY_ENVIRONMENT_ID);

  res.json({
    primaryStorage: TOKENS_FILE,
    volumeDetected: TOKENS_FILE === VOLUME_TOKENS_FILE,
    channelCount: Object.keys(allTokens).length,
    channels: channelNames,
    hasStoredTokensEnv: !!process.env.STORED_TOKENS,
    hasRailwayApiVars,
    railwayAutoBackup: hasRailwayApiVars ? 'enabled' : 'DISABLED -- set RAILWAY_API_TOKEN, RAILWAY_SERVICE_ID, RAILWAY_ENVIRONMENT_ID',
    recommendation: TOKENS_FILE === VOLUME_TOKENS_FILE
      ? 'Using Railway Volume -- tokens will survive deploys'
      : hasRailwayApiVars
        ? 'No volume but Railway API backup is enabled'
        : 'WARNING: No volume AND no Railway API backup. Tokens WILL be lost on next deploy. Add a Railway Volume at /data or set Railway API env vars.',
  });
});

// ---------------------------------------------------------------------------
// Start
// ---------------------------------------------------------------------------

app.listen(PORT, async () => {
  const domain = process.env.RAILWAY_PUBLIC_DOMAIN;
  const baseUrl = domain ? `https://${domain}` : `http://localhost:${PORT}`;
  console.log(`\n  YouTube Revenue Dashboard running at ${baseUrl}`);
  console.log(`  Token storage: ${TOKENS_FILE}`);
  console.log(`  To connect a channel, visit: ${baseUrl}/auth\n`);
  if (DASHBOARD_PASSWORD) {
    console.log(`  Dashboard is password-protected.\n`);
  }

  // Proactive token refresh on startup (keeps tokens alive)
  console.log('[startup] Running proactive token refresh...');
  await refreshAllTokens();
});
