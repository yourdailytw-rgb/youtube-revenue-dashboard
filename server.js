require('dotenv').config();
const express = require('express');
const { google } = require('googleapis');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const PORT = process.env.PORT || 3000;
const TOKENS_FILE = path.join(__dirname, 'tokens.json');
const SCOPES = [
  'https://www.googleapis.com/auth/yt-analytics.readonly',
  'https://www.googleapis.com/auth/yt-analytics-monetary.readonly',
  'https://www.googleapis.com/auth/youtube.readonly',
];

// ---------------------------------------------------------------------------
// Helpers â token persistence
// ---------------------------------------------------------------------------

function loadTokens() {
  if (fs.existsSync(TOKENS_FILE)) {
    return JSON.parse(fs.readFileSync(TOKENS_FILE, 'utf-8'));
  }
  return {};
}

function saveTokens(data) {
  fs.writeFileSync(TOKENS_FILE, JSON.stringify(data, null, 2));
}

// ---------------------------------------------------------------------------
// Password protection middleware
// ---------------------------------------------------------------------------

const DASHBOARD_PASSWORD = process.env.DASHBOARD_PASSWORD;

// Simple session store (in-memory; resets on restart, which is fine)
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
  if (!DASHBOARD_PASSWORD) return true; // no password set = open access
  const cookies = parseCookies(req.headers.cookie);
  const sid = cookies['dashboard_session'];
  return sid && sessions.has(sid);
}

// Login page HTML
function loginPageHTML(error) {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Login â YouTube Revenue Dashboard</title>
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
    <div class="logo">ð</div>
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

// Login routes
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

// Auth-guard middleware (skip /auth and /oauth2callback so OAuth still works)
app.use((req, res, next) => {
  if (!DASHBOARD_PASSWORD) return next(); // no password = skip guard
  const openPaths = ['/login', '/auth', '/oauth2callback'];
  if (openPaths.some((p) => req.path.startsWith(p))) return next();
  if (isAuthenticated(req)) return next();
  res.redirect('/login');
});

// Serve static files AFTER auth guard
app.use(express.static(path.join(__dirname, 'public')));

// ---------------------------------------------------------------------------
// OAuth2 client factory
// ---------------------------------------------------------------------------

function getRedirectUri() {
  // In production (Railway), use the RAILWAY_PUBLIC_DOMAIN if available
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
// Routes â OAuth flow
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
    allTokens[channelId] = { tokens, channelTitle, channelThumbnail };
    saveTokens(allTokens);

    res.redirect('/?connected=' + encodeURIComponent(channelTitle));
  } catch (err) {
    console.error('OAuth callback error:', err.message);
    if (err.response) console.error('Error details:', JSON.stringify(err.response.data));
    res.status(500).send('Authentication failed: ' + err.message);
  }
});

// ---------------------------------------------------------------------------
// Routes â API
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

app.get('/api/revenue', async (req, res) => {
  const startDate = req.query.startDate || '2024-01-01';
  const endDate = req.query.endDate || new Date().toISOString().slice(0, 10);
  const allTokens = loadTokens();

  if (Object.keys(allTokens).length === 0) {
    return res.json({ channels: [], totals: [] });
  }

  const results = [];

  for (const [channelId, data] of Object.entries(allTokens)) {
    const oauth2Client = makeOAuth2Client();
    oauth2Client.setCredentials(data.tokens);

    oauth2Client.on('tokens', (newTokens) => {
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

      const report = await ytAnalytics.reports.query({
        ids: `channel==${channelId}`,
        startDate,
        endDate,
        metrics: 'estimatedRevenue',
        dimensions: 'day',
        sort: 'day',
        currency: 'SEK',
      });

      const rows = (report.data.rows || []).map((r) => ({
        date: r[0],
        revenue: r[1],
      }));

      results.push({
        channelId,
        channelTitle: data.channelTitle,
        channelThumbnail: data.channelThumbnail,
        data: rows,
      });
    } catch (err) {
      console.error(`Error fetching revenue for ${data.channelTitle}:`, err.message);
      if (err.response) console.error('Revenue error details:', err.response.status, JSON.stringify(err.response.data));
      console.error('Token scopes:', data.tokens.scope);
      results.push({
        channelId,
        channelTitle: data.channelTitle,
        channelThumbnail: data.channelThumbnail,
        data: [],
        error: err.message,
      });
    }
  }

  const dayMap = {};
  for (const ch of results) {
    for (const row of ch.data) {
      dayMap[row.date] = (dayMap[row.date] || 0) + row.revenue;
    }
  }
  const totals = Object.entries(dayMap)
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([date, revenue]) => ({ date, revenue }));

  res.json({ channels: results, totals });
});

// ---------------------------------------------------------------------------
// Start
// ---------------------------------------------------------------------------

app.listen(PORT, () => {
  const domain = process.env.RAILWAY_PUBLIC_DOMAIN;
  const baseUrl = domain ? `https://${domain}` : `http://localhost:${PORT}`;
  console.log(`\n  YouTube Revenue Dashboard running at ${baseUrl}\n`);
  console.log(`  To connect a channel, visit: ${baseUrl}/auth\n`);
  if (DASHBOARD_PASSWORD) {
    console.log(`  Dashboard is password-protected.\n`);
  }
});
