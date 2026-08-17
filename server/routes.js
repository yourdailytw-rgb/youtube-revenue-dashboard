/**
 * HTTP routes. Everything the SPA needs, plus the OAuth flow (unchanged from
 * v1 so existing channel connections keep working).
 */

const express = require('express');
const config = require('./config');
const db = require('./db');
const auth = require('./auth');
const tokens = require('./tokens');
const oauth = require('./oauth');
const youtube = require('./youtube');
const analytics = require('./analytics');
const livecounts = require('./livecounts');
const sync = require('./sync');
const { estimateChannel } = require('./estimator');
const { today, addDays, isValidISO, diffDays } = require('./util/dates');

const router = express.Router();

// ---------------------------------------------------------------------------
// Login / logout
// ---------------------------------------------------------------------------

router.get('/login', (req, res) => {
  if (auth.currentUser(req)) return res.redirect('/');
  res.send(auth.loginPageHTML({ next: auth.safeNext(req.query.next) }));
});

router.post('/login', (req, res) => {
  const { username, password, next } = req.body || {};
  const resolved = auth.verifyCredentials(username, password);
  if (!resolved) {
    return res.status(401).send(auth.loginPageHTML({ error: true, next: auth.safeNext(next) }));
  }
  const sid = auth.createSession(resolved, req.headers['user-agent']);
  res.setHeader('Set-Cookie', auth.sessionCookie(sid));
  res.redirect(auth.safeNext(next));
});

router.get('/logout', (req, res) => {
  const cookies = auth.parseCookies(req.headers.cookie);
  auth.destroySession(cookies.dashboard_session);
  res.setHeader('Set-Cookie', 'dashboard_session=; Path=/; Max-Age=0');
  res.redirect('/login');
});

router.get('/healthz', (req, res) => res.json({ ok: true, uptime: process.uptime() }));

// ---------------------------------------------------------------------------
// OAuth — connect a channel
// ---------------------------------------------------------------------------

router.get('/auth', (req, res) => {
  if (!config.CLIENT_ID || !config.CLIENT_SECRET) {
    return res.status(500).send('CLIENT_ID / CLIENT_SECRET are not configured on the server.');
  }
  // Derived from this request, so connecting through a tunnel or a custom
  // domain sends the user back to the host they are actually using.
  console.log(`[oauth] Starting flow with redirect_uri: ${oauth.getRedirectUri(req)}`);
  res.redirect(oauth.generateAuthUrl(req));
});

router.get('/oauth2callback', async (req, res) => {
  const { code } = req.query;
  if (!code) return res.status(400).send('Missing authorization code');

  try {
    // Must be built from the same request host as /auth used, otherwise Google
    // rejects the exchange with redirect_uri_mismatch.
    const client = oauth.makeOAuth2Client(req);
    const { tokens: newTokens } = await client.getToken(code);
    client.setCredentials(newTokens);

    const channel = await youtube.fetchMyChannel(client);

    const allTokens = tokens.loadTokens();
    const existing = allTokens[channel.id];
    allTokens[channel.id] = {
      // Preserve an existing refresh_token if Google omits one this time.
      tokens: { ...(existing?.tokens || {}), ...newTokens },
      channelTitle: channel.title,
      channelThumbnail: channel.thumbnail,
      connectedAt: existing?.connectedAt || new Date().toISOString(),
    };
    tokens.saveTokens(allTokens);
    tokens.channelHealth[channel.id] = {
      status: 'ok',
      error: null,
      lastChecked: new Date().toISOString(),
    };

    db.upsertChannel({
      id: channel.id,
      title: channel.title,
      thumbnail: channel.thumbnail,
      connectedAt: allTokens[channel.id].connectedAt,
    });

    // Pull this channel's history in the background so it appears with data.
    sync
      .syncChannel(channel.id, allTokens[channel.id], { full: true })
      .then(() => sync.recomputeChannelEstimates(channel.id))
      .catch((err) => console.error('[oauth] Initial sync failed:', err.message));

    res.redirect(`/?connected=${encodeURIComponent(channel.title)}`);
  } catch (err) {
    console.error('OAuth callback error:', err.message);
    res.status(500).send(`Authentication failed: ${err.message}`);
  }
});

// ---------------------------------------------------------------------------
// API
// ---------------------------------------------------------------------------

const api = express.Router();

api.get('/me', (req, res) => {
  const user = auth.currentUser(req);
  res.json({ user, authRequired: auth.AUTH_REQUIRED, currency: config.CURRENCY });
});

api.get('/channels', (req, res) => {
  const stored = tokens.loadTokens();
  const rows = db.listChannels();
  const known = new Map(rows.map((r) => [r.id, r]));

  const channels = Object.entries(stored).map(([id, data]) => {
    const row = known.get(id);
    return {
      id,
      title: row?.custom_name || data.channelTitle,
      originalTitle: data.channelTitle,
      thumbnail: data.channelThumbnail,
      connectedAt: data.connectedAt,
      group: row?.group_name || null,
      sortOrder: row?.sort_order ?? 0,
      hidden: Boolean(row?.hidden),
      health: tokens.channelHealth[id] || null,
      lastSync: db.getState(`lastSync:${id}`) || null,
    };
  });

  channels.sort((a, b) => a.sortOrder - b.sortOrder || a.title.localeCompare(b.title));
  res.json(channels);
});

api.patch('/channels/:id', (req, res) => {
  const { customName, groupName, sortOrder, hidden } = req.body || {};
  const updated = db.updateChannel(req.params.id, { customName, groupName, sortOrder, hidden });
  if (!updated) return res.status(404).json({ error: 'Channel not found' });
  res.json({ ok: true, channel: updated });
});

api.delete('/channels/:id', (req, res) => {
  const allTokens = tokens.loadTokens();
  if (!allTokens[req.params.id]) return res.status(404).json({ error: 'Channel not connected' });
  delete allTokens[req.params.id];
  tokens.saveTokens(allTokens);
  if (req.query.purge === 'true') db.deleteChannel(req.params.id);
  res.json({ ok: true });
});

/** Shared query parsing for the analytics endpoints. */
function parseRange(req) {
  const end = isValidISO(req.query.end) ? req.query.end : today();
  const start = isValidISO(req.query.start) ? req.query.start : addDays(end, -29);
  if (start > end) return { error: 'start must be on or before end' };

  const connected = Object.keys(tokens.loadTokens());
  const requested = req.query.channels
    ? String(req.query.channels)
        .split(',')
        .map((s) => s.trim())
        .filter(Boolean)
    : null;
  const channelIds = requested ? requested.filter((id) => connected.includes(id)) : connected;

  return { start, end, channelIds, allChannelIds: connected };
}

api.get('/analytics', (req, res) => {
  const range = parseRange(req);
  if (range.error) return res.status(400).json({ error: range.error });
  const { start, end, channelIds } = range;

  const compareMode = ['previous', 'year', 'none'].includes(req.query.compare)
    ? req.query.compare
    : 'previous';

  const channels = db.listChannels().filter((c) => channelIds.includes(c.id));
  const series = analytics.buildSeries({ channelIds, start, end });
  const summary = analytics.summarize(series.totals);

  let comparison = null;
  let previousSeries = null;
  if (compareMode !== 'none' && channelIds.length) {
    const prevRange =
      compareMode === 'year'
        ? analytics.previousYearPeriod(start, end)
        : analytics.previousPeriod(start, end);
    previousSeries = analytics.buildSeries({ channelIds, start: prevRange.start, end: prevRange.end });
    const prevSummary = analytics.summarize(previousSeries.totals);
    comparison = {
      mode: compareMode,
      range: prevRange,
      summary: prevSummary,
      totals: previousSeries.totals,
      deltas: analytics.computeDeltas(summary, prevSummary),
    };
  }

  // The month grid and the forecast need the whole history, not just the
  // selected range — year-over-year is meaningless otherwise. This reads from
  // local SQLite so the extra span costs almost nothing.
  const bounds = db.dataBounds();
  const wideStart = bounds?.min || addDays(start, -365);
  const wide = analytics.buildSeries({ channelIds, start: wideStart, end: maxDate(end, today()) });

  res.json({
    range: { start, end, days: diffDays(start, end) + 1 },
    dataRange: bounds,
    currency: config.CURRENCY,
    channels: channels.map((c) => ({
      id: c.id,
      title: c.custom_name || c.title,
      thumbnail: c.thumbnail,
      group: c.group_name,
    })),
    series,
    summary,
    comparison,
    breakdown: analytics.channelBreakdown({ channels, series, previousSeries }),
    monthly: analytics.monthlyBreakdown(wide.totals),
    // Rolling averages are computed over the full history and then cropped to
    // the visible range, so a 28-day average at the start of the range is a
    // real 28-day average rather than a one-day one.
    rolling: {
      revenue7: cropSeries(analytics.rollingAverage(wide.totals, 'effectiveRevenue', 7), start, end),
      revenue28: cropSeries(analytics.rollingAverage(wide.totals, 'effectiveRevenue', 28), start, end),
      views7: cropSeries(analytics.rollingAverage(wide.totals, 'views', 7), start, end),
    },
    forecast: analytics.forecast(wide.totals),
    estimation: analytics.estimationMeta(channelIds),
    sync: { lastRun: db.getState('lastSync'), running: sync.isRunning() },
  });
});

function maxDate(a, b) {
  return a > b ? a : b;
}

function cropSeries(rows, start, end) {
  return rows.filter((r) => r.date >= start && r.date <= end);
}

/** Detailed estimator diagnostics for one channel (or all). */
api.get('/estimates', (req, res) => {
  const connected = tokens.loadTokens();
  const ids = req.query.channel ? [req.query.channel] : Object.keys(connected);
  const out = {};
  for (const id of ids) {
    if (!connected[id]) continue;
    const reported = db.getChannelDaily(id, addDays(today(), -220), today());
    if (!reported.length) continue;
    // Same merge the sync uses, so this view matches what the dashboard shows.
    const history = livecounts.mergeLiveIntoHistory(id, reported);
    const result = estimateChannel(history);
    out[id] = {
      channelTitle: connected[id].channelTitle,
      ...result,
    };
  }
  res.json(out);
});

api.get('/videos', async (req, res) => {
  const range = parseRange(req);
  if (range.error) return res.status(400).json({ error: range.error });
  const { start, end, channelIds } = range;
  const limit = Math.min(50, Math.max(5, Number(req.query.limit) || 25));

  const cacheKey = `videos:${channelIds.join('|')}:${start}:${end}:${limit}`;
  const cached = db.getCache(cacheKey, 60 * 60 * 1000);
  if (cached) return res.json({ ...cached, cached: true });

  const allTokens = tokens.loadTokens();
  const collected = [];
  const errors = [];

  for (const channelId of channelIds) {
    const tokenData = allTokens[channelId];
    if (!tokenData) continue;
    try {
      const client = oauth.clientForChannel(channelId, tokenData);
      const videos = await youtube.fetchTopVideos({ auth: client, channelId, start, end, limit });
      const ids = videos.map((v) => v.videoId);

      const known = new Map(db.getVideos(ids).map((v) => [v.video_id, v]));
      const missing = ids.filter((id) => !known.has(id));
      if (missing.length) {
        const details = await youtube.fetchVideoDetails({ auth: client, videoIds: missing });
        for (const detail of details) {
          db.upsertVideo(detail);
          known.set(detail.videoId, {
            video_id: detail.videoId,
            title: detail.title,
            thumbnail: detail.thumbnail,
            published_at: detail.publishedAt,
            duration_sec: detail.durationSec,
            is_short: detail.isShort ? 1 : 0,
          });
        }
      }

      for (const video of videos) {
        const meta = known.get(video.videoId);
        collected.push({
          ...video,
          channelId,
          channelTitle: tokenData.channelTitle,
          title: meta?.title || video.videoId,
          thumbnail: meta?.thumbnail || null,
          publishedAt: meta?.published_at || null,
          durationSec: meta?.duration_sec ?? null,
          isShort: Boolean(meta?.is_short),
          rpm: video.views > 0 && video.revenue != null ? (video.revenue / video.views) * 1000 : null,
        });
      }
    } catch (err) {
      errors.push({ channelId, message: err.message });
    }
  }

  collected.sort((a, b) => (b.revenue ?? 0) - (a.revenue ?? 0) || b.views - a.views);
  const payload = { range: { start, end }, videos: collected.slice(0, limit * 2), errors };
  db.setCache(cacheKey, payload);
  res.json(payload);
});

api.get('/export', (req, res) => {
  const range = parseRange(req);
  if (range.error) return res.status(400).json({ error: range.error });
  const { start, end, channelIds } = range;
  const scope = req.query.scope === 'channel' ? 'channel' : 'total';

  const series = analytics.buildSeries({ channelIds, start, end });
  const channels = new Map(db.listChannels().map((c) => [c.id, c.custom_name || c.title]));

  const header = [
    'date',
    'channel',
    'revenue_reported',
    'revenue_estimated',
    'revenue_effective',
    'is_estimated',
    'views',
    'longform_views',
    'shortform_views',
    'watch_hours',
    'subs_gained',
    'subs_lost',
    'rpm',
    'cpm',
  ];

  const lines = [header.join(',')];
  const pushRow = (name, day) => {
    lines.push(
      [
        day.date,
        csvEscape(name),
        fixed(day.revenue),
        fixed(day.estimatedRevenue),
        fixed(day.effectiveRevenue),
        day.isEstimated ? 'yes' : 'no',
        day.views,
        day.lf_views,
        day.sf_views,
        fixed(day.watch_hours),
        day.subs_gained,
        day.subs_lost,
        fixed(day.rpm),
        fixed(day.cpm),
      ].join(',')
    );
  };

  if (scope === 'channel') {
    for (const [id, days] of Object.entries(series.byChannel)) {
      for (const day of days) pushRow(channels.get(id) || id, day);
    }
  } else {
    for (const day of series.totals) pushRow('All channels', day);
  }

  res.setHeader('Content-Type', 'text/csv; charset=utf-8');
  res.setHeader('Content-Disposition', `attachment; filename="youtube-${scope}-${start}_${end}.csv"`);
  res.send(lines.join('\n'));
});

const fixed = (v) => (typeof v === 'number' && Number.isFinite(v) ? v.toFixed(2) : '');
const csvEscape = (v) => (/[",\n]/.test(String(v)) ? `"${String(v).replace(/"/g, '""')}"` : String(v));

// --- Sync + diagnostics ----------------------------------------------------

api.get('/sync/status', (req, res) => res.json(sync.syncStatus()));

/** Live view-count feed: snapshots taken, days derived, and how well they held up. */
api.get('/live-status', (req, res) => res.json(livecounts.liveStatus()));

api.post('/live-poll', async (req, res) => {
  try {
    const result = await livecounts.refreshLiveCounts();
    sync.recomputeAllEstimates();
    res.json(result);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

api.post('/sync', async (req, res) => {
  const full = req.query.full === 'true' || req.body?.full === true;
  if (sync.isRunning()) return res.status(409).json({ error: 'A sync is already running' });
  res.json({ started: true, full });
  sync.syncAll({ full }).catch((err) => console.error('[sync] Manual run failed:', err.message));
});

api.get('/token-health', (req, res) => {
  const allTokens = tokens.loadTokens();
  res.json(
    Object.entries(allTokens).map(([id, data]) => ({
      channelId: id,
      channelTitle: data.channelTitle,
      connectedAt: data.connectedAt,
      hasRefreshToken: Boolean(data.tokens?.refresh_token),
      expiryDate: data.tokens?.expiry_date || null,
      ...(tokens.channelHealth[id] || { status: 'unknown' }),
    }))
  );
});

api.post('/token-refresh', async (req, res) => {
  const result = await oauth.refreshAllTokens();
  res.json(result);
});

api.get('/admin/storage-status', (req, res) => {
  res.json({ tokens: tokenStorageStatus(), db: db.stats(), dataDir: config.DATA_DIR });
});

function tokenStorageStatus() {
  return tokens.storageStatus();
}

api.get('/admin/export-tokens', (req, res) => {
  res.json({ stored_tokens: tokens.exportTokensBase64() });
});

router.use('/api', api);

module.exports = router;
