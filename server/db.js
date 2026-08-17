/**
 * SQLite metrics store, living on the Railway Volume next to tokens.json.
 *
 * This is a CACHE of what the YouTube Analytics API returns — never a source of
 * truth. It exists so that:
 *   - the dashboard renders instantly instead of waiting on 5 channels × N API calls
 *   - period-vs-period and year-over-year comparisons are cheap
 *   - the revenue estimator has the daily history it needs to learn each
 *     channel's RPM behaviour
 *
 * Uses node:sqlite (built into Node 22.5+) so there is no native module to
 * compile on Railway.
 */

let DatabaseSync;
try {
  ({ DatabaseSync } = require('node:sqlite'));
} catch (err) {
  console.error(
    `\nFATAL: node:sqlite is unavailable on ${process.version}.\n` +
      'This app needs Node 24 or newer (node:sqlite is flagged on older runtimes).\n' +
      'On Railway, set the NIXPACKS_NODE_VERSION variable to 24, or make sure\n' +
      'package.json "engines".node is respected by the builder.\n'
  );
  throw err;
}

const config = require('./config');

const db = new DatabaseSync(config.DB_FILE);

db.exec('PRAGMA journal_mode = WAL');
db.exec('PRAGMA synchronous = NORMAL');
db.exec('PRAGMA foreign_keys = ON');

db.exec(`
CREATE TABLE IF NOT EXISTS channels (
  id             TEXT PRIMARY KEY,
  title          TEXT NOT NULL,
  thumbnail      TEXT,
  connected_at   TEXT,
  custom_name    TEXT,
  group_name     TEXT,
  sort_order     INTEGER DEFAULT 0,
  hidden         INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS daily_metrics (
  channel_id          TEXT NOT NULL,
  date                TEXT NOT NULL,

  revenue             REAL,
  ad_revenue          REAL,
  red_revenue         REAL,
  gross_revenue       REAL,
  cpm                 REAL,
  playback_cpm        REAL,
  monetized_playbacks INTEGER,
  ad_impressions      INTEGER,

  views               INTEGER,
  lf_views            INTEGER,
  sf_views            INTEGER,

  watch_minutes       REAL,
  lf_watch_minutes    REAL,
  sf_watch_minutes    REAL,
  avg_view_duration   REAL,

  subs_gained         INTEGER,
  subs_lost           INTEGER,
  likes               INTEGER,
  comments            INTEGER,
  shares              INTEGER,

  -- 1 when the API actually returned a row for this metric family on this day.
  -- Distinguishes "genuinely zero" from "not reported yet" (the 2-day delay).
  revenue_present     INTEGER DEFAULT 0,
  views_present       INTEGER DEFAULT 0,

  updated_at          TEXT,
  PRIMARY KEY (channel_id, date)
);

CREATE INDEX IF NOT EXISTS idx_daily_date ON daily_metrics(date);

CREATE TABLE IF NOT EXISTS estimates (
  channel_id    TEXT NOT NULL,
  date          TEXT NOT NULL,
  revenue       REAL NOT NULL,
  low           REAL,
  high          REAL,
  method        TEXT,
  confidence    REAL,
  computed_at   TEXT,
  PRIMARY KEY (channel_id, date)
);

CREATE TABLE IF NOT EXISTS videos (
  video_id      TEXT PRIMARY KEY,
  channel_id    TEXT,
  title         TEXT,
  thumbnail     TEXT,
  published_at  TEXT,
  duration_sec  INTEGER,
  is_short      INTEGER,
  fetched_at    TEXT
);

CREATE TABLE IF NOT EXISTS video_stats_cache (
  cache_key   TEXT PRIMARY KEY,
  payload     TEXT NOT NULL,
  fetched_at  TEXT NOT NULL
);

-- Per-video cumulative counters, snapshotted on the same schedule as the
-- channel counters. Differencing these is what gives a genuine views-per-hour
-- velocity — "what is taking off right now" — which no Analytics report can
-- provide, since those lag by days.
CREATE TABLE IF NOT EXISTS video_snapshots (
  video_id     TEXT NOT NULL,
  captured_at  TEXT NOT NULL,
  view_count   INTEGER,
  like_count   INTEGER,
  comment_count INTEGER,
  PRIMARY KEY (video_id, captured_at)
);

CREATE INDEX IF NOT EXISTS idx_video_snapshots ON video_snapshots(video_id, captured_at);

CREATE TABLE IF NOT EXISTS sync_state (
  key    TEXT PRIMARY KEY,
  value  TEXT
);

-- ---------------------------------------------------------------------------
-- Live view counts
--
-- The Analytics API reports views AND revenue with the same ~2-3 day lag, so it
-- can never tell us about today. The Data API's channels.list(statistics)
-- returns a near-live *cumulative* view count instead. We snapshot that on a
-- schedule and difference consecutive snapshots across Pacific-time day
-- boundaries (YouTube's reporting day) to recover per-day views for the days
-- Analytics has not published yet.
--
-- These are kept in their own tables, never written into daily_metrics, so
-- reported figures and derived figures never get mixed up.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS view_snapshots (
  channel_id   TEXT NOT NULL,
  captured_at  TEXT NOT NULL,
  pt_date      TEXT NOT NULL,
  view_count   INTEGER,
  subscriber_count INTEGER,
  video_count  INTEGER,
  PRIMARY KEY (channel_id, captured_at)
);

CREATE INDEX IF NOT EXISTS idx_snapshots_ptdate ON view_snapshots(channel_id, pt_date);

CREATE TABLE IF NOT EXISTS live_daily (
  channel_id     TEXT NOT NULL,
  date           TEXT NOT NULL,
  views          INTEGER,
  lf_views       INTEGER,
  sf_views       INTEGER,
  complete       INTEGER DEFAULT 0,
  split_ratio    REAL,
  first_snapshot TEXT,
  last_snapshot  TEXT,
  computed_at    TEXT,
  PRIMARY KEY (channel_id, date)
);

-- How well a live-derived day matched Analytics once it finally reported.
-- This is what proves (or disproves) that the live feed is trustworthy.
CREATE TABLE IF NOT EXISTS live_accuracy (
  channel_id      TEXT NOT NULL,
  date            TEXT NOT NULL,
  live_views      INTEGER,
  analytics_views INTEGER,
  pct_error       REAL,
  recorded_at     TEXT,
  PRIMARY KEY (channel_id, date)
);
`);

/** Add a column to an existing table when it is missing (SQLite has no IF NOT EXISTS). */
function addColumnIfMissing(table, column, definition) {
  const cols = db.prepare(`PRAGMA table_info(${table})`).all();
  if (!cols.some((c) => c.name === column)) {
    db.exec(`ALTER TABLE ${table} ADD COLUMN ${column} ${definition}`);
  }
}

addColumnIfMissing('daily_metrics', 'views_source', "TEXT DEFAULT 'analytics'");
// Partial-day coverage: how much of the reporting day the snapshots actually
// span. Lets a same-day figure be shown honestly as "so far" instead of being
// withheld until the day closes.
addColumnIfMissing('live_daily', 'covered_hours', 'REAL');
addColumnIfMissing('live_daily', 'elapsed_hours', 'REAL');
addColumnIfMissing('live_daily', 'partial', 'INTEGER DEFAULT 0');
// Lifetime counters on the video row, so popular back-catalogue videos can be
// tracked for spikes — not just recent uploads.
addColumnIfMissing('videos', 'lifetime_views', 'INTEGER');
addColumnIfMissing('videos', 'lifetime_likes', 'INTEGER');
addColumnIfMissing('videos', 'lifetime_comments', 'INTEGER');

// ---------------------------------------------------------------------------
// Channels
// ---------------------------------------------------------------------------

const stmtUpsertChannel = db.prepare(`
  INSERT INTO channels (id, title, thumbnail, connected_at)
  VALUES (?, ?, ?, ?)
  ON CONFLICT(id) DO UPDATE SET title = excluded.title, thumbnail = excluded.thumbnail
`);

function upsertChannel({ id, title, thumbnail, connectedAt }) {
  stmtUpsertChannel.run(id, title, thumbnail ?? null, connectedAt ?? new Date().toISOString());
}

function listChannels() {
  return db.prepare('SELECT * FROM channels ORDER BY sort_order, title').all();
}

function updateChannel(id, { customName, groupName, sortOrder, hidden }) {
  const current = db.prepare('SELECT * FROM channels WHERE id = ?').get(id);
  if (!current) return null;
  db.prepare(
    `UPDATE channels SET custom_name = ?, group_name = ?, sort_order = ?, hidden = ? WHERE id = ?`
  ).run(
    customName !== undefined ? customName : current.custom_name,
    groupName !== undefined ? groupName : current.group_name,
    sortOrder !== undefined ? sortOrder : current.sort_order,
    hidden !== undefined ? (hidden ? 1 : 0) : current.hidden,
    id
  );
  return db.prepare('SELECT * FROM channels WHERE id = ?').get(id);
}

function deleteChannel(id) {
  db.prepare('DELETE FROM daily_metrics WHERE channel_id = ?').run(id);
  db.prepare('DELETE FROM estimates WHERE channel_id = ?').run(id);
  db.prepare('DELETE FROM videos WHERE channel_id = ?').run(id);
  db.prepare('DELETE FROM channels WHERE id = ?').run(id);
}

// ---------------------------------------------------------------------------
// Daily metrics
// ---------------------------------------------------------------------------

const DAILY_COLUMNS = [
  'revenue',
  'ad_revenue',
  'red_revenue',
  'gross_revenue',
  'cpm',
  'playback_cpm',
  'monetized_playbacks',
  'ad_impressions',
  'views',
  'lf_views',
  'sf_views',
  'watch_minutes',
  'lf_watch_minutes',
  'sf_watch_minutes',
  'avg_view_duration',
  'subs_gained',
  'subs_lost',
  'likes',
  'comments',
  'shares',
  'revenue_present',
  'views_present',
  'views_source',
];

/**
 * Merge a partial set of columns into one day's row. Each sync query only knows
 * about some columns, so we never overwrite a column we weren't given.
 */
function upsertDaily(channelId, date, values) {
  const cols = Object.keys(values).filter((c) => DAILY_COLUMNS.includes(c));
  if (cols.length === 0) return;

  const placeholders = cols.map(() => '?').join(', ');
  const updates = cols.map((c) => `${c} = excluded.${c}`).join(', ');
  const sql = `
    INSERT INTO daily_metrics (channel_id, date, ${cols.join(', ')}, updated_at)
    VALUES (?, ?, ${placeholders}, ?)
    ON CONFLICT(channel_id, date) DO UPDATE SET ${updates}, updated_at = excluded.updated_at
  `;
  db.prepare(sql).run(channelId, date, ...cols.map((c) => values[c]), new Date().toISOString());
}

function upsertDailyBatch(rows) {
  db.exec('BEGIN');
  try {
    for (const row of rows) upsertDaily(row.channelId, row.date, row.values);
    db.exec('COMMIT');
  } catch (err) {
    db.exec('ROLLBACK');
    throw err;
  }
}

function getDaily(channelIds, start, end) {
  if (!channelIds || channelIds.length === 0) return [];
  const marks = channelIds.map(() => '?').join(',');
  return db
    .prepare(
      `SELECT * FROM daily_metrics
       WHERE channel_id IN (${marks}) AND date >= ? AND date <= ?
       ORDER BY date`
    )
    .all(...channelIds, start, end);
}

function getChannelDaily(channelId, start, end) {
  return db
    .prepare(
      `SELECT * FROM daily_metrics WHERE channel_id = ? AND date >= ? AND date <= ? ORDER BY date`
    )
    .all(channelId, start, end);
}

/** Last day where the revenue report actually returned data for this channel. */
function lastRevenueDate(channelId) {
  const row = db
    .prepare(`SELECT MAX(date) AS d FROM daily_metrics WHERE channel_id = ? AND revenue_present = 1`)
    .get(channelId);
  return row?.d || null;
}

/** Last day where views were reported (usually today-1, sometimes today). */
function lastViewsDate(channelId) {
  const row = db
    .prepare(`SELECT MAX(date) AS d FROM daily_metrics WHERE channel_id = ? AND views_present = 1`)
    .get(channelId);
  return row?.d || null;
}

function firstDataDate(channelId) {
  const row = db.prepare(`SELECT MIN(date) AS d FROM daily_metrics WHERE channel_id = ?`).get(channelId);
  return row?.d || null;
}

function dataBounds() {
  return db.prepare(`SELECT MIN(date) AS min, MAX(date) AS max FROM daily_metrics`).get();
}

// ---------------------------------------------------------------------------
// Estimates
// ---------------------------------------------------------------------------

function saveEstimate({ channelId, date, revenue, low, high, method, confidence }) {
  db.prepare(
    `INSERT INTO estimates (channel_id, date, revenue, low, high, method, confidence, computed_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?)
     ON CONFLICT(channel_id, date) DO UPDATE SET
       revenue = excluded.revenue, low = excluded.low, high = excluded.high,
       method = excluded.method, confidence = excluded.confidence,
       computed_at = excluded.computed_at`
  ).run(channelId, date, revenue, low ?? null, high ?? null, method ?? null, confidence ?? null, new Date().toISOString());
}

function getEstimates(channelIds, start, end) {
  if (!channelIds || channelIds.length === 0) return [];
  const marks = channelIds.map(() => '?').join(',');
  return db
    .prepare(
      `SELECT * FROM estimates WHERE channel_id IN (${marks}) AND date >= ? AND date <= ? ORDER BY date`
    )
    .all(...channelIds, start, end);
}

/** Drop estimates for days where real revenue has since arrived. */
function pruneSettledEstimates() {
  db.exec(`
    DELETE FROM estimates
    WHERE EXISTS (
      SELECT 1 FROM daily_metrics d
      WHERE d.channel_id = estimates.channel_id
        AND d.date = estimates.date
        AND d.revenue_present = 1
    )
  `);
}

// ---------------------------------------------------------------------------
// Videos + caches
// ---------------------------------------------------------------------------

function upsertVideo({
  videoId, channelId, title, thumbnail, publishedAt, durationSec, isShort,
  lifetimeViews, lifetimeLikes, lifetimeComments,
}) {
  db.prepare(
    `INSERT INTO videos (video_id, channel_id, title, thumbnail, published_at, duration_sec,
                         is_short, lifetime_views, lifetime_likes, lifetime_comments, fetched_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
     ON CONFLICT(video_id) DO UPDATE SET
       title = excluded.title, thumbnail = excluded.thumbnail,
       published_at = excluded.published_at, duration_sec = excluded.duration_sec,
       is_short = excluded.is_short, fetched_at = excluded.fetched_at,
       -- keep the previous value when a caller does not supply counters
       lifetime_views = COALESCE(excluded.lifetime_views, videos.lifetime_views),
       lifetime_likes = COALESCE(excluded.lifetime_likes, videos.lifetime_likes),
       lifetime_comments = COALESCE(excluded.lifetime_comments, videos.lifetime_comments)`
  ).run(
    videoId,
    channelId ?? null,
    title ?? null,
    thumbnail ?? null,
    publishedAt ?? null,
    durationSec ?? null,
    isShort ? 1 : 0,
    lifetimeViews ?? null,
    lifetimeLikes ?? null,
    lifetimeComments ?? null,
    new Date().toISOString()
  );
}

function getVideos(videoIds) {
  if (!videoIds.length) return [];
  const marks = videoIds.map(() => '?').join(',');
  return db.prepare(`SELECT * FROM videos WHERE video_id IN (${marks})`).all(...videoIds);
}

function insertVideoSnapshot({ videoId, capturedAt, viewCount, likeCount, commentCount }) {
  db.prepare(
    `INSERT INTO video_snapshots (video_id, captured_at, view_count, like_count, comment_count)
     VALUES (?, ?, ?, ?, ?)
     ON CONFLICT(video_id, captured_at) DO NOTHING`
  ).run(videoId, capturedAt, viewCount ?? null, likeCount ?? null, commentCount ?? null);
}

/**
 * Views per hour over the most recent snapshot window, per video.
 * Returns a map of videoId -> { viewsPerHour, windowHours, gained, latestViews }.
 */
function videoVelocity(videoIds, windowHours = 24) {
  if (!videoIds.length) return new Map();
  const since = new Date(Date.now() - windowHours * 3600 * 1000).toISOString();
  const marks = videoIds.map(() => '?').join(',');

  const rows = db
    .prepare(
      `SELECT video_id, captured_at, view_count FROM video_snapshots
       WHERE video_id IN (${marks}) AND captured_at >= ?
       ORDER BY video_id, captured_at`
    )
    .all(...videoIds, since);

  const byVideo = new Map();
  for (const row of rows) {
    if (!byVideo.has(row.video_id)) byVideo.set(row.video_id, []);
    byVideo.get(row.video_id).push(row);
  }

  const out = new Map();
  for (const [videoId, snaps] of byVideo) {
    if (snaps.length < 2) continue;
    const first = snaps[0];
    const last = snaps[snaps.length - 1];
    const hours = (new Date(last.captured_at) - new Date(first.captured_at)) / 3600000;
    if (hours <= 0) continue;
    const gained = (last.view_count ?? 0) - (first.view_count ?? 0);
    if (gained < 0) continue;
    out.set(videoId, {
      viewsPerHour: gained / hours,
      windowHours: hours,
      gained,
      latestViews: last.view_count,
      samples: snaps.length,
    });
  }
  return out;
}

/**
 * Views-per-hour over several windows at once, from one pass over the snapshots.
 * Comparing a short window against a long one is what reveals acceleration —
 * the signature of something going viral.
 */
function videoVelocityWindows(videoIds, windows = [6, 24, 72]) {
  if (!videoIds.length) return new Map();
  const longest = Math.max(...windows);
  const since = new Date(Date.now() - longest * 3600 * 1000).toISOString();
  const marks = videoIds.map(() => '?').join(',');

  const rows = db
    .prepare(
      `SELECT video_id, captured_at, view_count FROM video_snapshots
       WHERE video_id IN (${marks}) AND captured_at >= ?
       ORDER BY video_id, captured_at`
    )
    .all(...videoIds, since);

  const byVideo = new Map();
  for (const row of rows) {
    if (row.view_count == null) continue;
    if (!byVideo.has(row.video_id)) byVideo.set(row.video_id, []);
    byVideo.get(row.video_id).push(row);
  }

  const now = Date.now();
  const out = new Map();

  for (const [videoId, snaps] of byVideo) {
    if (snaps.length < 2) continue;
    const latest = snaps[snaps.length - 1];
    const result = { latestViews: latest.view_count, samples: snaps.length, windows: {} };

    for (const hours of windows) {
      const cutoff = now - hours * 3600 * 1000;
      // Earliest snapshot at or after the cutoff gives this window's baseline.
      const baseline = snaps.find((s) => new Date(s.captured_at).getTime() >= cutoff) || snaps[0];
      const spanHours = (new Date(latest.captured_at) - new Date(baseline.captured_at)) / 3600000;
      if (spanHours <= 0) continue;
      const gained = latest.view_count - baseline.view_count;
      if (gained < 0) continue;
      result.windows[hours] = {
        viewsPerHour: gained / spanHours,
        gained,
        spanHours,
      };
    }

    if (Object.keys(result.windows).length) out.set(videoId, result);
  }

  return out;
}

function pruneVideoSnapshots(beforeISO) {
  db.prepare('DELETE FROM video_snapshots WHERE captured_at < ?').run(beforeISO);
}

/**
 * Which videos to snapshot for velocity.
 *
 * Deliberately a UNION of two sets: the newest uploads (where a launch surge
 * happens) and the most-viewed back catalogue (where an old video can suddenly
 * pick up traction again). Tracking only recent uploads would make resurgences
 * invisible, which is precisely the case worth catching.
 */
function getTrackedVideoIds({ recentPerChannel = 40, popularPerChannel = 40 } = {}) {
  const ids = new Set();

  /** Take the first N rows per channel from an ordered query. */
  const takePerChannel = (sql, perChannel) => {
    const counts = new Map();
    for (const row of db.prepare(sql).all()) {
      const seen = counts.get(row.channel_id) || 0;
      if (seen >= perChannel) continue;
      counts.set(row.channel_id, seen + 1);
      ids.add(row.video_id);
    }
  };

  // Newest uploads — where a launch surge shows up.
  takePerChannel(
    `SELECT video_id, channel_id FROM videos
     WHERE published_at IS NOT NULL
     ORDER BY published_at DESC`,
    recentPerChannel
  );

  // Biggest back catalogue — where an old video can suddenly pick up again.
  takePerChannel(
    `SELECT video_id, channel_id FROM videos
     WHERE lifetime_views IS NOT NULL
     ORDER BY lifetime_views DESC`,
    popularPerChannel
  );

  return [...ids];
}

/** Every video we have metadata for, for spike analysis. */
function getAllVideos() {
  return db.prepare('SELECT * FROM videos').all();
}

function getCache(key, maxAgeMs) {
  const row = db.prepare('SELECT * FROM video_stats_cache WHERE cache_key = ?').get(key);
  if (!row) return null;
  if (maxAgeMs && Date.now() - new Date(row.fetched_at).getTime() > maxAgeMs) return null;
  try {
    return JSON.parse(row.payload);
  } catch {
    return null;
  }
}

function setCache(key, payload) {
  db.prepare(
    `INSERT INTO video_stats_cache (cache_key, payload, fetched_at) VALUES (?, ?, ?)
     ON CONFLICT(cache_key) DO UPDATE SET payload = excluded.payload, fetched_at = excluded.fetched_at`
  ).run(key, JSON.stringify(payload), new Date().toISOString());
}

function clearCache() {
  db.exec('DELETE FROM video_stats_cache');
}

// ---------------------------------------------------------------------------
// Live view counts
// ---------------------------------------------------------------------------

function insertSnapshot({ channelId, capturedAt, ptDate, viewCount, subscriberCount, videoCount }) {
  db.prepare(
    `INSERT INTO view_snapshots (channel_id, captured_at, pt_date, view_count, subscriber_count, video_count)
     VALUES (?, ?, ?, ?, ?, ?)
     ON CONFLICT(channel_id, captured_at) DO NOTHING`
  ).run(channelId, capturedAt, ptDate, viewCount ?? null, subscriberCount ?? null, videoCount ?? null);
}

function getSnapshots(channelId, sinceISO) {
  return db
    .prepare(
      `SELECT * FROM view_snapshots WHERE channel_id = ? AND captured_at >= ? ORDER BY captured_at`
    )
    .all(channelId, sinceISO);
}

/** Keep the snapshot table from growing without bound. */
function pruneSnapshots(beforeISO) {
  db.prepare('DELETE FROM view_snapshots WHERE captured_at < ?').run(beforeISO);
}

function upsertLiveDaily(row) {
  db.prepare(
    `INSERT INTO live_daily (channel_id, date, views, lf_views, sf_views, complete, split_ratio,
                             first_snapshot, last_snapshot, covered_hours, elapsed_hours, partial,
                             computed_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
     ON CONFLICT(channel_id, date) DO UPDATE SET
       views = excluded.views, lf_views = excluded.lf_views, sf_views = excluded.sf_views,
       complete = excluded.complete, split_ratio = excluded.split_ratio,
       first_snapshot = excluded.first_snapshot, last_snapshot = excluded.last_snapshot,
       covered_hours = excluded.covered_hours, elapsed_hours = excluded.elapsed_hours,
       partial = excluded.partial, computed_at = excluded.computed_at`
  ).run(
    row.channelId,
    row.date,
    row.views ?? null,
    row.lfViews ?? null,
    row.sfViews ?? null,
    row.complete ? 1 : 0,
    row.splitRatio ?? null,
    row.firstSnapshot ?? null,
    row.lastSnapshot ?? null,
    row.coveredHours ?? null,
    row.elapsedHours ?? null,
    row.partial ? 1 : 0,
    new Date().toISOString()
  );
}

function getLiveDaily(channelIds, start, end) {
  if (!channelIds || channelIds.length === 0) return [];
  const marks = channelIds.map(() => '?').join(',');
  return db
    .prepare(
      `SELECT * FROM live_daily WHERE channel_id IN (${marks}) AND date >= ? AND date <= ? ORDER BY date`
    )
    .all(...channelIds, start, end);
}

function getChannelLiveDaily(channelId) {
  return db.prepare('SELECT * FROM live_daily WHERE channel_id = ? ORDER BY date').all(channelId);
}

function deleteLiveDaily(channelId, date) {
  db.prepare('DELETE FROM live_daily WHERE channel_id = ? AND date = ?').run(channelId, date);
}

function recordLiveAccuracy({ channelId, date, liveViews, analyticsViews }) {
  const pctError = analyticsViews > 0 ? (liveViews - analyticsViews) / analyticsViews : null;
  db.prepare(
    `INSERT INTO live_accuracy (channel_id, date, live_views, analytics_views, pct_error, recorded_at)
     VALUES (?, ?, ?, ?, ?, ?)
     ON CONFLICT(channel_id, date) DO UPDATE SET
       live_views = excluded.live_views, analytics_views = excluded.analytics_views,
       pct_error = excluded.pct_error, recorded_at = excluded.recorded_at`
  ).run(channelId, date, liveViews, analyticsViews, pctError, new Date().toISOString());
  return pctError;
}

function getLiveAccuracy(channelId) {
  return db
    .prepare('SELECT * FROM live_accuracy WHERE channel_id = ? ORDER BY date DESC LIMIT 30')
    .all(channelId);
}

// ---------------------------------------------------------------------------
// Sync state
// ---------------------------------------------------------------------------

function getState(key, fallback = null) {
  const row = db.prepare('SELECT value FROM sync_state WHERE key = ?').get(key);
  if (!row) return fallback;
  try {
    return JSON.parse(row.value);
  } catch {
    return row.value;
  }
}

function setState(key, value) {
  db.prepare(
    `INSERT INTO sync_state (key, value) VALUES (?, ?)
     ON CONFLICT(key) DO UPDATE SET value = excluded.value`
  ).run(key, JSON.stringify(value));
}

function stats() {
  const rows = db.prepare('SELECT COUNT(*) AS n FROM daily_metrics').get();
  const bounds = dataBounds();
  return {
    file: config.DB_FILE,
    dailyRows: rows.n,
    channels: db.prepare('SELECT COUNT(*) AS n FROM channels').get().n,
    estimates: db.prepare('SELECT COUNT(*) AS n FROM estimates').get().n,
    videos: db.prepare('SELECT COUNT(*) AS n FROM videos').get().n,
    dateRange: bounds,
  };
}

module.exports = {
  db,
  upsertChannel,
  listChannels,
  updateChannel,
  deleteChannel,
  upsertDaily,
  upsertDailyBatch,
  getDaily,
  getChannelDaily,
  lastRevenueDate,
  lastViewsDate,
  firstDataDate,
  dataBounds,
  saveEstimate,
  getEstimates,
  pruneSettledEstimates,
  insertSnapshot,
  getSnapshots,
  pruneSnapshots,
  upsertLiveDaily,
  getLiveDaily,
  getChannelLiveDaily,
  deleteLiveDaily,
  recordLiveAccuracy,
  getLiveAccuracy,
  upsertVideo,
  getVideos,
  insertVideoSnapshot,
  videoVelocity,
  pruneVideoSnapshots,
  getTrackedVideoIds,
  getAllVideos,
  videoVelocityWindows,
  getCache,
  setCache,
  clearCache,
  getState,
  setState,
  stats,
};
