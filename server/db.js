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

CREATE TABLE IF NOT EXISTS sync_state (
  key    TEXT PRIMARY KEY,
  value  TEXT
);
`);

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

function upsertVideo({ videoId, channelId, title, thumbnail, publishedAt, durationSec, isShort }) {
  db.prepare(
    `INSERT INTO videos (video_id, channel_id, title, thumbnail, published_at, duration_sec, is_short, fetched_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?)
     ON CONFLICT(video_id) DO UPDATE SET
       title = excluded.title, thumbnail = excluded.thumbnail,
       published_at = excluded.published_at, duration_sec = excluded.duration_sec,
       is_short = excluded.is_short, fetched_at = excluded.fetched_at`
  ).run(
    videoId,
    channelId ?? null,
    title ?? null,
    thumbnail ?? null,
    publishedAt ?? null,
    durationSec ?? null,
    isShort ? 1 : 0,
    new Date().toISOString()
  );
}

function getVideos(videoIds) {
  if (!videoIds.length) return [];
  const marks = videoIds.map(() => '?').join(',');
  return db.prepare(`SELECT * FROM videos WHERE video_id IN (${marks})`).all(...videoIds);
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
  upsertVideo,
  getVideos,
  getCache,
  setCache,
  clearCache,
  getState,
  setState,
  stats,
};
