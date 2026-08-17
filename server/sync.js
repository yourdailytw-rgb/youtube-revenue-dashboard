/**
 * Sync engine: pulls the YouTube Analytics API into the local SQLite cache and
 * recomputes revenue estimates.
 *
 * Two modes:
 *   - backfill : first run for a channel, walks back to BACKFILL_START
 *   - refresh  : the trailing SYNC_REFRESH_DAYS window, because YouTube revises
 *                recent numbers for several days after the fact
 */

const config = require('./config');
const db = require('./db');
const { loadTokens, channelHealth } = require('./tokens');
const { clientForChannel, isExpiredError } = require('./oauth');
const youtube = require('./youtube');
const livecounts = require('./livecounts');
const { estimateChannel } = require('./estimator');
const { today, addDays, maxISO } = require('./util/dates');

let running = false;
let lastRun = null;
let lastError = null;

function isRunning() {
  return running;
}

/** History depth handed to the estimator — enough for the 120-day DOW window. */
const ESTIMATOR_HISTORY_DAYS = 200;

async function syncChannel(channelId, tokenData, { full = false } = {}) {
  // Seeded mock channels hold no real credentials — their data is already in
  // the database, so there is nothing to fetch.
  if (tokenData.mock) {
    console.log(`[sync] ${tokenData.channelTitle}: mock channel, skipping API fetch`);
    return { channelId, days: 0, errors: [], mock: true };
  }

  const auth = clientForChannel(channelId, tokenData);
  const end = today();
  const backfilledThrough = db.getState(`backfill:${channelId}`);

  const start = full || !backfilledThrough
    ? config.BACKFILL_START
    : maxISO(addDays(end, -config.SYNC_REFRESH_DAYS), config.BACKFILL_START);

  const label = tokenData.channelTitle || channelId;
  console.log(`[sync] ${label}: fetching ${start} → ${end}${full || !backfilledThrough ? ' (backfill)' : ''}`);

  const { byDate, errors } = await youtube.fetchDailyMetrics({ auth, channelId, start, end });

  const rows = [];
  for (const [date, values] of byDate) {
    rows.push({ channelId, date, values });
  }
  if (rows.length) db.upsertDailyBatch(rows);

  db.upsertChannel({
    id: channelId,
    title: tokenData.channelTitle,
    thumbnail: tokenData.channelThumbnail,
    connectedAt: tokenData.connectedAt,
  });

  if (errors.length) {
    const fatal = errors.some((e) => isExpiredError(e.message));
    channelHealth[channelId] = {
      status: fatal ? 'expired' : 'error',
      error: errors[0].message,
      lastChecked: new Date().toISOString(),
    };
    console.warn(`[sync] ${label}: ${errors.length} query error(s) — ${errors[0].message}`);
  } else {
    channelHealth[channelId] = { status: 'ok', error: null, lastChecked: new Date().toISOString() };
    db.setState(`backfill:${channelId}`, config.BACKFILL_START);
  }

  db.setState(`lastSync:${channelId}`, new Date().toISOString());
  return { channelId, days: rows.length, errors };
}

/** Recompute estimates for one channel from its recent history. */
function recomputeChannelEstimates(channelId) {
  const start = addDays(today(), -ESTIMATOR_HISTORY_DAYS);
  const reported = db.getChannelDaily(channelId, start, today());
  if (reported.length === 0) return null;

  // Overlay live-derived view counts so the estimator has days to model — the
  // Analytics API alone never gives views ahead of revenue.
  const history = livecounts.mergeLiveIntoHistory(channelId, reported);

  const result = estimateChannel(history);
  for (const est of result.estimates) {
    db.saveEstimate({
      channelId,
      date: est.date,
      revenue: est.revenue,
      low: est.low,
      high: est.high,
      method: est.method,
      confidence: est.confidence,
    });
  }
  db.setState(`accuracy:${channelId}`, result.accuracy);
  db.setState(`estimateMeta:${channelId}`, {
    lastRevenueDate: result.lastRevenueDate,
    lastViewsDate: result.lastViewsDate,
    partialDate: result.partialDate,
    estimatedDates: result.estimates.map((e) => e.date),
    computedAt: new Date().toISOString(),
  });
  return result;
}

function recomputeAllEstimates() {
  db.pruneSettledEstimates();
  const out = {};
  for (const channel of db.listChannels()) {
    try {
      out[channel.id] = recomputeChannelEstimates(channel.id);
    } catch (err) {
      console.error(`[estimate] ${channel.title}: ${err.message}`);
    }
  }
  return out;
}

async function syncAll({ full = false } = {}) {
  if (running) {
    console.log('[sync] Already running — skipping');
    return { skipped: true };
  }
  running = true;
  lastError = null;
  const startedAt = Date.now();

  try {
    const allTokens = loadTokens();
    const ids = Object.keys(allTokens);
    if (ids.length === 0) {
      console.log('[sync] No connected channels');
      return { channels: 0, skipped: false };
    }

    const results = [];
    for (const [channelId, tokenData] of Object.entries(allTokens)) {
      try {
        results.push(await syncChannel(channelId, tokenData, { full }));
      } catch (err) {
        console.error(`[sync] ${tokenData.channelTitle || channelId}: FAILED — ${err.message}`);
        channelHealth[channelId] = {
          status: isExpiredError(err.message) ? 'expired' : 'error',
          error: err.message,
          lastChecked: new Date().toISOString(),
        };
        results.push({ channelId, error: err.message });
      }
    }

    recomputeAllEstimates();
    db.clearCache();

    lastRun = {
      at: new Date().toISOString(),
      durationMs: Date.now() - startedAt,
      channels: results.length,
      failed: results.filter((r) => r.error).length,
      full,
    };
    db.setState('lastSync', lastRun);
    console.log(
      `[sync] Complete in ${Math.round(lastRun.durationMs / 1000)}s — ${results.length} channel(s), ${lastRun.failed} failed`
    );
    return { ...lastRun, results };
  } catch (err) {
    lastError = err.message;
    console.error('[sync] Fatal:', err.message);
    throw err;
  } finally {
    running = false;
  }
}

function syncStatus() {
  const channels = db.listChannels().map((c) => ({
    id: c.id,
    title: c.title,
    lastSync: db.getState(`lastSync:${c.id}`),
    backfilled: Boolean(db.getState(`backfill:${c.id}`)),
    health: channelHealth[c.id] || null,
    accuracy: db.getState(`accuracy:${c.id}`),
    estimateMeta: db.getState(`estimateMeta:${c.id}`),
  }));
  return {
    running,
    lastRun: lastRun || db.getState('lastSync'),
    lastError,
    intervalMinutes: config.SYNC_INTERVAL_MINUTES,
    channels,
    db: db.stats(),
  };
}

function startScheduler() {
  const ms = config.SYNC_INTERVAL_MINUTES * 60 * 1000;
  setInterval(() => {
    syncAll().catch((err) => console.error('[sync] Scheduled run failed:', err.message));
  }, ms);
  console.log(`[sync] Scheduler started — every ${config.SYNC_INTERVAL_MINUTES} minutes`);

  // Live view counts poll far more often than the Analytics sync: they are the
  // only source of same-day data, and each snapshot sharpens the day boundary.
  const liveMs = config.LIVE_POLL_MINUTES * 60 * 1000;
  const runLive = async () => {
    try {
      await livecounts.refreshLiveCounts();
      recomputeAllEstimates();
    } catch (err) {
      console.error('[live] Poll failed:', err.message);
    }
  };
  setInterval(runLive, liveMs);
  runLive();
  console.log(`[live] View-count polling started — every ${config.LIVE_POLL_MINUTES} minutes`);
}

module.exports = {
  syncAll,
  syncChannel,
  recomputeAllEstimates,
  recomputeChannelEstimates,
  syncStatus,
  startScheduler,
  isRunning,
};
