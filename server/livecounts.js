/**
 * Live view counts — the front half of the real-time revenue estimate.
 *
 * THE PROBLEM THIS SOLVES
 * The YouTube Analytics API reports views and revenue with the SAME ~2-3 day
 * lag. There is no window where we have views but not revenue, so the RPM model
 * in estimator.js has nothing to work with. (YouTube Studio shows live views
 * because it reads a different, real-time feed — not this API.)
 *
 * THE APPROACH
 * The Data API's channels.list(part=statistics) returns a near-live *cumulative*
 * view count. Snapshot it on a schedule, then difference consecutive snapshots
 * across Pacific-time day boundaries — YouTube's reporting day — to recover how
 * many views a channel got on a day Analytics has not published yet.
 *
 * KNOWN LIMITS, stated plainly:
 *   - the cumulative counter is rounded and refreshes periodically, so a single
 *     day's delta is approximate
 *   - it is a COMBINED count; long-form and Shorts are split using the channel's
 *     own recent ratio from Analytics
 *   - it needs snapshots either side of a day boundary, so the first useful
 *     numbers appear a day after polling starts
 *
 * Because those limits are real, every derived day is reconciled against
 * Analytics once it finally reports, and the error is recorded in live_accuracy.
 * That table is the evidence for whether this feed can be trusted — it is
 * surfaced in the UI rather than hidden.
 */

const { google } = require('googleapis');
const db = require('./db');
const { loadTokens } = require('./tokens');
const { clientForChannel } = require('./oauth');
const { addDays } = require('./util/dates');

/** YouTube reports its analytics days in Pacific Time. */
const REPORTING_TZ = 'America/Los_Angeles';

const ptFormatter = new Intl.DateTimeFormat('en-CA', {
  timeZone: REPORTING_TZ,
  year: 'numeric',
  month: '2-digit',
  day: '2-digit',
});

const ptHourFormatter = new Intl.DateTimeFormat('en-GB', {
  timeZone: REPORTING_TZ,
  hour: '2-digit',
  hour12: false,
});

/** The YouTube reporting date ('YYYY-MM-DD') an instant falls on. */
function ptDateOf(date = new Date()) {
  return ptFormatter.format(date);
}

/** Hour of day (0-23) in the reporting timezone. */
function ptHourOf(date = new Date()) {
  return Number(ptHourFormatter.format(date));
}

/** Capture one cumulative-statistics snapshot per connected channel. */
async function pollAll() {
  const allTokens = loadTokens();
  const ids = Object.keys(allTokens);
  if (ids.length === 0) return { polled: 0, failed: 0 };

  const capturedAt = new Date().toISOString();
  const ptDate = ptDateOf();
  let polled = 0;
  let failed = 0;

  for (const [channelId, tokenData] of Object.entries(allTokens)) {
    if (tokenData.mock) continue;
    try {
      const auth = clientForChannel(channelId, tokenData);
      const youtube = google.youtube({ version: 'v3', auth });
      const res = await youtube.channels.list({ part: 'statistics', id: channelId });
      const stats = res.data.items?.[0]?.statistics;
      if (!stats) {
        failed++;
        continue;
      }
      db.insertSnapshot({
        channelId,
        capturedAt,
        ptDate,
        viewCount: Number(stats.viewCount) || null,
        subscriberCount: Number(stats.subscriberCount) || null,
        videoCount: Number(stats.videoCount) || null,
      });
      polled++;
    } catch (err) {
      console.warn(`[live] ${tokenData.channelTitle}: snapshot failed — ${err.message}`);
      failed++;
    }
  }

  // 45 days of snapshots is far more than the estimator needs.
  db.pruneSnapshots(addDays(ptDateOf(), -45));

  if (polled) console.log(`[live] Snapshotted ${polled} channel(s)${failed ? `, ${failed} failed` : ''}`);
  return { polled, failed, capturedAt };
}

/**
 * The long-form share of a channel's views, from the most recent Analytics data.
 * Used to split the combined live counter.
 */
function recentSplitRatio(channelId, referenceDate) {
  const rows = db.getChannelDaily(channelId, addDays(referenceDate, -35), referenceDate);
  let lf = 0;
  let total = 0;
  for (const row of rows) {
    if (row.views_present !== 1) continue;
    lf += row.lf_views ?? 0;
    total += (row.lf_views ?? 0) + (row.sf_views ?? 0);
  }
  // Default to all long-form: most of these channels have negligible Shorts,
  // and long-form is what actually carries revenue.
  return total > 0 ? lf / total : 1;
}

/**
 * Turn snapshots into per-day view counts for the days Analytics has not
 * reported yet, for one channel.
 */
function deriveForChannel(channelId) {
  const lastAnalytics = db.lastViewsDate(channelId);
  if (!lastAnalytics) return { derived: [], reason: 'no analytics history yet' };

  const snapshots = db.getSnapshots(channelId, addDays(lastAnalytics, -2));
  if (snapshots.length < 2) return { derived: [], reason: 'not enough snapshots yet' };

  // Last snapshot of each reporting day — that is the day's closing counter.
  const closingByDate = new Map();
  const firstByDate = new Map();
  for (const snap of snapshots) {
    if (snap.view_count == null) continue;
    closingByDate.set(snap.pt_date, snap);
    if (!firstByDate.has(snap.pt_date)) firstByDate.set(snap.pt_date, snap);
  }

  const dates = [...closingByDate.keys()].sort();
  const todayPT = ptDateOf();
  const derived = [];

  for (const date of dates) {
    // Only fill days Analytics has not published.
    if (date <= lastAnalytics) continue;

    const previousDate = addDays(date, -1);
    const previousClose = closingByDate.get(previousDate);
    if (!previousClose) continue; // no baseline to difference against

    const close = closingByDate.get(date);
    const views = close.view_count - previousClose.view_count;
    if (!Number.isFinite(views) || views < 0) continue; // counter reset or correction

    // A past day is complete; today is still accumulating.
    const isToday = date === todayPT;
    const closedLateEnough = ptHourOf(new Date(close.captured_at)) >= 22;
    const complete = !isToday && closedLateEnough;

    const ratio = recentSplitRatio(channelId, lastAnalytics);
    const lfViews = Math.round(views * ratio);

    derived.push({
      channelId,
      date,
      views,
      lfViews,
      sfViews: views - lfViews,
      complete,
      splitRatio: ratio,
      firstSnapshot: previousClose.captured_at,
      lastSnapshot: close.captured_at,
      isToday,
    });
  }

  for (const row of derived) db.upsertLiveDaily(row);
  return { derived, lastAnalytics };
}

/**
 * Once Analytics reports a day we had derived live, compare the two, record the
 * error, and drop the derived row — reported data always wins.
 */
function reconcileChannel(channelId) {
  const liveRows = db.getChannelLiveDaily(channelId);
  const results = [];

  for (const live of liveRows) {
    const [reported] = db.getChannelDaily(channelId, live.date, live.date);
    if (!reported || reported.views_present !== 1) continue;

    const analyticsViews = (reported.lf_views ?? 0) + (reported.sf_views ?? 0);
    const pctError = db.recordLiveAccuracy({
      channelId,
      date: live.date,
      liveViews: live.views,
      analyticsViews,
    });
    db.deleteLiveDaily(channelId, live.date);
    results.push({ date: live.date, liveViews: live.views, analyticsViews, pctError });
  }

  return results;
}

/**
 * Refresh the list of recent uploads we track per channel.
 *
 * Runs less often than the statistics poll — the upload list changes slowly,
 * the counters change constantly.
 */
async function refreshTrackedVideos({ perChannel = 50 } = {}) {
  const allTokens = loadTokens();
  let discovered = 0;

  for (const [channelId, tokenData] of Object.entries(allTokens)) {
    if (tokenData.mock) continue;
    try {
      const auth = clientForChannel(channelId, tokenData);
      const youtube = google.youtube({ version: 'v3', auth });

      const channelRes = await youtube.channels.list({ part: 'contentDetails', id: channelId });
      const uploadsPlaylist =
        channelRes.data.items?.[0]?.contentDetails?.relatedPlaylists?.uploads;
      if (!uploadsPlaylist) continue;

      const playlist = await youtube.playlistItems.list({
        part: 'contentDetails',
        playlistId: uploadsPlaylist,
        maxResults: Math.min(50, perChannel),
      });
      const videoIds = (playlist.data.items || [])
        .map((item) => item.contentDetails?.videoId)
        .filter(Boolean);
      if (!videoIds.length) continue;

      const details = await youtube.videos.list({
        part: 'snippet,contentDetails,statistics',
        id: videoIds.join(','),
        maxResults: 50,
      });

      for (const item of details.data.items || []) {
        const durationSec = parseISODurationSeconds(item.contentDetails?.duration);
        db.upsertVideo({
          videoId: item.id,
          channelId,
          title: item.snippet?.title,
          thumbnail:
            item.snippet?.thumbnails?.medium?.url || item.snippet?.thumbnails?.default?.url || null,
          publishedAt: item.snippet?.publishedAt,
          durationSec,
          isShort: durationSec !== null && durationSec <= 180,
        });
        discovered++;
      }
    } catch (err) {
      console.warn(`[live] ${tokenData.channelTitle}: upload list refresh failed — ${err.message}`);
    }
  }

  if (discovered) console.log(`[live] Tracking ${discovered} recent video(s)`);
  return { discovered };
}

/**
 * Snapshot per-video cumulative counters. Differencing these across polls is
 * what produces a real views-per-hour figure — Analytics cannot, it lags days.
 */
async function pollVideoStats() {
  const allTokens = loadTokens();
  const firstLive = Object.entries(allTokens).find(([, t]) => !t.mock);
  if (!firstLive) return { snapshotted: 0 };

  const videoIds = db.getTrackedVideoIds(60);
  if (!videoIds.length) return { snapshotted: 0 };

  const capturedAt = new Date().toISOString();
  const auth = clientForChannel(firstLive[0], firstLive[1]);
  const youtube = google.youtube({ version: 'v3', auth });
  let snapshotted = 0;

  for (let i = 0; i < videoIds.length; i += 50) {
    const batch = videoIds.slice(i, i + 50);
    try {
      const res = await youtube.videos.list({
        part: 'statistics',
        id: batch.join(','),
        maxResults: 50,
      });
      for (const item of res.data.items || []) {
        db.insertVideoSnapshot({
          videoId: item.id,
          capturedAt,
          viewCount: item.statistics?.viewCount != null ? Number(item.statistics.viewCount) : null,
          likeCount: item.statistics?.likeCount != null ? Number(item.statistics.likeCount) : null,
          commentCount:
            item.statistics?.commentCount != null ? Number(item.statistics.commentCount) : null,
        });
        snapshotted++;
      }
    } catch (err) {
      console.warn(`[live] Video stats batch failed — ${err.message}`);
    }
  }

  // A week of per-video snapshots is plenty for velocity windows.
  db.pruneVideoSnapshots(new Date(Date.now() - 7 * 86400000).toISOString());

  return { snapshotted };
}

function parseISODurationSeconds(iso) {
  if (!iso) return null;
  const m = /^P(?:(\d+)D)?T?(?:(\d+)H)?(?:(\d+)M)?(?:(\d+)S)?$/.exec(iso);
  if (!m) return null;
  const [, d, h, min, s] = m.map((v) => (v ? Number(v) : 0));
  return d * 86400 + h * 3600 + min * 60 + s;
}

let pollCount = 0;

/** Poll, derive and reconcile for every connected channel. */
async function refreshLiveCounts() {
  const poll = await pollAll();
  const perChannel = {};

  for (const channel of db.listChannels()) {
    try {
      reconcileChannel(channel.id);
      perChannel[channel.id] = deriveForChannel(channel.id);
    } catch (err) {
      console.error(`[live] ${channel.title}: ${err.message}`);
    }
  }

  // Upload lists change slowly; refresh them every 6th poll (~2 hours).
  let videos = { snapshotted: 0 };
  try {
    if (pollCount % 6 === 0) await refreshTrackedVideos();
    videos = await pollVideoStats();
  } catch (err) {
    console.error('[live] Video polling failed:', err.message);
  }
  pollCount++;

  return { poll, perChannel, videos };
}

/**
 * Merge live-derived views into a channel's Analytics history so the estimator
 * sees days it can actually model. Live days are marked so nothing downstream
 * mistakes them for reported figures.
 */
function mergeLiveIntoHistory(channelId, history) {
  const liveRows = db.getChannelLiveDaily(channelId);
  if (!liveRows.length) return history;

  const byDate = new Map(history.map((row) => [row.date, row]));

  for (const live of liveRows) {
    const existing = byDate.get(live.date);
    // Never override a day Analytics has actually reported.
    if (existing && existing.views_present === 1) continue;

    byDate.set(live.date, {
      ...(existing || { channel_id: channelId, date: live.date }),
      date: live.date,
      views: live.views,
      lf_views: live.lf_views,
      sf_views: live.sf_views,
      views_present: 1,
      views_source: 'live',
      revenue_present: existing?.revenue_present ?? 0,
      revenue: existing?.revenue ?? null,
      live_complete: live.complete === 1,
    });
  }

  return [...byDate.values()].sort((a, b) => a.date.localeCompare(b.date));
}

/** Health/diagnostics for the Estimator tab. */
function liveStatus() {
  const channels = db.listChannels().map((channel) => {
    const snapshots = db.getSnapshots(channel.id, addDays(ptDateOf(), -3));
    const accuracy = db.getLiveAccuracy(channel.id);
    const errors = accuracy.map((a) => Math.abs(a.pct_error)).filter((v) => Number.isFinite(v));
    return {
      id: channel.id,
      title: channel.custom_name || channel.title,
      snapshots72h: snapshots.length,
      lastSnapshot: snapshots.length ? snapshots[snapshots.length - 1].captured_at : null,
      liveDays: db.getChannelLiveDaily(channel.id).map((r) => ({
        date: r.date,
        views: r.views,
        lfViews: r.lf_views,
        complete: r.complete === 1,
      })),
      accuracySamples: accuracy.length,
      medianAbsError: errors.length ? median(errors) : null,
      recent: accuracy.slice(0, 10),
    };
  });

  return { reportingTimezone: REPORTING_TZ, ptDate: ptDateOf(), ptHour: ptHourOf(), channels };
}

function median(values) {
  const sorted = [...values].sort((a, b) => a - b);
  const mid = Math.floor(sorted.length / 2);
  return sorted.length % 2 ? sorted[mid] : (sorted[mid - 1] + sorted[mid]) / 2;
}

module.exports = {
  REPORTING_TZ,
  ptDateOf,
  ptHourOf,
  pollAll,
  refreshTrackedVideos,
  pollVideoStats,
  deriveForChannel,
  reconcileChannel,
  refreshLiveCounts,
  mergeLiveIntoHistory,
  recentSplitRatio,
  liveStatus,
};
