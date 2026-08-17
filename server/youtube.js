/**
 * Thin wrapper over the YouTube Analytics v2 + Data v3 APIs.
 *
 * Rules carried over from v1 that must not be broken:
 *   - currency MUST be passed explicitly on any revenue query, otherwise the
 *     API silently returns USD.
 *   - creatorContentType values are camelCase: 'videoOnDemand' and 'shorts'.
 *     Using VIDEO_ON_DEMAND returns zero rows.
 */

const { google } = require('googleapis');
const config = require('./config');
const { addDays, diffDays, minISO } = require('./util/dates');

const CONTENT_TYPE_LONGFORM = 'videoOnDemand';
const CONTENT_TYPE_SHORTS = 'shorts';

/** Analytics reports get chunked so a long backfill never hits row limits. */
const CHUNK_DAYS = 180;

const REVENUE_METRICS = [
  'estimatedRevenue',
  'estimatedAdRevenue',
  'estimatedRedPartnerRevenue',
  'grossRevenue',
  'cpm',
  'playbackBasedCpm',
  'monetizedPlaybacks',
  'adImpressions',
];

const CORE_METRICS = [
  'views',
  'estimatedMinutesWatched',
  'averageViewDuration',
  'subscribersGained',
  'subscribersLost',
  'likes',
  'comments',
  'shares',
];

const SPLIT_METRICS = ['views', 'estimatedMinutesWatched'];

const VIDEO_METRICS = ['views', 'estimatedRevenue', 'estimatedMinutesWatched', 'averageViewDuration'];

function analyticsFor(auth) {
  return google.youtubeAnalytics({ version: 'v2', auth });
}

/** Turn a report into objects keyed by column name instead of index. */
function rowsToObjects(report) {
  const headers = (report.data.columnHeaders || []).map((h) => h.name);
  return (report.data.rows || []).map((row) => {
    const obj = {};
    headers.forEach((name, i) => {
      obj[name] = row[i];
    });
    return obj;
  });
}

/**
 * Run a report, dropping metrics the API rejects rather than losing the whole
 * query. Some metric combinations are unavailable on certain channels (e.g. a
 * channel not in the YouTube Partner Program has no revenue metrics at all).
 */
async function queryReport(auth, params, metrics) {
  const attempt = async (metricList) => {
    const report = await analyticsFor(auth).reports.query({ ...params, metrics: metricList.join(',') });
    return rowsToObjects(report);
  };

  try {
    return { rows: await attempt(metrics), metrics };
  } catch (err) {
    const message = err?.message || '';
    const unsupported = message.includes('metrics') || message.includes('Unknown identifier');
    if (!unsupported || metrics.length <= 1) throw err;

    // Retry with only the first metric, which is the one we actually need.
    const reduced = [metrics[0]];
    console.warn(`[youtube] Metric set rejected (${message}); retrying with ${reduced.join(',')}`);
    return { rows: await attempt(reduced), metrics: reduced };
  }
}

/** Split a long range into API-friendly chunks. */
function chunkRange(start, end, size = CHUNK_DAYS) {
  const chunks = [];
  let cursor = start;
  while (cursor <= end) {
    const chunkEnd = minISO(addDays(cursor, size - 1), end);
    chunks.push({ start: cursor, end: chunkEnd });
    cursor = addDays(chunkEnd, 1);
  }
  return chunks;
}

const num = (v) => (v === undefined || v === null ? null : Number(v));

/**
 * Fetch every daily metric family for one channel over a range.
 * Returns a map of date -> partial daily_metrics column values.
 */
async function fetchDailyMetrics({ auth, channelId, start, end, currency = config.CURRENCY }) {
  const byDate = new Map();
  const touch = (date) => {
    if (!byDate.has(date)) byDate.set(date, {});
    return byDate.get(date);
  };

  const base = { ids: `channel==${channelId}`, dimensions: 'day', sort: 'day' };
  const errors = [];

  for (const chunk of chunkRange(start, end)) {
    const range = { startDate: chunk.start, endDate: chunk.end };

    // --- Revenue (monetary scope, explicit currency) -----------------------
    try {
      const { rows } = await queryReport(auth, { ...base, ...range, currency }, REVENUE_METRICS);
      for (const r of rows) {
        const day = touch(r.day);
        day.revenue = num(r.estimatedRevenue) ?? 0;
        day.ad_revenue = num(r.estimatedAdRevenue);
        day.red_revenue = num(r.estimatedRedPartnerRevenue);
        day.gross_revenue = num(r.grossRevenue);
        day.cpm = num(r.cpm);
        day.playback_cpm = num(r.playbackBasedCpm);
        day.monetized_playbacks = num(r.monetizedPlaybacks);
        day.ad_impressions = num(r.adImpressions);
        day.revenue_present = 1;
      }
    } catch (err) {
      errors.push({ query: 'revenue', message: err.message });
    }

    // --- Core engagement metrics ------------------------------------------
    try {
      const { rows } = await queryReport(auth, { ...base, ...range }, CORE_METRICS);
      for (const r of rows) {
        const day = touch(r.day);
        day.views = num(r.views) ?? 0;
        day.watch_minutes = num(r.estimatedMinutesWatched);
        day.avg_view_duration = num(r.averageViewDuration);
        day.subs_gained = num(r.subscribersGained);
        day.subs_lost = num(r.subscribersLost);
        day.likes = num(r.likes);
        day.comments = num(r.comments);
        day.shares = num(r.shares);
        day.views_present = 1;
      }
    } catch (err) {
      errors.push({ query: 'core', message: err.message });
    }

    // --- Long-form / short-form split -------------------------------------
    try {
      const { rows } = await queryReport(
        auth,
        { ...base, ...range, dimensions: 'day,creatorContentType' },
        SPLIT_METRICS
      );
      for (const r of rows) {
        const day = touch(r.day);
        const type = r.creatorContentType;
        const views = num(r.views) ?? 0;
        const minutes = num(r.estimatedMinutesWatched) ?? 0;
        if (type === CONTENT_TYPE_LONGFORM) {
          day.lf_views = (day.lf_views || 0) + views;
          day.lf_watch_minutes = (day.lf_watch_minutes || 0) + minutes;
        } else if (type === CONTENT_TYPE_SHORTS) {
          day.sf_views = (day.sf_views || 0) + views;
          day.sf_watch_minutes = (day.sf_watch_minutes || 0) + minutes;
        }
        day.views_present = 1;
      }
    } catch (err) {
      errors.push({ query: 'split', message: err.message });
    }
  }

  // Days that reported views but no long/short rows genuinely had zero of that
  // type — record 0 rather than null so the estimator can trust the value.
  for (const values of byDate.values()) {
    if (values.views_present) {
      values.lf_views = values.lf_views ?? 0;
      values.sf_views = values.sf_views ?? 0;
      values.lf_watch_minutes = values.lf_watch_minutes ?? 0;
      values.sf_watch_minutes = values.sf_watch_minutes ?? 0;
      // Marks these as reported figures, as opposed to the live-counter
      // estimates that livecounts.js derives for more recent days.
      values.views_source = 'analytics';
    }
  }

  return { byDate, errors };
}

/** Top videos for a range, sorted by revenue (falls back to views). */
async function fetchTopVideos({ auth, channelId, start, end, limit = 25, currency = config.CURRENCY }) {
  const params = {
    ids: `channel==${channelId}`,
    startDate: start,
    endDate: end,
    dimensions: 'video',
    sort: '-estimatedRevenue',
    maxResults: limit,
    currency,
  };

  try {
    const { rows } = await queryReport(auth, params, VIDEO_METRICS);
    return rows.map((r) => ({
      videoId: r.video,
      views: num(r.views) ?? 0,
      revenue: num(r.estimatedRevenue) ?? 0,
      watchMinutes: num(r.estimatedMinutesWatched) ?? 0,
      avgViewDuration: num(r.averageViewDuration) ?? 0,
    }));
  } catch (err) {
    // Non-monetised channels cannot sort by revenue — fall back to views.
    // `currency` must be removed rather than set to undefined, which would be
    // serialised into the query string.
    const fallbackParams = { ...params, sort: '-views' };
    delete fallbackParams.currency;
    const { rows } = await queryReport(auth, fallbackParams, [
      'views',
      'estimatedMinutesWatched',
      'averageViewDuration',
    ]);
    return rows.map((r) => ({
      videoId: r.video,
      views: num(r.views) ?? 0,
      revenue: null,
      watchMinutes: num(r.estimatedMinutesWatched) ?? 0,
      avgViewDuration: num(r.averageViewDuration) ?? 0,
      revenueUnavailable: true,
      revenueError: err.message,
    }));
  }
}

/** Titles/thumbnails/durations for a batch of video IDs (Data API v3). */
async function fetchVideoDetails({ auth, videoIds }) {
  if (!videoIds.length) return [];
  const youtube = google.youtube({ version: 'v3', auth });
  const out = [];
  for (let i = 0; i < videoIds.length; i += 50) {
    const batch = videoIds.slice(i, i + 50);
    const res = await youtube.videos.list({
      part: 'snippet,contentDetails',
      id: batch.join(','),
      maxResults: 50,
    });
    for (const item of res.data.items || []) {
      const durationSec = parseISODuration(item.contentDetails?.duration);
      out.push({
        videoId: item.id,
        channelId: item.snippet?.channelId,
        title: item.snippet?.title,
        thumbnail:
          item.snippet?.thumbnails?.medium?.url || item.snippet?.thumbnails?.default?.url || null,
        publishedAt: item.snippet?.publishedAt,
        durationSec,
        isShort: durationSec !== null && durationSec <= 180,
      });
    }
  }
  return out;
}

function parseISODuration(iso) {
  if (!iso) return null;
  const m = /^P(?:(\d+)D)?T?(?:(\d+)H)?(?:(\d+)M)?(?:(\d+)S)?$/.exec(iso);
  if (!m) return null;
  const [, d, h, min, s] = m.map((v) => (v ? Number(v) : 0));
  return d * 86400 + h * 3600 + min * 60 + s;
}

/** Channel identity for the OAuth callback. */
async function fetchMyChannel(auth) {
  const youtube = google.youtube({ version: 'v3', auth });
  const res = await youtube.channels.list({ part: 'snippet', mine: true });
  const channel = res.data.items?.[0];
  if (!channel) throw new Error('No YouTube channel found for this Google account');
  return {
    id: channel.id,
    title: channel.snippet.title,
    thumbnail: channel.snippet.thumbnails?.default?.url || null,
  };
}

module.exports = {
  CONTENT_TYPE_LONGFORM,
  CONTENT_TYPE_SHORTS,
  chunkRange,
  fetchDailyMetrics,
  fetchTopVideos,
  fetchVideoDetails,
  fetchMyChannel,
  diffDays,
};
