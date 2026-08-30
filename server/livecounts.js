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
 * The Data API exposes near-live *cumulative* view counters. We snapshot them on
 * a schedule and difference consecutive snapshots across Pacific-time day
 * boundaries — YouTube's reporting day — to recover how many views arrived on a
 * day Analytics has not published yet.
 *
 * There are two counters available, and which one we use matters:
 *
 *   PER-VIDEO (primary)  videos.list(statistics) per tracked video, summed.
 *     Updates frequently, so short windows produce real numbers. Measured on
 *     production: these move within the hour.
 *
 *   PER-CHANNEL (fallback)  channels.list(statistics).
 *     Updates in large, infrequent chunks — differencing it over less than a day
 *     returns exactly zero, which is why it cannot be the primary source. Kept
 *     only to cover days the per-video snapshots miss.
 *
 * KNOWN LIMITS, stated plainly:
 *   - the per-video sum covers the 80 tracked videos per channel, not the whole
 *     back catalogue, so it UNDERSTATES the channel total by whatever the long
 *     tail contributes
 *   - counters are rounded, so a single day's delta is approximate
 *   - both counters are COMBINED figures; long-form and Shorts are split using
 *     the channel's own recent ratio from Analytics
 *   - a whole-day figure needs snapshots either side of a day boundary; before
 *     that, the day is reported as partial with the hours actually covered
 *
 * Because those limits are real, every derived day is reconciled against
 * Analytics once it finally reports. The error is recorded in live_accuracy, and
 * the median ratio becomes a per-channel calibration factor that corrects for
 * the untracked long tail. That table is the evidence for whether this feed can
 * be trusted, and it is surfaced in the UI rather than hidden.
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
 * The share of raw views that counted as ENGAGED, per content type, learned from
 * recent SETTLED Analytics days.
 *
 * This is the conversion the estimator depends on. The live counters are RAW
 * views — the public counter counts every play — while the RPM model is fitted
 * on engaged views. Feeding raw views into a model calibrated on engaged views
 * overstates revenue by exactly 1/rate: harmless while long-form sits at 100%,
 * but roughly double for Shorts.
 *
 * The newest days are excluded because engagedViews settles more slowly than
 * views, so including them would drag the rate down and understate the estimate.
 */
function recentEngagedRates(channelId, referenceDate, opts = {}) {
  const lookback = opts.lookbackDays ?? 21;
  // referenceDate is the newest day Analytics has REPORTED, and Analytics only
  // publishes days that are already two to three days old — so it is settled by
  // construction. Excluding it here previously skipped the single day that
  // carried the view-definition change, leaving the rate stuck on the old
  // regime and inflating every live estimate.
  const settledThrough = referenceDate;
  const rows = db
    .getChannelDaily(channelId, addDays(settledThrough, -lookback), settledThrough)
    .filter((r) => r.views_present === 1);

  const clampRate = (v) => (Number.isFinite(v) && v > 0.05 && v <= 1.05 ? Math.min(1, v) : null);

  const lfDays = rows
    .filter((r) => (r.lf_views ?? 0) > 0 && r.lf_engaged_views != null)
    .map((r) => ({ date: r.date, views: r.lf_views, engaged: r.lf_engaged_views, rate: r.lf_engaged_views / r.lf_views }))
    .sort((a, b) => a.date.localeCompare(b.date));

  const sfDays = rows
    .filter((r) => (r.sf_views ?? 0) > 0 && r.sf_engaged_views != null)
    .map((r) => ({ views: r.sf_views, engaged: r.sf_engaged_views }));

  /**
   * Views-weighted rate over a set of days.
   */
  const weighted = (days) => {
    const v = days.reduce((a, d) => a + d.views, 0);
    const e = days.reduce((a, d) => a + d.engaged, 0);
    return v > 0 ? clampRate(e / v) : null;
  };

  /**
   * Detect a step change in how YouTube counts views.
   *
   * In late August 2026 the "views" metric was redefined to count from about a
   * second, roughly doubling it, while "engaged views" kept the older meaning.
   * A long trailing average would take weeks to notice, and until it did every
   * live estimate would be inflated by the ratio between the two regimes — so
   * the break is found explicitly and only days after it are used.
   */
  let lfUsable = lfDays;
  let regimeBreak = null;

  if (lfDays.length >= 3) {
    const priorRates = lfDays.slice(0, -1).map((d) => d.rate).sort((a, b) => a - b);
    const priorMedian = priorRates[Math.floor(priorRates.length / 2)];
    const newest = lfDays[lfDays.length - 1];

    if (priorMedian && newest.rate < priorMedian * 0.8) {
      // Walk back over the contiguous run of days in the new, lower regime.
      let i = lfDays.length - 1;
      while (i > 0 && lfDays[i - 1].rate < priorMedian * 0.8) i--;
      lfUsable = lfDays.slice(i);
      regimeBreak = lfUsable[0].date;
    }
  }

  return {
    lf: weighted(lfUsable) ?? 1,
    sf: weighted(sfDays) ?? 1,
    regimeBreak,
    lfDaysUsed: lfUsable.length,
    // The days the rate was actually computed from, so a wrong rate can be
    // traced to its inputs instead of guessed at.
    inspect: lfDays.slice(-6).map((d) => ({
      date: d.date,
      views: d.views,
      engaged: d.engaged,
      rate: Number(d.rate.toFixed(4)),
    })),
    samples: { lfViews: lfUsable.reduce((a, d) => a + d.views, 0) },
  };
}

/**
 * Per-day view counts derived by summing PER-VIDEO counter deltas.
 *
 * This is the primary source, and it exists because the channel-level counter
 * turned out to be unusable for this: it updates in large infrequent chunks, so
 * differencing it over anything short of a day returns zero. Per-video counters
 * update far more often — measurably so; they are what makes the velocity in the
 * Viral tab work.
 *
 * The trade-off is coverage: we track 80 videos per channel, not the entire
 * back catalogue, so the sum understates the channel's true total by whatever
 * the long tail contributes. That is why every derived day is reconciled against
 * Analytics and a per-channel calibration factor is learned from the result —
 * see calibrationFactor() below.
 */
function deriveFromVideoSnapshots(channelId, lastAnalytics) {
  const rows = db.getChannelVideoSnapshots(channelId, addDays(lastAnalytics, -1));
  if (rows.length < 2) return new Map();

  // Group by video, then take each video's closing counter per reporting day.
  const byVideo = new Map();
  for (const row of rows) {
    if (row.view_count == null) continue;
    if (!byVideo.has(row.video_id)) byVideo.set(row.video_id, []);
    byVideo.get(row.video_id).push(row);
  }

  /** date -> { views, videos, firstSnapshot, lastSnapshot } */
  const byDate = new Map();

  for (const snaps of byVideo.values()) {
    const closingByDate = new Map();
    const firstByDate = new Map();
    for (const snap of snaps) {
      const ptDate = ptDateOf(new Date(snap.captured_at));
      closingByDate.set(ptDate, snap);
      if (!firstByDate.has(ptDate)) firstByDate.set(ptDate, snap);
    }

    for (const [date, close] of closingByDate) {
      if (date <= lastAnalytics) continue;

      const previous = closingByDate.get(addDays(date, -1));
      const baseline = previous || firstByDate.get(date);
      if (!baseline || baseline.captured_at === close.captured_at) continue;

      const delta = close.view_count - baseline.view_count;
      if (!Number.isFinite(delta) || delta < 0) continue;

      if (!byDate.has(date)) {
        byDate.set(date, {
          views: 0,
          videos: 0,
          partial: !previous,
          firstSnapshot: baseline.captured_at,
          lastSnapshot: close.captured_at,
        });
      }
      const bucket = byDate.get(date);
      bucket.views += delta;
      bucket.videos += 1;
      // The day is only whole-day if every contributing video had a
      // previous-day baseline.
      if (!previous) bucket.partial = true;
      if (baseline.captured_at < bucket.firstSnapshot) bucket.firstSnapshot = baseline.captured_at;
      if (close.captured_at > bucket.lastSnapshot) bucket.lastSnapshot = close.captured_at;
    }
  }

  return byDate;
}

/**
 * How much the per-video sum has historically understated Analytics, learned
 * from the days we have already reconciled. Applied as a multiplier so the
 * untracked long tail is accounted for instead of silently missing.
 *
 * Returns 1 (and calibrated: false) until there are enough samples to trust.
 */
function calibrationFactor(channelId) {
  const rows = db.getLiveAccuracy(channelId);
  const ratios = rows
    .filter((r) => r.live_views > 0 && r.analytics_views > 0)
    .map((r) => r.analytics_views / r.live_views)
    .filter((v) => v > 0.2 && v < 5); // ignore nonsense
  if (ratios.length < 3) return { factor: 1, calibrated: false, samples: ratios.length };
  return { factor: median(ratios), calibrated: true, samples: ratios.length };
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

  const todayPT = ptDateOf();
  const now = new Date();
  const derived = [];

  // Per-video sums are the primary source; the channel counter is a coarse
  // fallback for days the video snapshots cannot cover.
  const videoDays = deriveFromVideoSnapshots(channelId, lastAnalytics);
  const { factor, calibrated, samples } = calibrationFactor(channelId);
  const ratio = recentSplitRatio(channelId, lastAnalytics);
  const engagedRates = recentEngagedRates(channelId, lastAnalytics);

  for (const [date, bucket] of videoDays) {
    if (bucket.views <= 0) continue;

    const views = Math.round(bucket.views * factor);
    const lfViews = Math.round(views * ratio);
    const sfViews = views - lfViews;
    // Convert RAW live views to ENGAGED views, which is what the model expects.
    const lfEngagedViews = Math.round(lfViews * engagedRates.lf);
    const sfEngagedViews = Math.round(sfViews * engagedRates.sf);
    const isToday = date === todayPT;
    const coveredHours =
      (new Date(bucket.lastSnapshot) - new Date(bucket.firstSnapshot)) / 3600000;

    derived.push({
      channelId,
      date,
      views,
      lfViews,
      sfViews,
      engagedViews: lfEngagedViews + sfEngagedViews,
      lfEngagedViews,
      sfEngagedViews,
      lfEngagedRate: engagedRates.lf,
      sfEngagedRate: engagedRates.sf,
      complete: !bucket.partial && !isToday,
      partial: bucket.partial || isToday,
      coveredHours,
      elapsedHours: isToday ? ptHourOf(now) + now.getUTCMinutes() / 60 : 24,
      splitRatio: ratio,
      firstSnapshot: bucket.firstSnapshot,
      lastSnapshot: bucket.lastSnapshot,
      isToday,
      source: 'video-sum',
      videosCounted: bucket.videos,
      calibration: { factor, calibrated, samples },
    });
  }

  const coveredByVideos = new Set(derived.map((d) => d.date));
  const dates = [...closingByDate.keys()].sort();

  for (const date of dates) {
    // Only fill days Analytics has not published.
    if (date <= lastAnalytics) continue;
    if (coveredByVideos.has(date)) continue; // per-video sum already has it

    const close = closingByDate.get(date);
    const previousClose = closingByDate.get(addDays(date, -1));

    let baseline = previousClose;
    let partial = false;

    if (!baseline) {
      // No previous-day closing counter to difference against. That happens on
      // the first day of polling, and for any day whose predecessor we missed.
      // Rather than withhold everything, fall back to differencing within the
      // day itself — which yields the views accumulated SO FAR, from the first
      // snapshot of the day onwards. Honest, but incomplete, so it is flagged.
      const withinDay = firstByDate.get(date);
      if (!withinDay || withinDay.captured_at === close.captured_at) continue;
      baseline = withinDay;
      partial = true;
    }

    const views = close.view_count - baseline.view_count;
    if (!Number.isFinite(views) || views < 0) continue; // counter reset or correction

    // YouTube's channel-level view counter updates in chunks, not continuously,
    // so a short window often shows no movement at all. Zero measured views is
    // "we haven't seen an update yet", NOT "this day earned nothing" — storing it
    // would produce a 0 kr estimate and pollute every average downstream.
    if (views === 0) continue;

    const isToday = date === todayPT;
    const closedLateEnough = ptHourOf(new Date(close.captured_at)) >= 22;
    // Only a full-day difference on a finished day counts as complete.
    const complete = !partial && !isToday && closedLateEnough;

    // How much of the reporting day these snapshots actually span.
    const coveredHours = (new Date(close.captured_at) - new Date(baseline.captured_at)) / 3600000;
    const elapsedHours = isToday
      ? ptHourOf(now) + now.getUTCMinutes() / 60
      : 24;

    const lfViews = Math.round(views * ratio);
    const sfViewsFallback = views - lfViews;
    const lfEngagedFallback = Math.round(lfViews * engagedRates.lf);
    const sfEngagedFallback = Math.round(sfViewsFallback * engagedRates.sf);

    derived.push({
      channelId,
      date,
      views,
      lfViews,
      sfViews: sfViewsFallback,
      engagedViews: lfEngagedFallback + sfEngagedFallback,
      lfEngagedViews: lfEngagedFallback,
      sfEngagedViews: sfEngagedFallback,
      lfEngagedRate: engagedRates.lf,
      sfEngagedRate: engagedRates.sf,
      complete,
      partial: partial || isToday,
      coveredHours,
      elapsedHours,
      splitRatio: ratio,
      firstSnapshot: baseline.captured_at,
      lastSnapshot: close.captured_at,
      isToday,
      source: 'channel-counter',
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
      // The estimator reads these first — they are the engaged equivalents of
      // the raw live counters, which is the basis the RPM model was fitted on.
      engaged_views: live.engaged_views ?? live.views,
      lf_engaged_views: live.lf_engaged_views ?? live.lf_views,
      sf_engaged_views: live.sf_engaged_views ?? live.sf_views,
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
        partial: r.partial === 1,
        coveredHours: r.covered_hours,
        elapsedHours: r.elapsed_hours,
      })),
      calibration: calibrationFactor(channel.id),
      engagedRates: (() => {
        const edge = db.lastViewsDate(channel.id);
        if (!edge) return null;
        const r = recentEngagedRates(channel.id, edge);
        return {
          longform: r.lf,
          shorts: r.sf,
          regimeBreak: r.regimeBreak,
          daysUsed: r.lfDaysUsed,
          referenceDate: edge,
          inspect: r.inspect,
        };
      })(),
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
  deriveFromVideoSnapshots,
  calibrationFactor,
  reconcileChannel,
  refreshLiveCounts,
  mergeLiveIntoHistory,
  recentSplitRatio,
  recentEngagedRates,
  liveStatus,
};
