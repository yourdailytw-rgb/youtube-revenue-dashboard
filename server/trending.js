/**
 * Viral / spike detection.
 *
 * THE QUESTION THIS ANSWERS
 * "Which videos are picking up right now?" — including the case that is easy to
 * miss entirely: an old video that suddenly gets traction again months after
 * publication. Analytics cannot answer this at all, because it lags days behind.
 *
 * HOW IT WORKS
 * Every tracked video's cumulative view counter is snapshotted every 20 minutes
 * (see livecounts.js). For each video we compare a SHORT window against a
 * LONGER baseline:
 *
 *   spikeRatio = recent views/hour  ÷  baseline views/hour
 *
 * The baseline is chosen in order of preference:
 *   1. the 72h snapshot window, when we have that much history
 *   2. the video's lifetime average pace (all-time views ÷ hours since publish)
 *
 * Falling back to the lifetime average is what makes this work from the very
 * first hours of polling, and it is exactly the right comparison for a
 * resurgence: a two-year-old video that averaged 40 views/hour across its life
 * and is now doing 1,800 views/hour is unambiguously back from the dead.
 *
 * RANKING
 * Ratio alone would surface noise — a video going from 1 to 6 views/hour is a
 * 6x "spike" that nobody cares about. The heat score therefore combines the
 * ratio with the absolute pace, so a big ratio on a meaningful volume wins:
 *
 *   heat = log2(1 + spikeRatio) × sqrt(recent views/hour)
 *
 * Videos below a small absolute floor are excluded outright.
 */

const db = require('./db');

const DEFAULTS = {
  recentWindowHours: 6, // "right now"
  baselineWindowHours: 72, // what normal looks like
  minViewsPerHour: 15, // noise floor
  spikeThreshold: 2, // 2x baseline counts as heating up
  strongSpikeThreshold: 5,
  freshHours: 48, // a video this young is still in its launch curve
};

/** Classify what kind of movement this is — they mean different things. */
function classify(video, opts) {
  const { spikeRatio, ageHours, recentViewsPerHour, accelerating } = video;

  if (ageHours != null && ageHours <= opts.freshHours) {
    return spikeRatio >= opts.spikeThreshold || accelerating
      ? { kind: 'launch-surge', label: 'Launch surge' }
      : { kind: 'new', label: 'New upload' };
  }
  if (spikeRatio >= opts.strongSpikeThreshold) {
    return { kind: 'breakout', label: 'Breakout' };
  }
  if (spikeRatio >= opts.spikeThreshold) {
    return { kind: 'resurgence', label: 'Picking up' };
  }
  if (spikeRatio <= 0.6) {
    return { kind: 'cooling', label: 'Cooling off' };
  }
  return { kind: 'steady', label: 'Steady' };
}

/**
 * Score every tracked video for spike behaviour.
 * Returns them sorted hottest-first.
 */
function detect(options = {}) {
  const opts = { ...DEFAULTS, ...options };
  const windows = [opts.recentWindowHours, 24, opts.baselineWindowHours];

  const videos = db.getAllVideos();
  if (!videos.length) return { videos: [], ready: false, reason: 'no videos tracked yet' };

  const velocity = db.videoVelocityWindows(
    videos.map((v) => v.video_id),
    windows
  );
  if (velocity.size === 0) {
    return {
      videos: [],
      ready: false,
      reason: 'not enough view-counter snapshots yet — needs at least two polls',
    };
  }

  const channels = new Map(db.listChannels().map((c) => [c.id, c.custom_name || c.title]));
  const now = Date.now();
  const scored = [];

  for (const video of videos) {
    const vel = velocity.get(video.video_id);
    if (!vel) continue;

    const recent = vel.windows[opts.recentWindowHours] || vel.windows[24];
    if (!recent) continue;

    const recentViewsPerHour = recent.viewsPerHour;
    if (recentViewsPerHour < opts.minViewsPerHour) continue;

    const ageHours = video.published_at
      ? Math.max(1, (now - new Date(video.published_at).getTime()) / 3600000)
      : null;

    const lifetimeViews = video.lifetime_views ?? vel.latestViews;
    const lifetimePace = lifetimeViews != null && ageHours ? lifetimeViews / ageHours : null;

    // Prefer a measured baseline; fall back to the video's lifetime pace.
    const longWindow = vel.windows[opts.baselineWindowHours];
    const measuredBaseline =
      longWindow && longWindow.spanHours >= opts.recentWindowHours * 2
        ? longWindow.viewsPerHour
        : null;
    const baseline = measuredBaseline ?? lifetimePace;
    const baselineSource = measuredBaseline != null ? `${opts.baselineWindowHours}h window` : 'lifetime average';

    if (!baseline || baseline <= 0) continue;

    const spikeRatio = recentViewsPerHour / baseline;

    // Short window running ahead of the medium one means it is still climbing.
    const mid = vel.windows[24];
    const accelerating = mid ? recentViewsPerHour > mid.viewsPerHour * 1.25 : false;

    const heat = Math.log2(1 + spikeRatio) * Math.sqrt(recentViewsPerHour);

    const entry = {
      videoId: video.video_id,
      channelId: video.channel_id,
      channelTitle: channels.get(video.channel_id) || video.channel_id,
      title: video.title,
      thumbnail: video.thumbnail,
      publishedAt: video.published_at,
      durationSec: video.duration_sec,
      isShort: video.is_short === 1,
      ageHours,
      ageDays: ageHours ? ageHours / 24 : null,
      lifetimeViews,
      recentViewsPerHour,
      recentWindowHours: recent.spanHours,
      recentGained: recent.gained,
      viewsPerHour24: mid?.viewsPerHour ?? null,
      baselineViewsPerHour: baseline,
      baselineSource,
      spikeRatio,
      accelerating,
      heat,
      snapshots: vel.samples,
      // Rough extrapolation of the next 24h if the current pace holds. Labelled
      // as a projection everywhere it appears — it is not a prediction of virality.
      projected24h: Math.round(recentViewsPerHour * 24),
    };

    entry.classification = classify(entry, opts);
    scored.push(entry);
  }

  scored.sort((a, b) => b.heat - a.heat);

  return {
    ready: true,
    thresholds: {
      recentWindowHours: opts.recentWindowHours,
      baselineWindowHours: opts.baselineWindowHours,
      spikeThreshold: opts.spikeThreshold,
      minViewsPerHour: opts.minViewsPerHour,
    },
    counts: {
      tracked: videos.length,
      withVelocity: velocity.size,
      spiking: scored.filter((v) => v.spikeRatio >= opts.spikeThreshold).length,
      breakouts: scored.filter((v) => v.classification.kind === 'breakout').length,
      resurgences: scored.filter((v) => v.classification.kind === 'resurgence').length,
      launchSurges: scored.filter((v) => v.classification.kind === 'launch-surge').length,
    },
    videos: scored,
  };
}

module.exports = { DEFAULTS, detect, classify };
