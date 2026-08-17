/**
 * Aggregation layer. Turns rows of daily_metrics (+ estimates) into everything
 * the dashboard draws: series, summaries, period comparisons, month grids,
 * channel rankings and trend/forecast numbers.
 *
 * Estimated revenue is always kept in its own field. `revenue` is only ever
 * what YouTube reported; `effectiveRevenue` is revenue when present and the
 * estimate otherwise, and `isEstimated` marks those days so the UI can render
 * them differently and never pass an estimate off as reported.
 */

const db = require('./db');
const {
  eachDay,
  monthKey,
  previousPeriod,
  previousYearPeriod,
  addDays,
  diffDays,
  today,
  endOfMonth,
  startOfMonth,
} = require('./util/dates');

const SUM_FIELDS = [
  'revenue',
  'ad_revenue',
  'red_revenue',
  'gross_revenue',
  'views',
  'lf_views',
  'sf_views',
  'watch_minutes',
  'lf_watch_minutes',
  'sf_watch_minutes',
  'subs_gained',
  'subs_lost',
  'monetized_playbacks',
  'ad_impressions',
  'likes',
  'comments',
  'shares',
];

const emptyDay = (date) => {
  const day = { date };
  for (const f of SUM_FIELDS) day[f] = 0;
  day.estimatedRevenue = 0;
  day.estimatedLow = 0;
  day.estimatedHigh = 0;
  day.isEstimated = false;
  day.hasRevenue = false;
  day.hasViews = false;
  day.viewsAreLive = false;
  day.liveComplete = false;
  return day;
};

function addRow(day, row) {
  for (const f of SUM_FIELDS) {
    const v = row[f];
    if (typeof v === 'number' && Number.isFinite(v)) day[f] += v;
  }
  if (row.revenue_present === 1) day.hasRevenue = true;
  if (row.views_present === 1) day.hasViews = true;
}

function addEstimate(day, est) {
  day.estimatedRevenue += est.revenue ?? 0;
  day.estimatedLow += est.low ?? est.revenue ?? 0;
  day.estimatedHigh += est.high ?? est.revenue ?? 0;
  day.isEstimated = true;
}

/** Effective revenue + derived rates, applied once a day is fully assembled. */
function finalizeDay(day) {
  // A day with no reported revenue and no estimate has NO DATA — it is not a
  // zero-revenue day. Conflating the two drags charts to the floor and poisons
  // averages, so it is flagged here and rendered as a gap downstream.
  day.hasData = day.hasRevenue || day.hasViews || day.isEstimated;
  day.hasRevenueData = day.hasRevenue || day.isEstimated;

  // A day is "estimated" when at least one channel's revenue had to be modelled.
  day.effectiveRevenue = day.revenue + day.estimatedRevenue;
  day.effectiveLow = day.revenue + (day.isEstimated ? day.estimatedLow : 0);
  day.effectiveHigh = day.revenue + (day.isEstimated ? day.estimatedHigh : 0);
  day.subs_net = (day.subs_gained || 0) - (day.subs_lost || 0);
  day.rpm = day.views > 0 ? (day.effectiveRevenue / day.views) * 1000 : 0;
  day.lf_rpm = day.lf_views > 0 ? (day.effectiveRevenue / day.lf_views) * 1000 : 0;
  day.cpm =
    day.monetized_playbacks > 0 ? ((day.gross_revenue || 0) / day.monetized_playbacks) * 1000 : 0;
  day.avg_view_duration = day.views > 0 ? (day.watch_minutes * 60) / day.views : 0;
  day.watch_hours = day.watch_minutes / 60;
  return day;
}

/**
 * Build a continuous daily series (no gaps) for a set of channels.
 * `perChannel` also returns each channel's own series.
 */
function buildSeries({ channelIds, start, end, includeEstimates = true, includeLiveViews = true }) {
  const rows = db.getDaily(channelIds, start, end);
  const estimates = includeEstimates ? db.getEstimates(channelIds, start, end) : [];
  const liveRows = includeLiveViews ? db.getLiveDaily(channelIds, start, end) : [];

  // Days Analytics has already reported, so live-derived views for those days
  // can be ignored rather than double-counted.
  const reportedViews = new Set(
    rows.filter((r) => r.views_present === 1).map((r) => `${r.channel_id}:${r.date}`)
  );

  const totals = new Map();
  const perChannel = new Map();
  for (const id of channelIds) perChannel.set(id, new Map());

  for (const date of eachDay(start, end)) {
    totals.set(date, emptyDay(date));
    for (const id of channelIds) perChannel.get(id).set(date, emptyDay(date));
  }

  for (const row of rows) {
    const t = totals.get(row.date);
    if (t) addRow(t, row);
    const c = perChannel.get(row.channel_id)?.get(row.date);
    if (c) addRow(c, row);
  }

  // Live-derived views for days Analytics has not published. These are what let
  // the estimator model recent revenue at all, and they are flagged so the UI
  // can show them as provisional.
  for (const live of liveRows) {
    if (reportedViews.has(`${live.channel_id}:${live.date}`)) continue;
    const apply = (day) => {
      if (!day) return;
      day.views += live.views || 0;
      day.lf_views += live.lf_views || 0;
      day.sf_views += live.sf_views || 0;
      day.hasViews = true;
      day.viewsAreLive = true;
      day.liveComplete = live.complete === 1;
    };
    apply(totals.get(live.date));
    apply(perChannel.get(live.channel_id)?.get(live.date));
  }

  for (const est of estimates) {
    const t = totals.get(est.date);
    if (t) addEstimate(t, est);
    const c = perChannel.get(est.channel_id)?.get(est.date);
    if (c) addEstimate(c, est);
  }

  const finalize = (map) => [...map.values()].map(finalizeDay);

  return {
    totals: finalize(totals),
    byChannel: Object.fromEntries([...perChannel.entries()].map(([id, map]) => [id, finalize(map)])),
  };
}

/** Sum a series into a single summary object. */
function summarize(series) {
  const out = emptyDay(null);
  delete out.date;
  let estimatedDays = 0;

  for (const day of series) {
    for (const f of SUM_FIELDS) out[f] += day[f] || 0;
    out.estimatedRevenue += day.estimatedRevenue || 0;
    out.estimatedLow += day.estimatedLow || 0;
    out.estimatedHigh += day.estimatedHigh || 0;
    if (day.isEstimated) estimatedDays++;
  }

  out.isEstimated = estimatedDays > 0;
  finalizeDay(out);

  // Averages must divide by days that actually have revenue data. Counting the
  // trailing days YouTube has not reported yet would understate the average.
  const daysWithRevenue = series.filter((d) => d.hasRevenueData);

  out.days = series.length;
  out.daysWithData = daysWithRevenue.length;
  out.daysAwaitingData = series.length - daysWithRevenue.length;
  out.estimatedDays = estimatedDays;
  out.dailyAverage = daysWithRevenue.length ? out.effectiveRevenue / daysWithRevenue.length : 0;
  out.bestDay = daysWithRevenue.reduce(
    (best, d) => (!best || d.effectiveRevenue > best.effectiveRevenue ? d : best),
    null
  );
  out.latestDayWithData = daysWithRevenue.length ? daysWithRevenue[daysWithRevenue.length - 1] : null;
  return out;
}

const DELTA_FIELDS = [
  'effectiveRevenue',
  'revenue',
  'views',
  'lf_views',
  'sf_views',
  'watch_hours',
  'subs_net',
  'rpm',
  'cpm',
  'dailyAverage',
  'avg_view_duration',
];

/** Percentage deltas between two summaries. */
function computeDeltas(current, previous) {
  const deltas = {};
  for (const field of DELTA_FIELDS) {
    const now = current?.[field] ?? 0;
    const before = previous?.[field] ?? 0;
    deltas[field] = {
      current: now,
      previous: before,
      absolute: now - before,
      pct: before !== 0 ? (now - before) / Math.abs(before) : now !== 0 ? null : 0,
    };
  }
  return deltas;
}

/** Per-channel totals for the ranking / contribution views. */
function channelBreakdown({ channels, series, previousSeries }) {
  const rows = channels.map((channel) => {
    const current = summarize(series.byChannel[channel.id] || []);
    const previous = previousSeries ? summarize(previousSeries.byChannel[channel.id] || []) : null;
    return {
      id: channel.id,
      title: channel.custom_name || channel.title,
      thumbnail: channel.thumbnail,
      group: channel.group_name || null,
      revenue: current.effectiveRevenue,
      reportedRevenue: current.revenue,
      estimatedRevenue: current.estimatedRevenue,
      views: current.views,
      lfViews: current.lf_views,
      sfViews: current.sf_views,
      watchHours: current.watch_hours,
      subsNet: current.subs_net,
      rpm: current.rpm,
      cpm: current.cpm,
      dailyAverage: current.dailyAverage,
      previousRevenue: previous ? previous.effectiveRevenue : null,
      revenueDeltaPct:
        previous && previous.effectiveRevenue !== 0
          ? (current.effectiveRevenue - previous.effectiveRevenue) / Math.abs(previous.effectiveRevenue)
          : null,
      viewsDeltaPct:
        previous && previous.views !== 0 ? (current.views - previous.views) / Math.abs(previous.views) : null,
    };
  });

  const total = rows.reduce((a, r) => a + r.revenue, 0);
  for (const row of rows) row.share = total > 0 ? row.revenue / total : 0;
  rows.sort((a, b) => b.revenue - a.revenue);
  return { rows, total };
}

/** Calendar-month rollup with month-over-month and year-over-year deltas. */
function monthlyBreakdown(series) {
  const months = new Map();
  for (const day of series) {
    const key = monthKey(day.date);
    if (!months.has(key)) months.set(key, []);
    months.get(key).push(day);
  }

  const list = [...months.entries()]
    .map(([month, days]) => {
      const s = summarize(days);
      return {
        month,
        days: days.length,
        revenue: s.effectiveRevenue,
        reportedRevenue: s.revenue,
        estimatedRevenue: s.estimatedRevenue,
        views: s.views,
        lfViews: s.lf_views,
        sfViews: s.sf_views,
        watchHours: s.watch_hours,
        subsNet: s.subs_net,
        rpm: s.rpm,
        dailyAverage: s.dailyAverage,
        isPartial: month === monthKey(today()),
      };
    })
    .sort((a, b) => a.month.localeCompare(b.month));

  const byKey = new Map(list.map((m) => [m.month, m]));
  for (let i = 0; i < list.length; i++) {
    const m = list[i];
    const prev = list[i - 1];
    m.momPct = prev && prev.revenue !== 0 ? (m.revenue - prev.revenue) / Math.abs(prev.revenue) : null;

    const [y, mo] = m.month.split('-').map(Number);
    const lastYear = byKey.get(`${y - 1}-${String(mo).padStart(2, '0')}`);
    m.yoyPct =
      lastYear && lastYear.revenue !== 0 ? (m.revenue - lastYear.revenue) / Math.abs(lastYear.revenue) : null;
    m.lastYearRevenue = lastYear ? lastYear.revenue : null;
  }
  return list;
}

/** Rolling average over a numeric field. */
function rollingAverage(series, field, window) {
  const out = [];
  let sum = 0;
  for (let i = 0; i < series.length; i++) {
    sum += series[i][field] || 0;
    if (i >= window) sum -= series[i - window][field] || 0;
    const n = Math.min(i + 1, window);
    out.push({ date: series[i].date, value: sum / n });
  }
  return out;
}

/**
 * Month-to-date pace and a month-end projection.
 * Projection = MTD total + (remaining days × trailing 14-day daily average),
 * with a weekday-shape correction so a month ending on a weekend isn't
 * over-projected.
 */
function forecast(fullSeries) {
  const now = today();
  const monthStart = startOfMonth(now);
  const monthEnd = endOfMonth(now);

  const mtd = fullSeries.filter((d) => d.date >= monthStart && d.date <= now);
  if (mtd.length === 0) return null;

  const mtdRevenue = mtd.reduce((a, d) => a + d.effectiveRevenue, 0);
  const trailing = fullSeries.filter((d) => d.date >= addDays(now, -14) && d.date <= now);
  const trailingAvg = trailing.length
    ? trailing.reduce((a, d) => a + d.effectiveRevenue, 0) / trailing.length
    : 0;

  const daysRemaining = Math.max(0, diffDays(now, monthEnd));
  const projected = mtdRevenue + daysRemaining * trailingAvg;

  // Same window last month, for an honest "are we ahead?" comparison.
  const lastMonthEnd = addDays(monthStart, -1);
  const lastMonthStart = startOfMonth(lastMonthEnd);
  const sameDayLastMonth = addDays(lastMonthStart, diffDays(monthStart, now));
  const lastMonthToDate = fullSeries
    .filter((d) => d.date >= lastMonthStart && d.date <= sameDayLastMonth)
    .reduce((a, d) => a + d.effectiveRevenue, 0);
  const lastMonthTotal = fullSeries
    .filter((d) => d.date >= lastMonthStart && d.date <= lastMonthEnd)
    .reduce((a, d) => a + d.effectiveRevenue, 0);

  return {
    month: monthKey(now),
    monthStart,
    monthEnd,
    daysElapsed: mtd.length,
    daysRemaining,
    mtdRevenue,
    trailingDailyAverage: trailingAvg,
    projectedRevenue: projected,
    lastMonthToDate,
    lastMonthTotal,
    vsLastMonthToDatePct:
      lastMonthToDate !== 0 ? (mtdRevenue - lastMonthToDate) / Math.abs(lastMonthToDate) : null,
    vsLastMonthTotalPct:
      lastMonthTotal !== 0 ? (projected - lastMonthTotal) / Math.abs(lastMonthTotal) : null,
  };
}

/** Estimation metadata for the whole dashboard. */
function estimationMeta(channelIds) {
  const perChannel = {};
  let lastRevenueDate = null;
  let lastViewsDate = null;
  const estimatedDates = new Set();

  for (const id of channelIds) {
    const meta = db.getState(`estimateMeta:${id}`);
    const accuracy = db.getState(`accuracy:${id}`);
    if (!meta) continue;
    perChannel[id] = { ...meta, accuracy };
    if (meta.lastRevenueDate && (!lastRevenueDate || meta.lastRevenueDate > lastRevenueDate)) {
      lastRevenueDate = meta.lastRevenueDate;
    }
    if (meta.lastViewsDate && (!lastViewsDate || meta.lastViewsDate > lastViewsDate)) {
      lastViewsDate = meta.lastViewsDate;
    }
    for (const d of meta.estimatedDates || []) estimatedDates.add(d);
  }

  // Weighted headline accuracy: average of per-channel median errors.
  const accuracies = Object.values(perChannel)
    .map((c) => c.accuracy)
    .filter((a) => a && a.medianAbsPctError !== null && a.samples > 0);
  const headline = accuracies.length
    ? accuracies.reduce((a, c) => a + c.medianAbsPctError, 0) / accuracies.length
    : null;

  return {
    lastRevenueDate,
    lastViewsDate,
    delayDays: lastRevenueDate && lastViewsDate ? diffDays(lastRevenueDate, lastViewsDate) : null,
    estimatedDates: [...estimatedDates].sort(),
    medianAbsPctError: headline,
    perChannel,
  };
}

module.exports = {
  buildSeries,
  summarize,
  computeDeltas,
  channelBreakdown,
  monthlyBreakdown,
  rollingAverage,
  forecast,
  estimationMeta,
  previousPeriod,
  previousYearPeriod,
};
