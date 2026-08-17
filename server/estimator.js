/**
 * Real-time revenue estimation.
 *
 * WHY THIS EXISTS
 * YouTube reports revenue with a ~2 day lag, but view counts are essentially
 * live. Every day the dashboard therefore shows a revenue hole for the two most
 * recent days even though we already know exactly how many views those days
 * got. This module fills that hole.
 *
 * THE MODEL (per channel, recomputed from that channel's own history)
 *
 *   1. Fit revenue against long-form and short-form views separately:
 *
 *          revenue ≈ lfRpm × (lfViews / 1000) + sfRpm × (sfViews / 1000)
 *
 *      via weighted least squares over the trailing window, with an
 *      exponential recency weight (half-life 21 days) so a channel whose RPM
 *      is drifting is tracked rather than averaged away. Shorts and long-form
 *      earn wildly different RPMs, so they get their own coefficient.
 *
 *   2. Apply a day-of-week factor. Ad rates are consistently higher at the end
 *      of the week and lower on weekends; the factor is the median of
 *      actual/predicted for that weekday, damped toward 1 and clamped.
 *
 *   3. Apply a short-term trend factor — how the last 7 days of actual/predicted
 *      compare with the last 28 — also damped and clamped, so a genuine RPM
 *      shift is picked up without letting one loud day take over.
 *
 *   4. Produce an 80% interval from the model's own back-tested error, and a
 *      confidence score from that error plus the size of the training set.
 *
 * Every number the model produces is labelled as an estimate downstream and is
 * replaced by the real figure the moment YouTube reports it.
 */

const { dayOfWeek, addDays, diffDays } = require('./util/dates');

const DEFAULTS = {
  trainWindowDays: 56, // history used to fit RPM
  dowWindowDays: 120, // history used for weekday factors
  minTrainingDays: 10, // below this we fall back to a plain average RPM
  halfLifeDays: 21, // recency weighting for the fit
  dowDamping: 0.7, // 0 = ignore weekday effect, 1 = apply it fully
  dowClamp: [0.75, 1.35],
  trendDamping: 0.6,
  trendClamp: [0.85, 1.2],
  backtestDays: 45, // days used to measure the model's own accuracy
  intervalZ: 1.2816, // 80% interval
  // A trailing revenue day whose RPM is far below the model is almost certainly
  // a partially-reported day; re-estimate it instead of trusting it.
  partialDayThreshold: 0.55,
  // Hard cap on how many trailing days may be claimed as unsettled, so a
  // genuinely weak stretch can never cascade backwards through history.
  maxLookbackDays: 5,
};

const clamp = (v, [lo, hi]) => Math.min(hi, Math.max(lo, v));
const isNum = (v) => typeof v === 'number' && Number.isFinite(v);

function median(values) {
  if (!values.length) return null;
  const sorted = [...values].sort((a, b) => a - b);
  const mid = Math.floor(sorted.length / 2);
  return sorted.length % 2 ? sorted[mid] : (sorted[mid - 1] + sorted[mid]) / 2;
}

/** A history row is usable for training only if both sides were reported. */
function isTrainable(row) {
  return (
    row.revenue_present === 1 &&
    row.views_present === 1 &&
    isNum(row.revenue) &&
    (isNum(row.lf_views) || isNum(row.sf_views))
  );
}

function lf(row) {
  return (row.lf_views ?? 0) / 1000;
}
function sf(row) {
  return (row.sf_views ?? 0) / 1000;
}

/**
 * Weighted least squares fit of revenue on (long-form, short-form) views.
 * Falls back through progressively simpler models when the data cannot
 * support the full one.
 */
function fitRpmModel(rows, opts = DEFAULTS) {
  const usable = rows.filter(isTrainable);
  if (usable.length === 0) {
    return { lfRpm: 0, sfRpm: 0, method: 'no-data', samples: 0 };
  }

  const newest = usable[usable.length - 1].date;
  const weightOf = (row) => Math.pow(0.5, Math.abs(diffDays(row.date, newest)) / opts.halfLifeDays);

  let S11 = 0;
  let S12 = 0;
  let S22 = 0;
  let S1y = 0;
  let S2y = 0;
  let sumLf = 0;
  let sumSf = 0;
  let sumY = 0;
  let sumW = 0;

  for (const row of usable) {
    const w = weightOf(row);
    const x1 = lf(row);
    const x2 = sf(row);
    const y = row.revenue ?? 0;
    S11 += w * x1 * x1;
    S12 += w * x1 * x2;
    S22 += w * x2 * x2;
    S1y += w * x1 * y;
    S2y += w * x2 * y;
    sumLf += w * x1;
    sumSf += w * x2;
    sumY += w * y;
    sumW += w;
  }

  const totalViews = sumLf + sumSf;
  const shortsShare = totalViews > 0 ? sumSf / totalViews : 0;
  const enoughData = usable.length >= opts.minTrainingDays;

  // Channel is effectively long-form only (or short-form only) — one variable.
  if (!enoughData || shortsShare < 0.02) {
    const rpm = sumLf > 0 ? sumY / sumLf : 0;
    return {
      lfRpm: Math.max(0, rpm),
      sfRpm: 0,
      method: enoughData ? 'longform-only' : 'sparse-average',
      samples: usable.length,
      shortsShare,
    };
  }
  if (shortsShare > 0.98) {
    const rpm = sumSf > 0 ? sumY / sumSf : 0;
    return { lfRpm: 0, sfRpm: Math.max(0, rpm), method: 'shorts-only', samples: usable.length, shortsShare };
  }

  const det = S11 * S22 - S12 * S12;
  if (Math.abs(det) > 1e-9) {
    const a = (S22 * S1y - S12 * S2y) / det;
    const b = (S11 * S2y - S12 * S1y) / det;
    if (a >= 0 && b >= 0) {
      return { lfRpm: a, sfRpm: b, method: 'split-rpm', samples: usable.length, shortsShare };
    }
    // One coefficient went negative — the data does not separate cleanly.
    // Keep the positive one and solve the other against the residual.
    if (a >= 0 && sumSf > 0) {
      const residual = Math.max(0, sumY - a * sumLf);
      return {
        lfRpm: a,
        sfRpm: residual / sumSf,
        method: 'split-rpm-constrained',
        samples: usable.length,
        shortsShare,
      };
    }
    if (b >= 0 && sumLf > 0) {
      const residual = Math.max(0, sumY - b * sumSf);
      return {
        lfRpm: residual / sumLf,
        sfRpm: b,
        method: 'split-rpm-constrained',
        samples: usable.length,
        shortsShare,
      };
    }
  }

  // Last resort: one blended RPM across all views.
  const blended = totalViews > 0 ? sumY / totalViews : 0;
  return {
    lfRpm: Math.max(0, blended),
    sfRpm: Math.max(0, blended),
    method: 'blended-rpm',
    samples: usable.length,
    shortsShare,
    weightedDays: sumW,
  };
}

function predictBase(model, row) {
  return model.lfRpm * lf(row) + model.sfRpm * sf(row);
}

/**
 * Median actual/predicted ratio per weekday, damped toward 1.
 * Returns an array indexed 0 (Sunday) … 6 (Saturday).
 */
function computeDowFactors(rows, model, opts = DEFAULTS) {
  const buckets = Array.from({ length: 7 }, () => []);
  for (const row of rows) {
    if (!isTrainable(row)) continue;
    const base = predictBase(model, row);
    if (base <= 0) continue;
    const ratio = (row.revenue ?? 0) / base;
    if (ratio > 0 && ratio < 5) buckets[dayOfWeek(row.date)].push(ratio);
  }
  return buckets.map((values) => {
    if (values.length < 3) return 1;
    const m = median(values);
    return clamp(1 + opts.dowDamping * (m - 1), opts.dowClamp);
  });
}

/** How the most recent week's RPM compares with the trailing month. */
function computeTrendFactor(rows, model, opts = DEFAULTS) {
  const usable = rows.filter(isTrainable);
  if (usable.length < 14) return 1;

  const ratios = usable
    .map((row) => {
      const base = predictBase(model, row);
      return base > 0 ? { date: row.date, ratio: (row.revenue ?? 0) / base } : null;
    })
    .filter(Boolean);
  if (ratios.length < 14) return 1;

  const recent = median(ratios.slice(-7).map((r) => r.ratio));
  const baseline = median(ratios.slice(-28).map((r) => r.ratio));
  if (!recent || !baseline || baseline === 0) return 1;

  return clamp(1 + opts.trendDamping * (recent / baseline - 1), opts.trendClamp);
}

/**
 * Estimate revenue for one date using only history strictly before it.
 * `history` must be sorted ascending by date.
 */
function estimateForDate(history, target, opts = DEFAULTS) {
  const targetRow = history.find((r) => r.date === target.date) || target;
  const priorAll = history.filter((r) => r.date < target.date);

  const trainStart = addDays(target.date, -opts.trainWindowDays);
  const dowStart = addDays(target.date, -opts.dowWindowDays);
  const trainRows = priorAll.filter((r) => r.date >= trainStart);
  const dowRows = priorAll.filter((r) => r.date >= dowStart);

  const model = fitRpmModel(trainRows.length >= opts.minTrainingDays ? trainRows : priorAll, opts);
  if (model.method === 'no-data') {
    return null;
  }

  const dowFactors = computeDowFactors(dowRows, model, opts);
  const dowFactor = dowFactors[dayOfWeek(target.date)] ?? 1;
  const trend = computeTrendFactor(trainRows, model, opts);

  const base = predictBase(model, targetRow);
  const revenue = Math.max(0, base * dowFactor * trend);

  return {
    date: target.date,
    revenue,
    base,
    dowFactor,
    trendFactor: trend,
    model,
    inputs: {
      lfViews: targetRow.lf_views ?? 0,
      sfViews: targetRow.sf_views ?? 0,
      views: targetRow.views ?? 0,
    },
  };
}

/**
 * Walk-forward back-test: re-estimate each of the last N complete days using
 * only the data that existed before it, and compare against what YouTube
 * actually reported. This is what the dashboard's accuracy badge reports.
 */
function backtest(history, opts = DEFAULTS) {
  const complete = history.filter(isTrainable);
  if (complete.length < opts.minTrainingDays + 5) {
    return { samples: 0, mape: null, medianAbsPctError: null, sigma: null, errors: [] };
  }

  const targets = complete.slice(-opts.backtestDays);
  const errors = [];

  for (const row of targets) {
    const result = estimateForDate(history, row, opts);
    if (!result) continue;
    const actual = row.revenue ?? 0;
    if (actual <= 0) continue;
    const pctError = (result.revenue - actual) / actual;
    errors.push({
      date: row.date,
      actual,
      predicted: result.revenue,
      pctError,
      absPctError: Math.abs(pctError),
    });
  }

  if (errors.length === 0) {
    return { samples: 0, mape: null, medianAbsPctError: null, sigma: null, errors: [] };
  }

  const absErrors = errors.map((e) => e.absPctError);
  const mape = absErrors.reduce((a, b) => a + b, 0) / absErrors.length;
  const bias = errors.reduce((a, e) => a + e.pctError, 0) / errors.length;
  const variance =
    errors.reduce((a, e) => a + (e.pctError - bias) ** 2, 0) / Math.max(1, errors.length - 1);

  return {
    samples: errors.length,
    mape,
    medianAbsPctError: median(absErrors),
    bias,
    sigma: Math.sqrt(variance),
    errors,
  };
}

/**
 * Which recent days need estimating for a channel?
 *
 * Two things can happen at the trailing edge, and both have to be caught:
 *   a) YouTube returns no revenue row at all for the day (revenue_present = 0)
 *   b) YouTube returns a row that is only partially settled — a real number,
 *      but a fraction of what the day's views imply
 *
 * So rather than trusting "last day with a revenue row", we walk backwards from
 * the newest day with views and keep claiming days until we hit one that looks
 * properly settled. The walk is capped at `maxLookbackDays` so a genuinely
 * low-earning stretch can never cascade into rewriting history.
 */
function findMissingDays(history, opts = DEFAULTS) {
  const withRevenue = history.filter((r) => r.revenue_present === 1);
  const withViews = history.filter((r) => r.views_present === 1);
  if (withViews.length === 0) {
    return { dates: [], lastRevenueDate: null, lastViewsDate: null, partialDates: [] };
  }

  const lastRevenue = withRevenue.length ? withRevenue[withRevenue.length - 1].date : null;
  const lastViews = withViews[withViews.length - 1].date;

  const candidates = withViews.slice(-opts.maxLookbackDays).reverse();
  const dates = [];
  const partialDates = [];

  for (const row of candidates) {
    if (row.revenue_present !== 1) {
      dates.push(row.date);
      continue;
    }

    // The row exists — decide whether it is fully settled.
    const estimate = estimateForDate(history, row, opts);
    if (!estimate || estimate.revenue <= 0) break;

    const ratio = (row.revenue ?? 0) / estimate.revenue;
    if (ratio < opts.partialDayThreshold) {
      dates.push(row.date);
      partialDates.push(row.date);
      continue;
    }
    break; // settled day reached — everything older is trustworthy
  }

  dates.reverse();
  return {
    dates,
    lastRevenueDate: lastRevenue,
    lastViewsDate: lastViews,
    partialDates,
    partialDate: partialDates[partialDates.length - 1] || null,
  };
}

/**
 * Full pipeline for one channel: figure out which days are missing, estimate
 * each, and attach an interval derived from the model's back-tested error.
 */
function estimateChannel(history, options = {}) {
  const opts = { ...DEFAULTS, ...options };
  const sorted = [...history].sort((a, b) => a.date.localeCompare(b.date));

  const { dates, lastRevenueDate, lastViewsDate, partialDate, partialDates } = findMissingDays(
    sorted,
    opts
  );
  const accuracy = backtest(sorted, opts);

  const sigma = accuracy.sigma ?? 0.35; // assume wide error until proven otherwise
  const estimates = [];

  for (const date of dates) {
    const row = sorted.find((r) => r.date === date);
    if (!row || row.views_present !== 1) continue;

    const result = estimateForDate(sorted, row, opts);
    if (!result) continue;

    const spread = opts.intervalZ * sigma * result.revenue;
    estimates.push({
      date,
      revenue: round2(result.revenue),
      low: round2(Math.max(0, result.revenue - spread)),
      high: round2(result.revenue + spread),
      method: result.model.method,
      confidence: confidenceScore(accuracy, result.model),
      isPartialCorrection: partialDates.includes(date),
      reportedRevenue: partialDates.includes(date) ? row.revenue : null,
      lfViews: result.inputs.lfViews,
      sfViews: result.inputs.sfViews,
      lfRpm: round2(result.model.lfRpm),
      sfRpm: round2(result.model.sfRpm),
      dowFactor: round3(result.dowFactor),
      trendFactor: round3(result.trendFactor),
    });
  }

  return {
    estimates,
    lastRevenueDate,
    lastViewsDate,
    partialDate,
    partialDates,
    accuracy: {
      samples: accuracy.samples,
      mape: accuracy.mape,
      medianAbsPctError: accuracy.medianAbsPctError,
      bias: accuracy.bias,
      sigma: accuracy.sigma,
      recent: accuracy.errors.slice(-14),
    },
  };
}

/** 0–1 score combining back-tested error with training-set size. */
function confidenceScore(accuracy, model) {
  if (!accuracy.samples) return 0.3;
  const errorScore = clamp(1 - (accuracy.medianAbsPctError ?? 0.4) / 0.5, [0, 1]);
  const sampleScore = clamp(accuracy.samples / 30, [0, 1]);
  const modelScore = model.method === 'split-rpm' ? 1 : model.method === 'longform-only' ? 0.9 : 0.7;
  return Math.round(clamp(errorScore * 0.6 + sampleScore * 0.25 + modelScore * 0.15, [0, 1]) * 100) / 100;
}

const round2 = (v) => (isNum(v) ? Math.round(v * 100) / 100 : v);
const round3 = (v) => (isNum(v) ? Math.round(v * 1000) / 1000 : v);

module.exports = {
  DEFAULTS,
  fitRpmModel,
  predictBase,
  computeDowFactors,
  computeTrendFactor,
  estimateForDate,
  backtest,
  findMissingDays,
  estimateChannel,
};
