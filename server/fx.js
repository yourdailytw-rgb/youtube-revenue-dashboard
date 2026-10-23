/**
 * Display-currency conversion.
 *
 * Everything is stored in the base currency (config.CURRENCY, SEK). To show the
 * dashboard in USD, each DAY is converted at YouTube's own exchange rate for
 * that day — recovered from the USD revenue figure stored next to the SEK one
 * (see db.fxRates). YouTube applies one rate per day to every channel, so this
 * reproduces the USD numbers YouTube Studio shows, rather than approximating
 * them with a third-party feed or a single flat rate. The rate moves around 1%
 * across a fortnight, which a flat rate would smear over every long range.
 *
 * Days with no rate of their own — modelled days, today, and any gap — use the
 * nearest earlier known rate.
 */

const config = require('./config');
const db = require('./db');

const BASE = config.CURRENCY;
const SUPPORTED = [...new Set([BASE, 'USD'])];

/** Revenue-denominated fields on a daily_metrics row. Rates such as RPM and
 * CPM are derived from these downstream, so they convert automatically. */
const MONEY_FIELDS = ['revenue', 'ad_revenue', 'red_revenue', 'gross_revenue'];

function normalise(code) {
  const c = String(code || '').toUpperCase();
  return SUPPORTED.includes(c) ? c : BASE;
}

const IDENTITY = {
  currency: BASE,
  base: BASE,
  identity: true,
  available: true,
  factorFor: () => 1,
};

/**
 * Build a converter for one request. Returns `identity: true` when no
 * conversion is needed, and falls back to the base currency (with
 * `available: false`) if USD was asked for but no rates are stored yet.
 */
function converter(requested) {
  const currency = normalise(requested);
  if (currency === BASE) return IDENTITY;

  const rates = db.fxRates();
  if (!rates.length) return { ...IDENTITY, available: false, requested: currency };

  const dates = rates.map((r) => r.date);

  /** Rate for the nearest date at or before `date`; the first rate before that. */
  const rateFor = (date) => {
    let lo = 0;
    let hi = dates.length - 1;
    let found = -1;
    while (lo <= hi) {
      const mid = (lo + hi) >> 1;
      if (dates[mid] <= date) {
        found = mid;
        lo = mid + 1;
      } else {
        hi = mid - 1;
      }
    }
    return rates[found === -1 ? 0 : found].rate;
  };

  const latest = rates[rates.length - 1];
  return {
    currency,
    base: BASE,
    identity: false,
    available: true,
    // base -> USD
    factorFor: (date) => 1 / rateFor(date),
    rateFor,
    latestRate: { date: latest.date, rate: latest.rate },
    coverage: { from: rates[0].date, to: latest.date, days: rates.length },
  };
}

/**
 * Convert a daily_metrics row's money fields; returns the row unchanged when
 * identity.
 *
 * A reported row carries its own USD figure, so its own rate (USD / SEK) is
 * used — that makes each channel's USD exactly YouTube's, even if the SEK and
 * USD figures for that row were fetched on different days and YouTube revised
 * the day in between. The day-wide rate is the fallback, and also the guard: a
 * row whose own rate strays more than 5% from it is treated as bad data.
 */
function convertRow(fx, row) {
  if (!fx || fx.identity) return row;
  const daily = fx.factorFor(row.date);
  const own = row.revenue > 0 && row.revenue_usd > 0 ? row.revenue_usd / row.revenue : null;
  const f = own !== null && Math.abs(own / daily - 1) <= 0.05 ? own : daily;
  const out = { ...row };
  for (const k of MONEY_FIELDS) {
    if (typeof out[k] === 'number') out[k] *= f;
  }
  return out;
}

/** Convert an estimates-table row (revenue, low, high). */
function convertEstimate(fx, est) {
  if (!fx || fx.identity) return est;
  const f = fx.factorFor(est.date);
  return {
    ...est,
    revenue: est.revenue != null ? est.revenue * f : est.revenue,
    low: est.low != null ? est.low * f : est.low,
    high: est.high != null ? est.high * f : est.high,
  };
}

/** Describe the conversion for API responses so the UI can label it. */
function describe(fx) {
  return {
    currency: fx.currency,
    base: fx.base,
    supported: SUPPORTED,
    available: fx.available,
    requested: fx.requested || fx.currency,
    latestRate: fx.latestRate || null,
    coverage: fx.coverage || null,
  };
}

module.exports = { BASE, SUPPORTED, MONEY_FIELDS, normalise, converter, convertRow, convertEstimate, describe };
