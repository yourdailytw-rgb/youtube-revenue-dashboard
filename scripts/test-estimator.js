/**
 * Estimator unit checks. No test framework — just assertions, run with:
 *
 *   node scripts/test-estimator.js
 *
 * These cover the behaviours that are easy to break by accident and expensive
 * to notice in production: which trailing days get claimed as unsettled, and
 * whether the RPM fit separates long-form from Shorts.
 */

const assert = require('node:assert');
const {
  fitRpmModel,
  findMissingDays,
  estimateChannel,
  backtest,
  DEFAULTS,
} = require('../server/estimator');
const { addDays, today } = require('../server/util/dates');

let passed = 0;
function test(name, fn) {
  try {
    fn();
    passed++;
    console.log(`  ✓ ${name}`);
  } catch (err) {
    console.error(`  ✗ ${name}\n    ${err.message}`);
    process.exitCode = 1;
  }
}

/** Build a clean history where revenue is exactly lfRpm×lf + sfRpm×sf. */
function makeHistory({ days = 120, lfRpm = 3, sfRpm = 0.1, lfViews = 50000, sfViews = 0 } = {}) {
  const end = today();
  const rows = [];
  for (let i = days - 1; i >= 0; i--) {
    const date = addDays(end, -i);
    const lf = Math.round(lfViews * (0.9 + ((i * 37) % 20) / 100));
    const sf = Math.round(sfViews * (0.9 + ((i * 53) % 20) / 100));
    rows.push({
      date,
      revenue: (lf / 1000) * lfRpm + (sf / 1000) * sfRpm,
      lf_views: lf,
      sf_views: sf,
      views: lf + sf,
      revenue_present: 1,
      views_present: 1,
    });
  }
  return rows;
}

console.log('\nEstimator checks\n');

test('fits a long-form-only channel to its true RPM', () => {
  const model = fitRpmModel(makeHistory({ lfRpm: 3.4, sfViews: 0 }));
  assert.ok(Math.abs(model.lfRpm - 3.4) < 0.05, `lfRpm was ${model.lfRpm}, expected ~3.4`);
  assert.strictEqual(model.method, 'longform-only');
});

test('separates long-form and Shorts RPM on a mixed channel', () => {
  const model = fitRpmModel(makeHistory({ lfRpm: 3.0, sfRpm: 0.08, lfViews: 40000, sfViews: 200000 }));
  assert.ok(Math.abs(model.lfRpm - 3.0) < 0.25, `lfRpm was ${model.lfRpm}, expected ~3.0`);
  assert.ok(Math.abs(model.sfRpm - 0.08) < 0.05, `sfRpm was ${model.sfRpm}, expected ~0.08`);
  assert.ok(model.method.startsWith('split-rpm'), `method was ${model.method}`);
});

test('claims trailing days that have NO revenue row', () => {
  const history = makeHistory();
  for (const row of history.slice(-2)) {
    row.revenue = null;
    row.revenue_present = 0;
  }
  const { dates } = findMissingDays(history);
  assert.deepStrictEqual(dates, history.slice(-2).map((r) => r.date));
});

test('claims trailing days reported as a ZERO revenue row', () => {
  const history = makeHistory();
  for (const row of history.slice(-2)) {
    row.revenue = 0; // YouTube returned the row, but it is not settled
    row.revenue_present = 1;
  }
  const { dates, partialDates } = findMissingDays(history);
  assert.deepStrictEqual(dates, history.slice(-2).map((r) => r.date));
  assert.strictEqual(partialDates.length, 2, 'both should be flagged as partial');
});

test('claims a half-reported trailing day', () => {
  const history = makeHistory();
  const last = history[history.length - 1];
  last.revenue = last.revenue * 0.3; // only 30% settled
  const { dates } = findMissingDays(history);
  assert.deepStrictEqual(dates, [last.date]);
});

test('leaves fully-settled history alone', () => {
  const { dates } = findMissingDays(makeHistory());
  assert.deepStrictEqual(dates, [], 'nothing should be claimed when every day is settled');
});

test('never claims more than maxLookbackDays', () => {
  const history = makeHistory();
  for (const row of history.slice(-40)) {
    row.revenue = 0;
    row.revenue_present = 1;
  }
  const { dates } = findMissingDays(history);
  assert.ok(
    dates.length <= DEFAULTS.maxLookbackDays,
    `claimed ${dates.length} days, cap is ${DEFAULTS.maxLookbackDays}`
  );
});

test('estimates a missing day close to its true value', () => {
  const history = makeHistory({ lfRpm: 3.2 });
  const truth = history[history.length - 1].revenue;
  history[history.length - 1].revenue = null;
  history[history.length - 1].revenue_present = 0;

  const { estimates } = estimateChannel(history);
  assert.strictEqual(estimates.length, 1);
  const error = Math.abs(estimates[0].revenue - truth) / truth;
  assert.ok(error < 0.1, `estimate was off by ${(error * 100).toFixed(1)}%`);
  assert.ok(estimates[0].low <= estimates[0].revenue && estimates[0].revenue <= estimates[0].high);
});

test('back-test reports near-zero error on noise-free data', () => {
  const score = backtest(makeHistory({ lfRpm: 2.9 }));
  assert.ok(score.samples > 20, `only ${score.samples} samples`);
  assert.ok(score.medianAbsPctError < 0.05, `median error ${score.medianAbsPctError}`);
});

test('survives a channel with almost no history', () => {
  const history = makeHistory({ days: 3 });
  history[2].revenue = null;
  history[2].revenue_present = 0;
  assert.doesNotThrow(() => estimateChannel(history));
});

test('survives a channel with zero views', () => {
  const history = makeHistory({ days: 40, lfViews: 0, sfViews: 0 });
  history[39].revenue_present = 0;
  const result = estimateChannel(history);
  assert.ok(Array.isArray(result.estimates));
});

console.log(`\n${passed} check(s) passed\n`);
