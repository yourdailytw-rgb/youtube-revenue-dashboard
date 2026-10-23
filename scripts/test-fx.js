/**
 * Display-currency checks.
 *
 *   node scripts/test-fx.js
 *
 * The property that matters: in USD, the dashboard's reported revenue must
 * equal the sum of YouTube's own USD figures — not SEK divided by some average
 * rate. Also covers modelled days, derived rates (RPM), the SEK identity path
 * and the no-rates fallback. Uses a throwaway database.
 */

const fs = require('fs');
const os = require('os');
const path = require('path');
const assert = require('node:assert');

const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ytdash-fx-'));
process.env.DATA_DIR_OVERRIDE = tmpDir;
process.env.CURRENCY = 'SEK';

const db = require('../server/db');
const fx = require('../server/fx');
const analytics = require('../server/analytics');

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

const near = (a, b, tol = 1e-6) => Math.abs(a - b) <= tol * Math.max(1, Math.abs(b));

console.log('\nDisplay-currency checks\n');

test('with no stored rates, USD falls back to SEK and says so', () => {
  const c = fx.converter('USD');
  assert.strictEqual(c.currency, 'SEK');
  assert.strictEqual(c.available, false);
  assert.strictEqual(c.requested, 'USD');
});

// Two channels, five reported days, a rate that moves every day — the real shape.
const RATES = { '2026-10-01': 10.2, '2026-10-02': 10.1, '2026-10-03': 9.95, '2026-10-04': 9.9, '2026-10-05': 10.05 };
const CH = ['UCa', 'UCb'];
let expectedUsd = 0;
for (const id of CH) db.upsertChannel({ id, title: id });
for (const [date, rate] of Object.entries(RATES)) {
  CH.forEach((id, i) => {
    const sek = 3000 + i * 1234.56;
    const usd = Math.round((sek / rate) * 100) / 100; // YouTube reports to the cent
    expectedUsd += usd;
    db.upsertDaily(id, date, {
      revenue: sek,
      revenue_usd: usd,
      gross_revenue: sek * 1.4,
      views: 100000,
      lf_views: 100000,
      sf_views: 0,
      engaged_views: 100000,
      lf_engaged_views: 100000,
      sf_engaged_views: 0,
      revenue_present: 1,
      views_present: 1,
    });
  });
}
// A modelled day after the last reported one.
db.saveEstimate({ channelId: 'UCa', date: '2026-10-06', revenue: 5000, low: 4500, high: 5500, method: 't', confidence: 0.9 });

test('recovers a separate rate for every day', () => {
  const rates = db.fxRates();
  assert.strictEqual(rates.length, 5);
  for (const r of rates) assert.ok(Math.abs(r.rate - RATES[r.date]) < 0.01, `${r.date}: ${r.rate} vs ${RATES[r.date]}`);
});

test('USD reported revenue equals the sum of YouTube\'s own USD figures', () => {
  const c = fx.converter('USD');
  assert.strictEqual(c.currency, 'USD');
  const series = analytics.buildSeries({ channelIds: CH, start: '2026-10-01', end: '2026-10-05', fx: c });
  const total = analytics.summarize(series.totals).revenue;
  assert.ok(Math.abs(total - expectedUsd) < 0.05, `USD total ${total.toFixed(2)} vs YouTube's ${expectedUsd.toFixed(2)}`);
});

test('a single flat rate would NOT have matched (the reason for per-day rates)', () => {
  const sekTotal = analytics.summarize(
    analytics.buildSeries({ channelIds: CH, start: '2026-10-01', end: '2026-10-05' }).totals
  ).revenue;
  const flat = sekTotal / RATES['2026-10-05'];
  assert.ok(Math.abs(flat - expectedUsd) > 1, 'flat-rate conversion should visibly diverge on this data');
});

test('modelled days use the latest known rate', () => {
  const c = fx.converter('USD');
  const series = analytics.buildSeries({ channelIds: CH, start: '2026-10-06', end: '2026-10-06', fx: c });
  const day = series.totals[0];
  // The rate RECOVERED from YouTube's cent-rounded USD figures, not the nominal
  // one used to generate them — that recovered rate is what conversion uses.
  const latest = db.fxRates().at(-1);
  assert.strictEqual(latest.date, '2026-10-05');
  assert.ok(near(day.estimatedRevenue, 5000 / latest.rate, 1e-9), `got ${day.estimatedRevenue}`);
  assert.ok(near(day.estimatedLow, 4500 / latest.rate, 1e-9));
});

test('RPM and CPM convert with the revenue they are built from', () => {
  const sekDay = analytics.buildSeries({ channelIds: CH, start: '2026-10-02', end: '2026-10-02' }).totals[0];
  const usdDay = analytics.buildSeries({ channelIds: CH, start: '2026-10-02', end: '2026-10-02', fx: fx.converter('USD') }).totals[0];
  assert.ok(near(usdDay.rpm, sekDay.rpm / RATES['2026-10-02'], 1e-3), `rpm ${usdDay.rpm} vs ${sekDay.rpm / 10.1}`);
  assert.ok(near(usdDay.views, sekDay.views), 'views must not be converted');
});

test('SEK is the identity — nothing changes', () => {
  const c = fx.converter('SEK');
  assert.strictEqual(c.identity, true);
  const a = analytics.buildSeries({ channelIds: CH, start: '2026-10-01', end: '2026-10-05' });
  const b = analytics.buildSeries({ channelIds: CH, start: '2026-10-01', end: '2026-10-05', fx: c });
  assert.strictEqual(analytics.summarize(a.totals).revenue, analytics.summarize(b.totals).revenue);
});

test('per channel, USD equals that channel\'s own USD even when SEK was revised', () => {
  // Simulate a revision: channel UCa's stored SEK drifted after its USD was
  // fetched (what happened to September 2026). Its own rate must still win.
  db.upsertDaily('UCa', '2026-10-03', { revenue: 3020 }); // was 3000; USD unchanged
  const c = fx.converter('USD');
  const day = analytics.buildSeries({ channelIds: ['UCa'], start: '2026-10-03', end: '2026-10-03', fx: c }).totals[0];
  const storedUsd = Math.round((3000 / RATES['2026-10-03']) * 100) / 100;
  assert.ok(Math.abs(day.revenue - storedUsd) < 1e-9, `got ${day.revenue}, YouTube's USD ${storedUsd}`);
  db.upsertDaily('UCa', '2026-10-03', { revenue: 3000 }); // restore
});

test('a row whose own rate is implausible falls back to the day rate', () => {
  db.upsertDaily('UCb', '2026-10-04', { revenue_usd: 1 }); // corrupt: would imply ~4235 SEK/USD
  const c = fx.converter('USD');
  const day = analytics.buildSeries({ channelIds: ['UCb'], start: '2026-10-04', end: '2026-10-04', fx: c }).totals[0];
  assert.ok(day.revenue > 300, `fell for the corrupt row: ${day.revenue}`);
});

test('unknown currency codes fall back to the base currency', () => {
  assert.strictEqual(fx.converter('EUR').currency, 'SEK');
  assert.strictEqual(fx.converter(undefined).currency, 'SEK');
});

console.log(`\n${passed} check(s) passed\n`);
try {
  fs.rmSync(tmpDir, { recursive: true, force: true });
} catch {
  /* best effort */
}
