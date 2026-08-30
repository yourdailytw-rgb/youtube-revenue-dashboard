/**
 * Live view-count pipeline checks.
 *
 *   node scripts/test-livecounts.js
 *
 * Simulates snapshots of the cumulative view counter across day boundaries and
 * verifies that the derived per-day views, the long-form split, the
 * completeness flag and the reconciliation against Analytics all behave.
 *
 * Uses a throwaway database so it never touches real data.
 */

process.env.BACKFILL_START = '2024-01-01';

const fs = require('fs');
const os = require('os');
const path = require('path');
const assert = require('node:assert');

// Point the app at a scratch data directory before anything loads config.
const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ytdash-test-'));
process.env.DATA_DIR_OVERRIDE = tmpDir;

const db = require('../server/db');
const livecounts = require('../server/livecounts');
const { addDays } = require('../server/util/dates');

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

const CHANNEL = 'UCtest_livecounts';

function reset() {
  db.db.exec(`DELETE FROM view_snapshots WHERE channel_id = '${CHANNEL}'`);
  db.db.exec(`DELETE FROM live_daily WHERE channel_id = '${CHANNEL}'`);
  db.db.exec(`DELETE FROM live_accuracy WHERE channel_id = '${CHANNEL}'`);
  db.db.exec(`DELETE FROM daily_metrics WHERE channel_id = '${CHANNEL}'`);
  db.upsertChannel({ id: CHANNEL, title: 'Live Test', thumbnail: null });
}

/** Seed Analytics history so lastViewsDate() and the split ratio have data. */
function seedAnalytics(throughDate, days = 40) {
  for (let i = days - 1; i >= 0; i--) {
    const date = addDays(throughDate, -i);
    db.upsertDaily(CHANNEL, date, {
      revenue: 1000,
      views: 100000,
      lf_views: 90000,
      sf_views: 10000,
      revenue_present: 1,
      views_present: 1,
      views_source: 'analytics',
    });
  }
}

/** Insert a snapshot with an explicit reporting date and cumulative count. */
function snapshot(ptDate, hourUTC, viewCount) {
  db.insertSnapshot({
    channelId: CHANNEL,
    capturedAt: `${ptDate}T${String(hourUTC).padStart(2, '0')}:00:00.000Z`,
    ptDate,
    viewCount,
    subscriberCount: 1000,
    videoCount: 50,
  });
}

console.log('\nLive view-count checks\n');

const LAST_ANALYTICS = '2026-08-14';

test('derives per-day views by differencing cumulative snapshots', () => {
  reset();
  seedAnalytics(LAST_ANALYTICS);

  // Closing counter each day. Day 15 gained 120k, day 16 gained 95k.
  snapshot('2026-08-14', 23, 10_000_000);
  snapshot('2026-08-15', 23, 10_120_000);
  snapshot('2026-08-16', 23, 10_215_000);

  const { derived } = livecounts.deriveForChannel(CHANNEL);
  const byDate = Object.fromEntries(derived.map((d) => [d.date, d]));

  assert.ok(byDate['2026-08-15'], 'expected a derived row for 2026-08-15');
  assert.strictEqual(byDate['2026-08-15'].views, 120_000);
  assert.strictEqual(byDate['2026-08-16'].views, 95_000);
});

test('does not derive days Analytics has already reported', () => {
  reset();
  seedAnalytics(LAST_ANALYTICS);
  snapshot('2026-08-13', 23, 9_900_000);
  snapshot('2026-08-14', 23, 10_000_000);

  const { derived } = livecounts.deriveForChannel(CHANNEL);
  assert.strictEqual(
    derived.find((d) => d.date <= LAST_ANALYTICS),
    undefined,
    'reported days must never be overwritten by derived ones'
  );
});

test('splits combined views into long-form and Shorts by recent ratio', () => {
  reset();
  seedAnalytics(LAST_ANALYTICS); // 90% long-form
  snapshot('2026-08-14', 23, 10_000_000);
  snapshot('2026-08-15', 23, 10_100_000);

  const { derived } = livecounts.deriveForChannel(CHANNEL);
  const day = derived.find((d) => d.date === '2026-08-15');
  assert.ok(Math.abs(day.splitRatio - 0.9) < 0.001, `ratio was ${day.splitRatio}`);
  assert.strictEqual(day.lfViews, 90_000);
  assert.strictEqual(day.sfViews, 10_000);
});

test('ignores a counter that goes backwards (correction or reset)', () => {
  reset();
  seedAnalytics(LAST_ANALYTICS);
  snapshot('2026-08-14', 23, 10_000_000);
  snapshot('2026-08-15', 23, 9_800_000); // YouTube revised downward

  const { derived } = livecounts.deriveForChannel(CHANNEL);
  assert.strictEqual(
    derived.find((d) => d.date === '2026-08-15'),
    undefined,
    'a negative delta must be discarded, not stored as negative views'
  );
});

test('needs a previous-day baseline before it derives anything', () => {
  reset();
  seedAnalytics(LAST_ANALYTICS);
  snapshot('2026-08-16', 23, 10_215_000); // no 08-15 snapshot to difference

  const { derived } = livecounts.deriveForChannel(CHANNEL);
  assert.strictEqual(derived.length, 0);
});

test('reconciles against Analytics and records the error', () => {
  reset();
  seedAnalytics(LAST_ANALYTICS);
  snapshot('2026-08-14', 23, 10_000_000);
  snapshot('2026-08-15', 23, 10_120_000);
  livecounts.deriveForChannel(CHANNEL);

  assert.strictEqual(db.getChannelLiveDaily(CHANNEL).length, 1, 'one derived day expected');

  // Analytics finally reports 08-15, and it was actually 110k views.
  db.upsertDaily(CHANNEL, '2026-08-15', {
    views: 110_000,
    lf_views: 100_000,
    sf_views: 10_000,
    views_present: 1,
    views_source: 'analytics',
  });

  const results = livecounts.reconcileChannel(CHANNEL);
  assert.strictEqual(results.length, 1);
  assert.strictEqual(results[0].liveViews, 120_000);
  assert.strictEqual(results[0].analyticsViews, 110_000);
  assert.ok(Math.abs(results[0].pctError - 0.0909) < 0.001, `error was ${results[0].pctError}`);
  assert.strictEqual(
    db.getChannelLiveDaily(CHANNEL).length,
    0,
    'the derived row must be dropped once real data arrives'
  );
});

test('merges live days into history without touching reported days', () => {
  reset();
  seedAnalytics(LAST_ANALYTICS);
  snapshot('2026-08-14', 23, 10_000_000);
  snapshot('2026-08-15', 23, 10_120_000);
  livecounts.deriveForChannel(CHANNEL);

  const reported = db.getChannelDaily(CHANNEL, '2026-07-01', '2026-08-20');
  const merged = livecounts.mergeLiveIntoHistory(CHANNEL, reported);

  const liveDay = merged.find((r) => r.date === '2026-08-15');
  assert.ok(liveDay, 'live day should appear in merged history');
  assert.strictEqual(liveDay.views_source, 'live');
  assert.strictEqual(liveDay.views_present, 1);
  assert.strictEqual(liveDay.revenue_present, 0, 'live views must not imply reported revenue');

  const reportedDay = merged.find((r) => r.date === LAST_ANALYTICS);
  assert.strictEqual(reportedDay.views_source, 'analytics', 'reported day must stay reported');
  assert.strictEqual(reportedDay.lf_views, 90_000);
});

test('the estimator produces an estimate once live views exist', () => {
  reset();
  seedAnalytics(LAST_ANALYTICS);
  snapshot('2026-08-14', 23, 10_000_000);
  snapshot('2026-08-15', 23, 10_120_000);
  livecounts.deriveForChannel(CHANNEL);

  const { estimateChannel } = require('../server/estimator');
  const reported = db.getChannelDaily(CHANNEL, '2026-06-01', '2026-08-20');
  const merged = livecounts.mergeLiveIntoHistory(CHANNEL, reported);
  const result = estimateChannel(merged);

  assert.ok(result.estimates.length >= 1, 'expected at least one estimate for the live day');
  const est = result.estimates.find((e) => e.date === '2026-08-15');
  assert.ok(est, 'expected an estimate for 2026-08-15');
  // Seed data is a flat 1000 kr on 90k long-form views -> ~11.11 kr per 1000.
  // 108k long-form live views should land near 1200 kr.
  assert.ok(est.revenue > 900 && est.revenue < 1500, `estimate was ${est.revenue}`);
});

test('converts raw live views to ENGAGED views before the estimator sees them', () => {
  reset();
  // History where Shorts engage at 50% and long-form at 100% — the real shape.
  for (let i = 39; i >= 0; i--) {
    const date = addDays(LAST_ANALYTICS, -i);
    db.upsertDaily(CHANNEL, date, {
      revenue: 1000,
      views: 200000,
      lf_views: 100000,
      sf_views: 100000,
      lf_engaged_views: 100000, // 100%
      sf_engaged_views: 50000, //  50%
      revenue_present: 1,
      views_present: 1,
      views_source: 'analytics',
    });
  }

  const rates = livecounts.recentEngagedRates(CHANNEL, LAST_ANALYTICS);
  assert.ok(Math.abs(rates.lf - 1.0) < 0.01, `lf rate was ${rates.lf}`);
  assert.ok(Math.abs(rates.sf - 0.5) < 0.01, `sf rate was ${rates.sf}`);

  snapshot('2026-08-14', 23, 10_000_000);
  snapshot('2026-08-15', 23, 10_200_000); // 200k raw views
  livecounts.deriveForChannel(CHANNEL);

  const [live] = db.getChannelLiveDaily(CHANNEL).filter((r) => r.date === '2026-08-15');
  assert.ok(live, 'expected a live day');

  // Raw split is 50/50, so engaged should be 100k long-form + 50k Shorts.
  assert.ok(Math.abs(live.lf_engaged_views - 100000) < 2000, `lf engaged ${live.lf_engaged_views}`);
  assert.ok(Math.abs(live.sf_engaged_views - 50000) < 2000, `sf engaged ${live.sf_engaged_views}`);
  assert.ok(
    live.sf_engaged_views < live.sf_views,
    'Shorts engaged views must be below raw views'
  );

  // And the estimator must receive the engaged figures, not the raw ones.
  const merged = livecounts.mergeLiveIntoHistory(
    CHANNEL,
    db.getChannelDaily(CHANNEL, '2026-06-01', '2026-08-20')
  );
  const row = merged.find((r) => r.date === '2026-08-15');
  assert.strictEqual(row.sf_engaged_views, live.sf_engaged_views);
  assert.ok(
    row.sf_engaged_views < row.sf_views,
    'merged history must carry engaged views distinct from raw'
  );
});

test('an inflated raw count does not inflate the estimate', () => {
  reset();
  // Revenue comes only from long-form; Shorts are pure padding at 50% engaged.
  for (let i = 39; i >= 0; i--) {
    const date = addDays(LAST_ANALYTICS, -i);
    db.upsertDaily(CHANNEL, date, {
      revenue: 1000, // 100k long-form engaged @ 10 kr/1000
      views: 300000,
      lf_views: 100000,
      sf_views: 200000,
      lf_engaged_views: 100000,
      sf_engaged_views: 100000,
      revenue_present: 1,
      views_present: 1,
      views_source: 'analytics',
    });
  }
  snapshot('2026-08-14', 23, 10_000_000);
  snapshot('2026-08-15', 23, 10_300_000); // same 300k raw shape as history
  livecounts.deriveForChannel(CHANNEL);

  const { estimateChannel } = require('../server/estimator');
  const merged = livecounts.mergeLiveIntoHistory(
    CHANNEL,
    db.getChannelDaily(CHANNEL, '2026-06-01', '2026-08-20')
  );
  const result = estimateChannel(merged);
  const est = result.estimates.find((e) => e.date === '2026-08-15');
  assert.ok(est, 'expected an estimate');
  // A day identical in shape to history must estimate close to history's 1000 kr.
  // Feeding raw views to an engaged-fitted model would have produced ~1500.
  assert.ok(
    est.revenue > 800 && est.revenue < 1250,
    `estimate was ${est.revenue}, expected ~1000 (raw-view leakage would give ~1500)`
  );
});

test('detects a view-definition regime change and uses the new rate', () => {
  reset();
  // The real August 2026 shape: ~99% engaged until 26 Aug, ~55% from 27 Aug,
  // with raw views nearly doubling at the break.
  // The edge is the newest day Analytics has reported — which is itself the
  // day carrying the change, so it must not be excluded from the rate window.
  const EDGE = '2026-08-27';
  for (let i = 25; i >= 0; i--) {
    const date = addDays(EDGE, -i);
    const newRegime = date >= '2026-08-27';
    const lfViews = newRegime ? 139504 : 75000;
    const lfEngaged = Math.round(lfViews * (newRegime ? 0.552 : 0.992));
    db.upsertDaily(CHANNEL, date, {
      revenue: 2800,
      views: lfViews,
      lf_views: lfViews,
      sf_views: 0,
      lf_engaged_views: lfEngaged,
      sf_engaged_views: 0,
      engaged_views: lfEngaged,
      revenue_present: 1,
      views_present: 1,
      views_source: 'analytics',
    });
  }

  const rates = livecounts.recentEngagedRates(CHANNEL, EDGE);
  assert.strictEqual(rates.regimeBreak, '2026-08-27', `break was ${rates.regimeBreak}`);
  assert.ok(
    Math.abs(rates.lf - 0.552) < 0.02,
    `rate was ${(rates.lf * 100).toFixed(1)}%, expected ~55.2% — a stale trailing average would give ~90%+`
  );
});

console.log(`\n${passed} check(s) passed\n`);

// Clean up the scratch database.
try {
  fs.rmSync(tmpDir, { recursive: true, force: true });
} catch {
  /* best effort */
}
