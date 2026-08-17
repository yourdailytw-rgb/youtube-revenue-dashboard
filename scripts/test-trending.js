/**
 * Spike-detection checks.
 *
 *   node scripts/test-trending.js
 *
 * Builds synthetic per-video snapshot histories and verifies that the detector
 * separates the cases that matter: an old video waking up, a fresh upload
 * climbing, ordinary steady traffic, and small-number noise that must NOT be
 * reported as viral.
 */

const fs = require('fs');
const os = require('os');
const path = require('path');
const assert = require('node:assert');

const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ytdash-trend-'));
process.env.DATA_DIR_OVERRIDE = tmpDir;

const db = require('../server/db');
const trending = require('../server/trending');

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

const CHANNEL = 'UCtrendtest';
db.upsertChannel({ id: CHANNEL, title: 'Trend Test', thumbnail: null });

const HOUR = 3600 * 1000;

/**
 * Create a video plus a snapshot history.
 * `paceByHoursAgo` maps "hours ago" -> views/hour applying up to that point.
 */
function makeVideo({ id, ageDays, lifetimeViews, recentPace, olderPace }) {
  const publishedAt = new Date(Date.now() - ageDays * 24 * HOUR).toISOString();
  db.upsertVideo({
    videoId: id,
    channelId: CHANNEL,
    title: id,
    publishedAt,
    durationSec: 600,
    isShort: false,
    lifetimeViews,
  });

  // Walk backwards 72h, accumulating views at the appropriate pace, then write
  // snapshots forwards so the counter increases monotonically.
  const points = [];
  let cumulative = lifetimeViews;
  for (let h = 0; h <= 72; h += 1) {
    points.push({ hoursAgo: h, views: Math.round(cumulative) });
    const pace = h < 6 ? recentPace : olderPace;
    cumulative -= pace; // going back in time removes views
  }
  for (const p of points.reverse()) {
    db.insertVideoSnapshot({
      videoId: id,
      capturedAt: new Date(Date.now() - p.hoursAgo * HOUR).toISOString(),
      viewCount: p.views,
      likeCount: 0,
      commentCount: 0,
    });
  }
}

console.log('\nSpike-detection checks\n');

// An old video that averaged ~40/h for two years, now doing 1800/h.
makeVideo({ id: 'old-resurgence', ageDays: 730, lifetimeViews: 700000, recentPace: 1800, olderPace: 40 });
// A fresh upload climbing hard.
makeVideo({ id: 'fresh-surge', ageDays: 1, lifetimeViews: 90000, recentPace: 4000, olderPace: 1200 });
// Ordinary steady traffic — same pace throughout.
makeVideo({ id: 'steady', ageDays: 200, lifetimeViews: 480000, recentPace: 100, olderPace: 100 });
// Tiny numbers with a big ratio: 1/h -> 8/h. Must not be called viral.
makeVideo({ id: 'noise', ageDays: 400, lifetimeViews: 9000, recentPace: 8, olderPace: 1 });

const result = trending.detect();
const byId = Object.fromEntries(result.videos.map((v) => [v.videoId, v]));

test('detector reports ready with snapshots present', () => {
  assert.strictEqual(result.ready, true, result.reason || 'expected ready');
});

test('flags an old video waking up as a spike', () => {
  const v = byId['old-resurgence'];
  assert.ok(v, 'old-resurgence should be detected');
  assert.ok(v.spikeRatio > 5, `spike ratio was ${v.spikeRatio?.toFixed(1)}`);
  assert.ok(
    ['breakout', 'resurgence'].includes(v.classification.kind),
    `classified as ${v.classification.kind}`
  );
});

test('classifies a fresh upload as a launch surge, not a resurgence', () => {
  const v = byId['fresh-surge'];
  assert.ok(v, 'fresh-surge should be detected');
  assert.ok(
    ['launch-surge', 'new'].includes(v.classification.kind),
    `classified as ${v.classification.kind}`
  );
});

test('does not flag steady traffic as spiking', () => {
  const v = byId['steady'];
  assert.ok(v, 'steady should still be listed');
  assert.ok(v.spikeRatio < 2, `spike ratio was ${v.spikeRatio?.toFixed(2)}`);
  assert.ok(['steady', 'cooling'].includes(v.classification.kind), `classified as ${v.classification.kind}`);
});

test('excludes small-number noise below the views/hour floor', () => {
  assert.strictEqual(
    byId['noise'],
    undefined,
    'a video doing 8 views/hour must not appear, however large its ratio'
  );
});

test('ranks the biggest real spike above steady traffic', () => {
  const order = result.videos.map((v) => v.videoId);
  assert.ok(
    order.indexOf('old-resurgence') < order.indexOf('steady'),
    `order was ${order.join(', ')}`
  );
});

test('counts summarise the population', () => {
  assert.ok(result.counts.spiking >= 2, `spiking count was ${result.counts.spiking}`);
  assert.ok(result.counts.tracked >= 4);
});

test('reports the baseline it actually used', () => {
  const v = byId['old-resurgence'];
  assert.ok(
    ['72h window', 'lifetime average'].includes(v.baselineSource),
    `baselineSource was ${v.baselineSource}`
  );
});

console.log(`\n${passed} check(s) passed\n`);
console.log('Ranking produced:');
for (const v of result.videos) {
  console.log(
    `  ${v.videoId.padEnd(18)}${v.spikeRatio.toFixed(1).padStart(6)}x  ` +
      `${Math.round(v.recentViewsPerHour).toString().padStart(6)}/h  ` +
      `heat ${v.heat.toFixed(1).padStart(6)}  ${v.classification.label}`
  );
}
console.log('');

try {
  fs.rmSync(tmpDir, { recursive: true, force: true });
} catch {
  /* best effort */
}
