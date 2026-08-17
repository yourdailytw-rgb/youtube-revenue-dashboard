/**
 * Seed the local database with realistic synthetic data.
 *
 *   npm run seed            # 5 channels, ~2.5 years, wipes existing mock rows
 *   npm run seed -- --days 400
 *
 * The generator deliberately includes the things that make estimation hard —
 * weekday RPM swings, seasonal RPM (Q4 high, January slump), growth trends,
 * shorts vs long-form RPM gaps, upload spikes and noise — so the back-test
 * numbers mean something. It also reproduces the 2-day revenue delay by
 * leaving revenue_present = 0 on the most recent days.
 */

const db = require('../server/db');
const { loadTokens, saveTokens } = require('../server/tokens');
const { today, addDays, eachDay, dayOfWeek } = require('../server/util/dates');

const args = process.argv.slice(2);
const getArg = (name, fallback) => {
  const i = args.indexOf(`--${name}`);
  return i !== -1 && args[i + 1] ? args[i + 1] : fallback;
};

const DAYS = Number(getArg('days', 900));
const REVENUE_DELAY_DAYS = Number(getArg('delay', 2));

/** Deterministic PRNG so repeated seeds are comparable. */
function mulberry32(seed) {
  return function random() {
    seed |= 0;
    seed = (seed + 0x6d2b79f5) | 0;
    let t = Math.imul(seed ^ (seed >>> 15), 1 | seed);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

const CHANNELS = [
  {
    id: 'UCmock000000000Supernetic',
    title: 'Supernetic',
    seed: 11,
    baseLfViews: 62000,
    baseSfViews: 0,
    growth: 0.0016,
    lfRpm: 3.1,
    sfRpm: 0.09,
    volatility: 0.28,
  },
  {
    id: 'UCmock000000000BreezyNews',
    title: 'BreezyNews',
    seed: 22,
    baseLfViews: 14000,
    baseSfViews: 210000,
    growth: 0.0022,
    lfRpm: 2.4,
    sfRpm: 0.07,
    volatility: 0.42,
  },
  {
    id: 'UCmock00000000SpideyParker',
    title: 'SpideyParker',
    seed: 33,
    baseLfViews: 38000,
    baseSfViews: 95000,
    growth: 0.0009,
    lfRpm: 2.8,
    sfRpm: 0.11,
    volatility: 0.33,
  },
  {
    id: 'UCmock0000000000000NerdDrop',
    title: 'NerdDrop',
    seed: 44,
    baseLfViews: 21000,
    baseSfViews: 3000,
    growth: 0.0031,
    lfRpm: 4.2,
    sfRpm: 0.1,
    volatility: 0.3,
  },
  {
    id: 'UCmock00000000NerdDropExplains',
    title: 'Nerd Drop Explains',
    seed: 55,
    baseLfViews: 7400,
    baseSfViews: 0,
    growth: 0.0042,
    lfRpm: 4.9,
    sfRpm: 0.1,
    volatility: 0.36,
  },
];

/** Ad rates rise through the week and collapse at the weekend. */
const DOW_RPM = [0.88, 0.96, 1.0, 1.03, 1.06, 1.08, 0.9]; // Sun..Sat
const DOW_VIEWS = [1.08, 0.97, 0.95, 0.96, 0.98, 1.02, 1.06];

/** Advertiser seasonality: Q4 peak, January trough. */
function seasonalRpm(iso) {
  const month = Number(iso.slice(5, 7));
  return [0.72, 0.8, 0.9, 0.95, 1.0, 1.02, 0.98, 0.97, 1.03, 1.1, 1.22, 1.35][month - 1];
}

function generateChannel(channel, dates) {
  const rand = mulberry32(channel.seed);
  const rows = [];

  // Slow random walk so RPM drifts instead of being a fixed constant.
  let rpmDrift = 1;
  let viewMomentum = 1;

  dates.forEach((date, index) => {
    rpmDrift *= 1 + (rand() - 0.5) * 0.012;
    rpmDrift = Math.min(1.35, Math.max(0.72, rpmDrift));
    viewMomentum *= 1 + (rand() - 0.5) * 0.05;
    viewMomentum = Math.min(1.8, Math.max(0.55, viewMomentum));

    const dow = dayOfWeek(date);
    const growth = Math.exp(channel.growth * index);
    const spike = rand() < 0.03 ? 1 + rand() * 2.5 : 1; // an upload goes off

    const noise = () => 1 + (rand() - 0.5) * channel.volatility;

    const lfViews = Math.round(
      channel.baseLfViews * growth * viewMomentum * DOW_VIEWS[dow] * spike * noise()
    );
    const sfViews = Math.round(
      channel.baseSfViews * growth * viewMomentum * DOW_VIEWS[dow] * (rand() < 0.05 ? 3 : 1) * noise()
    );

    const rpmFactor = DOW_RPM[dow] * seasonalRpm(date) * rpmDrift;
    const lfRpm = channel.lfRpm * rpmFactor * (1 + (rand() - 0.5) * 0.1);
    const sfRpm = channel.sfRpm * rpmFactor * (1 + (rand() - 0.5) * 0.15);

    const revenue = (lfViews / 1000) * lfRpm + (sfViews / 1000) * sfRpm;
    const views = lfViews + sfViews;
    const lfMinutes = (lfViews * (6.5 + rand() * 3)) / 1;
    const sfMinutes = (sfViews * (0.35 + rand() * 0.25)) / 1;

    rows.push({
      channelId: channel.id,
      date,
      values: {
        revenue: round2(revenue),
        ad_revenue: round2(revenue * 0.88),
        red_revenue: round2(revenue * 0.12),
        gross_revenue: round2(revenue * 1.45),
        cpm: round2(lfRpm * 1.9),
        playback_cpm: round2(lfRpm * 2.2),
        monetized_playbacks: Math.round(lfViews * 0.62),
        ad_impressions: Math.round(lfViews * 1.35),
        views,
        lf_views: lfViews,
        sf_views: sfViews,
        watch_minutes: Math.round(lfMinutes + sfMinutes),
        lf_watch_minutes: Math.round(lfMinutes),
        sf_watch_minutes: Math.round(sfMinutes),
        avg_view_duration: views ? Math.round(((lfMinutes + sfMinutes) * 60) / views) : 0,
        subs_gained: Math.round(views * 0.0022 * (0.6 + rand())),
        subs_lost: Math.round(views * 0.0004 * (0.6 + rand())),
        likes: Math.round(views * 0.031 * (0.7 + rand() * 0.6)),
        comments: Math.round(views * 0.0021 * (0.6 + rand())),
        shares: Math.round(views * 0.0013 * (0.6 + rand())),
        revenue_present: 1,
        views_present: 1,
      },
    });
  });

  return rows;
}

const round2 = (v) => Math.round(v * 100) / 100;

function main() {
  const end = today();
  const start = addDays(end, -(DAYS - 1));
  const dates = eachDay(start, end);

  console.log(`Seeding ${CHANNELS.length} channels × ${dates.length} days (${start} → ${end})`);

  for (const channel of CHANNELS) {
    db.upsertChannel({
      id: channel.id,
      title: channel.title,
      thumbnail: null,
      connectedAt: new Date().toISOString(),
    });

    const rows = generateChannel(channel, dates);

    // Reproduce YouTube's revenue delay: the most recent days have views but
    // no revenue yet. That is exactly the gap the estimator has to fill.
    const cutoff = addDays(end, -REVENUE_DELAY_DAYS);
    for (const row of rows) {
      if (row.date > cutoff) {
        row.values.revenue = null;
        row.values.ad_revenue = null;
        row.values.red_revenue = null;
        row.values.gross_revenue = null;
        row.values.cpm = null;
        row.values.playback_cpm = null;
        row.values.monetized_playbacks = null;
        row.values.ad_impressions = null;
        row.values.revenue_present = 0;
      }
    }

    db.upsertDailyBatch(rows);
    db.setState(`backfill:${channel.id}`, start);
    db.setState(`lastSync:${channel.id}`, new Date().toISOString());
    console.log(`  ${channel.title.padEnd(20)} ${rows.length} days`);
  }

  // Register the mock channels as "connected" so the API and UI surface them.
  // The `mock: true` flag stops the token refresher and the sync engine from
  // trying to talk to Google on their behalf.
  const allTokens = loadTokens();
  for (const channel of CHANNELS) {
    allTokens[channel.id] = {
      tokens: {},
      channelTitle: channel.title,
      channelThumbnail: null,
      connectedAt: new Date().toISOString(),
      mock: true,
    };
  }
  saveTokens(allTokens);

  db.setState('lastSync', {
    at: new Date().toISOString(),
    channels: CHANNELS.length,
    failed: 0,
    mock: true,
  });

  const { recomputeAllEstimates } = require('../server/sync');
  recomputeAllEstimates();

  console.log('\nDone.', JSON.stringify(db.stats(), null, 2));
  console.log('\nRun `npm run backtest` to score the estimator against this data.');
}

main();
