/**
 * Score the revenue estimator against whatever history is in the database.
 *
 *   npm run backtest
 *   npm run backtest -- --days 90
 *
 * For each channel it walks forward day by day, re-estimating each day using
 * ONLY the data that existed before it, then compares against what YouTube
 * actually reported. This is the honest measure of how much to trust the
 * "estimated" numbers on the dashboard.
 */

const db = require('../server/db');
const { estimateChannel, backtest, DEFAULTS } = require('../server/estimator');
const { today, addDays } = require('../server/util/dates');

const args = process.argv.slice(2);
const getArg = (name, fallback) => {
  const i = args.indexOf(`--${name}`);
  return i !== -1 && args[i + 1] ? Number(args[i + 1]) : fallback;
};

const BACKTEST_DAYS = getArg('days', 60);

const pct = (v) => (v === null || v === undefined ? '   n/a' : `${(v * 100).toFixed(1)}%`.padStart(6));
const money = (v) => (v === null || v === undefined ? 'n/a' : v.toFixed(2).padStart(10));

function main() {
  const channels = db.listChannels();
  if (channels.length === 0) {
    console.log('No channels in the database. Run `npm run seed` or connect a channel first.');
    return;
  }

  console.log(`\nRevenue estimator back-test — last ${BACKTEST_DAYS} complete days per channel\n`);
  console.log(
    'channel'.padEnd(22) +
      'samples'.padStart(8) +
      'median err'.padStart(12) +
      'MAPE'.padStart(9) +
      'bias'.padStart(9) +
      'sigma'.padStart(9) +
      '  model'
  );
  console.log('─'.repeat(84));

  const overall = [];

  for (const channel of channels) {
    const history = db.getChannelDaily(channel.id, addDays(today(), -400), today());
    if (history.length < 20) {
      console.log(`${channel.title.padEnd(22)}  (not enough history: ${history.length} days)`);
      continue;
    }

    const score = backtest(history, { ...DEFAULTS, backtestDays: BACKTEST_DAYS });
    const live = estimateChannel(history);
    const method = live.estimates[0]?.method || '—';

    console.log(
      channel.title.slice(0, 21).padEnd(22) +
        String(score.samples).padStart(8) +
        pct(score.medianAbsPctError).padStart(12) +
        pct(score.mape).padStart(9) +
        pct(score.bias).padStart(9) +
        pct(score.sigma).padStart(9) +
        `  ${method}`
    );

    if (score.samples) overall.push(score);
  }

  if (overall.length) {
    const avg = (key) => overall.reduce((a, s) => a + (s[key] ?? 0), 0) / overall.length;
    console.log('─'.repeat(84));
    console.log(
      'AVERAGE'.padEnd(22) +
        ''.padStart(8) +
        pct(avg('medianAbsPctError')).padStart(12) +
        pct(avg('mape')).padStart(9) +
        pct(avg('bias')).padStart(9) +
        pct(avg('sigma')).padStart(9)
    );
  }

  // Show what the model is currently predicting for the missing days.
  console.log('\nLive estimates for days YouTube has not reported yet:\n');
  console.log(
    'channel'.padEnd(22) + 'date'.padEnd(12) + 'estimate'.padStart(11) + 'low'.padStart(11) + 'high'.padStart(11) + '  conf'
  );
  console.log('─'.repeat(84));

  let totalEstimate = 0;
  for (const channel of channels) {
    const history = db.getChannelDaily(channel.id, addDays(today(), -400), today());
    if (!history.length) continue;
    const result = estimateChannel(history);
    for (const est of result.estimates) {
      totalEstimate += est.revenue;
      console.log(
        channel.title.slice(0, 21).padEnd(22) +
          est.date.padEnd(12) +
          money(est.revenue) +
          money(est.low) +
          money(est.high) +
          `   ${est.confidence}`
      );
    }
    if (!result.estimates.length) {
      console.log(`${channel.title.slice(0, 21).padEnd(22)}(nothing missing — revenue is current)`);
    }
  }
  console.log('─'.repeat(84));
  console.log(`${'TOTAL ESTIMATED'.padEnd(34)}${money(totalEstimate)}\n`);
}

main();
