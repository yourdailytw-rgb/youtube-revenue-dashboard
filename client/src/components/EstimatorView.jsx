import { useEffect, useState } from 'react';
import {
  CartesianGrid,
  Legend,
  Line,
  LineChart,
  ReferenceLine,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts';
import clsx from 'clsx';
import { Zap, Info, ShieldCheck, ChevronDown, Radio } from 'lucide-react';
import { Card, CardHeader, Badge, Stat, EmptyState, Skeleton, ChannelAvatar } from './ui';
import { api } from '../lib/api';
import { formatMoney, formatDate, formatPct, formatNumber } from '../lib/format';
import { channelColor } from '../lib/metrics';

/**
 * Everything the estimator is doing, in the open: what it predicts right now,
 * how those predictions are built, and how it scored against the last ~45 days
 * of real reported revenue.
 *
 * The point of this tab is that nobody has to take the estimate on faith.
 */
export function EstimatorView({ data }) {
  const [detail, setDetail] = useState(null);
  const [live, setLive] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [expanded, setExpanded] = useState(null);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    Promise.all([api.estimates(), api.liveStatus().catch(() => null)])
      .then(([est, liveStatus]) => {
        if (cancelled) return;
        setDetail(est);
        setLive(liveStatus);
      })
      .catch((err) => !cancelled && setError(err.message))
      .finally(() => !cancelled && setLoading(false));
    return () => {
      cancelled = true;
    };
  }, []);

  if (loading) {
    return (
      <div className="space-y-4">
        <Skeleton className="h-32" />
        <Skeleton className="h-64" />
      </div>
    );
  }

  if (error) {
    return (
      <Card>
        <EmptyState title="Could not load estimator details" description={error} />
      </Card>
    );
  }

  const channels = Object.entries(detail || {});
  const totalEstimated = channels.reduce(
    (sum, [, c]) => sum + (c.estimates || []).reduce((a, e) => a + e.revenue, 0),
    0
  );
  const allEstimates = channels.flatMap(([id, c]) =>
    (c.estimates || []).map((e) => ({ ...e, channelId: id, channelTitle: c.channelTitle }))
  );
  const dates = [...new Set(allEstimates.map((e) => e.date))].sort();

  return (
    <div className="space-y-4">
      <Card>
        <CardHeader
          title="Real-time revenue estimate"
          subtitle="YouTube reports revenue ~2 days late. Long-form views are current, so revenue for those days is modelled from each channel's own recent RPM behaviour."
          action={<Zap size={16} className="text-est" />}
        />
        <div className="grid grid-cols-2 gap-4 px-5 pb-4 sm:grid-cols-4">
          <Stat
            label="Total estimated"
            value={formatMoney(totalEstimated)}
            hint={`${dates.length} day${dates.length === 1 ? '' : 's'} filled`}
            tone="est"
          />
          <Stat
            label="Days covered"
            value={dates.length ? `${formatDate(dates[0], 'short')} – ${formatDate(dates[dates.length - 1], 'short')}` : '—'}
            hint="not yet reported by YouTube"
          />
          <Stat
            label="Model accuracy"
            value={
              data?.estimation?.medianAbsPctError != null
                ? `±${(data.estimation.medianAbsPctError * 100).toFixed(1)}%`
                : '—'
            }
            hint="median back-test error"
            tone={data?.estimation?.medianAbsPctError < 0.1 ? 'pos' : undefined}
          />
          <Stat label="Channels modelled" value={String(channels.length)} hint="each fitted separately" />
        </div>
      </Card>

      {live && <LiveFeedPanel live={live} />}

      {dates.length > 0 && (
        <Card className="overflow-hidden">
          <CardHeader title="Current estimates" subtitle="Per channel, per day, with the inputs behind each number" />
          <div className="scroll-x">
            <table className="w-full min-w-[820px] border-collapse text-sm">
              <thead>
                <tr className="border-y border-line bg-surface-2/40 text-[11px] uppercase tracking-wide text-ink-dim">
                  <th className="px-4 py-2 text-left font-medium">Channel</th>
                  <th className="px-3 py-2 text-left font-medium">Date</th>
                  <th className="px-3 py-2 text-right font-medium">Estimate</th>
                  <th className="px-3 py-2 text-right font-medium">Likely range</th>
                  <th className="px-3 py-2 text-right font-medium">Long-form views</th>
                  <th className="px-3 py-2 text-right font-medium">Long-form RPM</th>
                  <th className="px-3 py-2 text-right font-medium">Weekday adj.</th>
                  <th className="px-3 py-2 text-right font-medium">Trend adj.</th>
                  <th className="px-3 py-2 text-right font-medium">Confidence</th>
                </tr>
              </thead>
              <tbody>
                {allEstimates
                  .sort((a, b) => b.date.localeCompare(a.date) || b.revenue - a.revenue)
                  .map((est, i) => (
                    <tr key={`${est.channelId}-${est.date}`} className="border-b border-line-soft hover:bg-surface-2/40">
                      <td className="px-4 py-2.5 font-medium text-ink">{est.channelTitle}</td>
                      <td className="px-3 py-2.5 text-ink-dim">
                        {formatDate(est.date)}
                        {est.isPartialCorrection && (
                          <Badge tone="warn" className="ml-2" title={`YouTube reported ${formatMoney(est.reportedRevenue)} for this day, which looks partial. The dashboard uses the model instead.`}>
                            partial day
                          </Badge>
                        )}
                      </td>
                      <td className="px-3 py-2.5 text-right font-semibold tabular text-est">
                        {formatMoney(est.revenue)}
                      </td>
                      <td className="px-3 py-2.5 text-right tabular text-ink-dim">
                        {formatMoney(est.low, { decimals: 0 })} – {formatMoney(est.high, { decimals: 0 })}
                      </td>
                      <td className="px-3 py-2.5 text-right tabular text-ink-dim">{formatNumber(est.lfViews)}</td>
                      <td className="px-3 py-2.5 text-right tabular text-ink-dim">{formatMoney(est.lfRpm)}</td>
                      <td className="px-3 py-2.5 text-right tabular text-ink-dim">×{est.dowFactor?.toFixed(3)}</td>
                      <td className="px-3 py-2.5 text-right tabular text-ink-dim">×{est.trendFactor?.toFixed(3)}</td>
                      <td className="px-3 py-2.5 text-right">
                        <ConfidenceBar value={est.confidence} />
                      </td>
                    </tr>
                  ))}
              </tbody>
              <tfoot>
                <tr className="border-t border-line bg-surface-2/40 font-semibold">
                  <td className="px-4 py-2.5 text-ink" colSpan={2}>
                    Total estimated revenue
                  </td>
                  <td className="px-3 py-2.5 text-right tabular text-est">{formatMoney(totalEstimated)}</td>
                  <td colSpan={6} />
                </tr>
              </tfoot>
            </table>
          </div>
        </Card>
      )}

      <Card>
        <CardHeader
          title="Back-test — how the model scored against real reported revenue"
          subtitle="Each day is re-predicted using only the data that existed before it, then compared with what YouTube actually paid."
          action={<ShieldCheck size={16} className="text-ink-dim" />}
        />
        <div className="space-y-2 px-4 pb-4">
          {channels.map(([id, channel], index) => {
            const accuracy = channel.accuracy;
            const isOpen = expanded === id;
            return (
              <div key={id} className="overflow-hidden rounded-lg border border-line">
                <button
                  onClick={() => setExpanded(isOpen ? null : id)}
                  className="flex w-full items-center gap-3 bg-surface-2/40 px-3 py-2.5 text-left transition-colors hover:bg-surface-2"
                >
                  <ChannelAvatar
                    channel={{ title: channel.channelTitle }}
                    size={22}
                    index={index}
                    color={channelColor(index)}
                  />
                  <span className="min-w-0 flex-1 truncate text-sm font-medium text-ink">
                    {channel.channelTitle}
                  </span>

                  <span className="hidden gap-5 sm:flex">
                    <MiniStat
                      label="median error"
                      value={accuracy?.medianAbsPctError != null ? `±${(accuracy.medianAbsPctError * 100).toFixed(1)}%` : '—'}
                      good={accuracy?.medianAbsPctError < 0.1}
                    />
                    <MiniStat
                      label="bias"
                      value={accuracy?.bias != null ? formatPct(accuracy.bias, { sign: true }) : '—'}
                    />
                    <MiniStat label="samples" value={accuracy?.samples ?? 0} />
                  </span>

                  <ChevronDown
                    size={15}
                    className={clsx('shrink-0 text-ink-dim transition-transform', isOpen && 'rotate-180')}
                  />
                </button>

                {isOpen && (
                  <div className="border-t border-line p-3">
                    {accuracy?.recent?.length ? (
                      <>
                        <div className="h-[220px]">
                          <ResponsiveContainer width="100%" height="100%">
                            <LineChart
                              data={accuracy.recent.map((e) => ({
                                date: e.date,
                                actual: e.actual,
                                predicted: e.predicted,
                                errorPct: e.pctError,
                              }))}
                              margin={{ top: 8, right: 12, bottom: 4, left: 4 }}
                            >
                              <CartesianGrid stroke="#1c2230" strokeDasharray="3 3" vertical={false} />
                              <XAxis
                                dataKey="date"
                                tickFormatter={(v) => formatDate(v, 'axis')}
                                stroke="#4b5565"
                                tick={{ fontSize: 10, fill: '#7c8497' }}
                                tickLine={false}
                                axisLine={{ stroke: '#1c2230' }}
                              />
                              <YAxis
                                stroke="#4b5565"
                                tick={{ fontSize: 10, fill: '#7c8497' }}
                                tickLine={false}
                                axisLine={false}
                                width={48}
                              />
                              <Tooltip
                                content={({ active, payload, label }) =>
                                  active && payload?.length ? (
                                    <div className="rounded-lg border border-line bg-surface-2 px-2.5 py-2 text-xs shadow-xl">
                                      <p className="mb-1 font-semibold text-ink">{formatDate(label, 'long')}</p>
                                      <div className="flex justify-between gap-4">
                                        <span className="text-ink-dim">Reported</span>
                                        <span className="tabular text-ink">
                                          {formatMoney(payload[0].payload.actual)}
                                        </span>
                                      </div>
                                      <div className="flex justify-between gap-4">
                                        <span className="text-est">Model said</span>
                                        <span className="tabular text-ink">
                                          {formatMoney(payload[0].payload.predicted)}
                                        </span>
                                      </div>
                                      <div className="mt-1 flex justify-between gap-4 border-t border-line pt-1">
                                        <span className="text-ink-dim">Error</span>
                                        <span
                                          className={clsx(
                                            'tabular',
                                            Math.abs(payload[0].payload.errorPct) < 0.1 ? 'text-pos' : 'text-warn'
                                          )}
                                        >
                                          {formatPct(payload[0].payload.errorPct, { sign: true })}
                                        </span>
                                      </div>
                                    </div>
                                  ) : null
                                }
                              />
                              <Legend
                                verticalAlign="top"
                                height={24}
                                iconType="plainline"
                                iconSize={14}
                                wrapperStyle={{ fontSize: 11, color: '#98a1b3' }}
                              />
                              <Line
                                type="monotone"
                                dataKey="actual"
                                name="Reported by YouTube"
                                stroke="#22c55e"
                                strokeWidth={2}
                                dot={{ r: 2 }}
                                isAnimationActive={false}
                              />
                              <Line
                                type="monotone"
                                dataKey="predicted"
                                name="What the model predicted"
                                stroke="#a855f7"
                                strokeWidth={2}
                                strokeDasharray="5 4"
                                dot={{ r: 2 }}
                                isAnimationActive={false}
                              />
                            </LineChart>
                          </ResponsiveContainer>
                        </div>

                        <div className="mt-3 grid grid-cols-2 gap-3 border-t border-line pt-3 sm:grid-cols-4">
                          <Stat
                            label="Median error"
                            value={`±${((accuracy.medianAbsPctError ?? 0) * 100).toFixed(1)}%`}
                          />
                          <Stat label="Mean error (MAPE)" value={`±${((accuracy.mape ?? 0) * 100).toFixed(1)}%`} />
                          <Stat
                            label="Bias"
                            value={formatPct(accuracy.bias ?? 0, { sign: true })}
                            hint={accuracy.bias > 0 ? 'runs slightly high' : 'runs slightly low'}
                          />
                          <Stat label="Days tested" value={String(accuracy.samples ?? 0)} />
                        </div>
                      </>
                    ) : (
                      <p className="py-6 text-center text-xs text-ink-dim">
                        Not enough reported history yet to score this channel.
                      </p>
                    )}
                  </div>
                )}
              </div>
            );
          })}
        </div>
      </Card>

      <Card>
        <CardHeader title="How the estimate is built" action={<Info size={15} className="text-ink-dim" />} />
        <ol className="space-y-2.5 px-5 pb-5 text-[13px] leading-relaxed text-ink-dim">
          {[
            ['Fit RPM per channel', 'Revenue is regressed against long-form and Shorts views separately over the trailing 56 days, weighted so recent days count more (21-day half-life). Shorts and long-form earn very different RPMs, so they get separate coefficients.'],
            ['Correct for the weekday', 'Ad rates move on a weekly cycle. The model measures how each weekday historically over- or under-performs its prediction and applies a damped correction.'],
            ['Correct for the trend', 'If the last 7 days have been running above the last 28, the estimate is nudged up — damped and capped so one loud day cannot run away with it.'],
            ['Publish a range, not just a number', 'The 80% interval comes from the model\'s own back-tested error on that channel, so a noisy channel honestly shows a wider range.'],
            ['Replace with reality', 'The moment YouTube reports a day, the estimate for it is deleted and the real number takes over everywhere — charts, totals and exports.'],
          ].map(([title, body], i) => (
            <li key={title} className="flex gap-3">
              <span className="grid h-5 w-5 shrink-0 place-items-center rounded-full bg-est/15 text-[11px] font-semibold text-est">
                {i + 1}
              </span>
              <span>
                <span className="font-medium text-ink">{title}.</span> {body}
              </span>
            </li>
          ))}
        </ol>
      </Card>
    </div>
  );
}

/**
 * The live view-count feed. The Analytics API reports views and revenue with the
 * same lag, so this is the only source of same-day data — and therefore the only
 * reason a modelled day can exist at all. Its own accuracy is tracked against
 * Analytics and shown here rather than assumed.
 */
function LiveFeedPanel({ live }) {
  const channels = live.channels || [];
  const totalSnapshots = channels.reduce((a, c) => a + (c.snapshots72h || 0), 0);
  const totalLiveDays = channels.reduce((a, c) => a + (c.liveDays?.length || 0), 0);
  const scored = channels.filter((c) => c.medianAbsError !== null && c.medianAbsError !== undefined);
  const headline = scored.length
    ? scored.reduce((a, c) => a + c.medianAbsError, 0) / scored.length
    : null;

  return (
    <Card>
      <CardHeader
        title="Live view feed"
        subtitle="YouTube's Analytics API lags views and revenue equally, so same-day views come from the Data API's cumulative counter instead — snapshotted every 20 minutes and differenced across Pacific-time day boundaries."
        action={<Radio size={16} className={totalSnapshots > 0 ? 'text-pos' : 'text-ink-dim'} />}
      />
      <div className="grid grid-cols-2 gap-4 px-5 pb-4 sm:grid-cols-4">
        <Stat
          label="Snapshots (72h)"
          value={String(totalSnapshots)}
          hint={totalSnapshots === 0 ? 'polling not started yet' : 'across all channels'}
          tone={totalSnapshots > 0 ? 'pos' : undefined}
        />
        <Stat
          label="Days derived live"
          value={String(totalLiveDays)}
          hint="ahead of Analytics"
          tone={totalLiveDays > 0 ? 'est' : undefined}
        />
        <Stat
          label="Live feed accuracy"
          value={headline !== null ? `±${(headline * 100).toFixed(1)}%` : 'not yet scored'}
          hint="vs Analytics once it reports"
          tone={headline !== null && headline < 0.1 ? 'pos' : undefined}
        />
        <Stat
          label="Reporting day"
          value={`${live.ptDate}`}
          hint={`${live.ptHour}:00 Pacific — YouTube's day boundary`}
        />
      </div>

      {totalSnapshots === 0 ? (
        <p className="mx-5 mb-4 rounded-lg border border-warn/30 bg-warn/10 px-3 py-2 text-xs text-warn">
          No snapshots captured yet. The feed needs a closing snapshot on two consecutive days before
          it can derive anything, so the first modelled day appears roughly 24 hours after polling
          starts.
        </p>
      ) : (
        <div className="border-t border-line px-5 py-3">
          <table className="w-full text-xs">
            <thead>
              <tr className="text-[10px] uppercase tracking-wide text-ink-dim">
                <th className="pb-1.5 text-left font-medium">Channel</th>
                <th className="pb-1.5 text-right font-medium">Snapshots</th>
                <th className="pb-1.5 text-right font-medium">Live days</th>
                <th className="pb-1.5 text-right font-medium">Views derived</th>
                <th className="pb-1.5 text-right font-medium">Accuracy</th>
              </tr>
            </thead>
            <tbody>
              {channels.map((c) => (
                <tr key={c.id} className="border-t border-line-soft">
                  <td className="py-1.5 text-ink">{c.title}</td>
                  <td className="py-1.5 text-right tabular text-ink-dim">{c.snapshots72h}</td>
                  <td className="py-1.5 text-right tabular text-ink-dim">{c.liveDays?.length || 0}</td>
                  <td className="py-1.5 text-right tabular text-ink-dim">
                    {c.liveDays?.length
                      ? c.liveDays.map((d) => formatNumber(d.views)).join(', ')
                      : '—'}
                  </td>
                  <td className="py-1.5 text-right tabular">
                    {c.medianAbsError !== null && c.medianAbsError !== undefined ? (
                      <span className={c.medianAbsError < 0.1 ? 'text-pos' : 'text-warn'}>
                        ±{(c.medianAbsError * 100).toFixed(1)}%{' '}
                        <span className="text-ink-dim">({c.accuracySamples})</span>
                      </span>
                    ) : (
                      <span className="text-ink-dim">not yet scored</span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </Card>
  );
}

function MiniStat({ label, value, good }) {
  return (
    <span className="text-right">
      <span className="block text-[10px] uppercase tracking-wide text-ink-dim">{label}</span>
      <span className={clsx('block text-xs font-semibold tabular', good ? 'text-pos' : 'text-ink')}>
        {value}
      </span>
    </span>
  );
}

function ConfidenceBar({ value = 0 }) {
  const pct = Math.round(value * 100);
  const tone = value >= 0.8 ? 'bg-pos' : value >= 0.6 ? 'bg-warn' : 'bg-neg';
  return (
    <span className="inline-flex items-center justify-end gap-2">
      <span className="h-1.5 w-10 overflow-hidden rounded-full bg-line">
        <span className={clsx('block h-full rounded-full', tone)} style={{ width: `${pct}%` }} />
      </span>
      <span className="w-8 text-right text-xs tabular text-ink-dim">{pct}%</span>
    </span>
  );
}
