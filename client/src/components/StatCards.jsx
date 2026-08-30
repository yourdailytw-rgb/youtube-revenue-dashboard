import { Area, AreaChart, ResponsiveContainer, YAxis } from 'recharts';
import clsx from 'clsx';
import { Zap } from 'lucide-react';
import { Card, Delta, Badge } from './ui';
import { METRICS, HEADLINE_METRICS } from '../lib/metrics';
import { formatMoney, formatDate } from '../lib/format';

/**
 * Headline cards. Each shows the period total, the change against the
 * comparison period, and a sparkline of the period itself. The revenue card
 * additionally breaks out how much of the total is modelled rather than
 * reported.
 */
export function StatCards({ data, loading, compareLabel }) {
  if (loading || !data) {
    return (
      <div className="grid grid-cols-2 gap-2.5 sm:gap-3 lg:grid-cols-4">
        {[0, 1, 2, 3].map((i) => (
          <Card key={i} className="h-[104px] skeleton border-line" />
        ))}
      </div>
    );
  }

  const { summary, comparison } = data;

  return (
    <div className="grid grid-cols-2 gap-2.5 sm:gap-3 lg:grid-cols-4">
      {HEADLINE_METRICS.map((id) => {
        const metric = METRICS[id];
        const value = summary[metric.summaryKey];
        const delta = comparison?.deltas?.[metric.deltaKey]?.pct ?? null;
        const spark = data.series.totals.map((d) => ({ v: d[metric.dayKey] || 0 }));

        return (
          <Card key={id} className="relative overflow-hidden p-3 sm:p-4">
            <div className="flex items-start justify-between gap-2">
              <p className="text-[11px] font-medium uppercase tracking-wide text-ink-dim">
                {metric.label}
              </p>
              {id === 'revenue' && summary.estimatedRevenue > 0 && (
                <Badge
                  tone="est"
                  title={`${formatMoney(summary.estimatedRevenue)} of this total is modelled, covering ${summary.estimatedDays} day(s) YouTube has not reported yet.`}
                >
                  <Zap size={10} />
                  incl. est.
                </Badge>
              )}
            </div>

            <p className="mt-1.5 truncate text-xl font-semibold tracking-tight tabular sm:text-2xl">
              {metric.format(value)}
            </p>

            <div className="mt-1.5 flex items-center gap-2">
              <Delta value={delta} />
              {compareLabel && <span className="text-[11px] text-ink-dim">vs {compareLabel}</span>}
            </div>

            <div className="pointer-events-none absolute bottom-0 right-0 h-10 w-2/3 opacity-40">
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={spark} margin={{ top: 4, right: 0, bottom: 0, left: 0 }}>
                  {/* Without an explicit domain Recharts anchors at 0, which
                      flattens a high-baseline series into a solid block. */}
                  <YAxis hide domain={['dataMin', 'dataMax']} />
                  <defs>
                    <linearGradient id={`spark-${id}`} x1="0" y1="0" x2="0" y2="1">
                      <stop offset="0%" stopColor={metric.color} stopOpacity={0.5} />
                      <stop offset="100%" stopColor={metric.color} stopOpacity={0} />
                    </linearGradient>
                  </defs>
                  <Area
                    type="monotone"
                    dataKey="v"
                    stroke={metric.color}
                    strokeWidth={1.5}
                    fill={`url(#spark-${id})`}
                    isAnimationActive={false}
                    dot={false}
                  />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          </Card>
        );
      })}
    </div>
  );
}

/** Secondary row: today/yesterday snapshot, averages and estimator accuracy. */
export function QuickStats({ data }) {
  if (!data) return null;
  const { series, summary, estimation, forecast } = data;

  // Only days that actually have revenue data — the trailing days YouTube has
  // not published are not zero-revenue days, and showing them as "0 kr" was
  // both wrong and alarming.
  const days = series.totals.filter((d) => d.hasRevenueData);
  const last = days[days.length - 1];
  const prev = days[days.length - 2];
  const best = summary.bestDay;
  const awaiting = summary.daysAwaitingData || 0;

  const accuracy = estimation?.medianAbsPctError;

  const items = [
    {
      // Money YouTube has actually reported. No modelling in this number.
      label: 'Confirmed revenue',
      value: formatMoney(summary.revenue),
      hint: estimation?.lastRevenueDate
        ? `reported through ${formatDate(estimation.lastRevenueDate, 'short')}`
        : 'reported by YouTube',
      tone: 'pos',
    },
    {
      // Modelled fill for the days YouTube has not reported yet.
      label: 'Estimated on top',
      value: summary.estimatedRevenue > 0 ? `+ ${formatMoney(summary.estimatedRevenue)}` : '—',
      hint:
        summary.estimatedDays > 0
          ? `${summary.estimatedDays} day${summary.estimatedDays === 1 ? '' : 's'} modelled`
          : 'nothing pending',
      tone: summary.estimatedRevenue > 0 ? 'est' : undefined,
    },
    {
      label: 'Total (incl. estimate)',
      value: formatMoney(summary.effectiveRevenue),
      hint: `${summary.daysComplete ?? summary.days} complete days`,
    },
    {
      label: last?.livePartial ? 'Today so far (est.)' : 'Latest day',
      value: formatMoney(last?.effectiveRevenue ?? 0),
      hint: last
        ? last.livePartial && last.liveCoveredHours
          ? `${formatDate(last.date, 'short')} · ${last.liveCoveredHours.toFixed(1)}h measured`
          : formatDate(last.date, 'short')
        : '—',
      tone: last?.isEstimated ? 'est' : undefined,
    },
    {
      label: 'Daily average',
      value: formatMoney(summary.dailyAverage),
      hint: `over ${summary.daysComplete ?? summary.daysWithData ?? summary.days} complete days`,
    },
    {
      label: 'Projected this month',
      value: forecast ? formatMoney(forecast.projectedRevenue, { decimals: 0 }) : '—',
      hint: forecast ? `${forecast.daysRemaining} days left` : '—',
    },
  ];

  return (
    <Card className="grid grid-cols-2 gap-px bg-line sm:grid-cols-3 lg:grid-cols-6">
      {items.map((item) => (
        <div key={item.label} className="bg-surface px-3 py-2.5 sm:px-4 sm:py-3">
          <p className="truncate text-[11px] uppercase tracking-wide text-ink-dim">{item.label}</p>
          <p
            className={clsx(
              'mt-0.5 truncate text-sm font-semibold tabular',
              item.tone === 'est' && 'text-est',
              item.tone === 'pos' && 'text-pos',
              !item.tone && 'text-ink'
            )}
          >
            {item.value}
          </p>
          <p className="truncate text-[11px] text-ink-dim">{item.hint}</p>
        </div>
      ))}
    </Card>
  );
}
