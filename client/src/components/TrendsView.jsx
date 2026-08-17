import { useMemo } from 'react';
import {
  Area,
  Bar,
  CartesianGrid,
  Cell,
  ComposedChart,
  Legend,
  Line,
  ReferenceLine,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts';
import { Target, CalendarDays, Activity } from 'lucide-react';
import { Card, CardHeader, Stat, Delta } from './ui';
import { formatMoney, formatMoneyShort, formatDate, formatMonth, formatPct } from '../lib/format';

/**
 * Trends: rolling averages to strip out weekday noise, a month-end projection,
 * and the weekday revenue profile the estimator relies on.
 */
export function TrendsView({ data }) {
  const forecast = data?.forecast;

  const trendData = useMemo(() => {
    if (!data) return [];
    const roll7 = new Map(data.rolling.revenue7.map((r) => [r.date, r.value]));
    const roll28 = new Map(data.rolling.revenue28.map((r) => [r.date, r.value]));
    return data.series.totals.map((d) => ({
      date: d.date,
      actual: d.effectiveRevenue,
      avg7: roll7.get(d.date) ?? null,
      avg28: roll28.get(d.date) ?? null,
      isEstimated: d.isEstimated,
    }));
  }, [data]);

  const weekdayProfile = useMemo(() => {
    if (!data) return [];
    const names = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'];
    const buckets = names.map((name) => ({ name, total: 0, count: 0 }));
    for (const day of data.series.totals) {
      if (!day.hasRevenue && !day.isEstimated) continue;
      const jsDay = new Date(`${day.date}T00:00:00Z`).getUTCDay();
      const index = (jsDay + 6) % 7; // Monday-first
      buckets[index].total += day.effectiveRevenue;
      buckets[index].count += 1;
    }
    const withAvg = buckets.map((b) => ({ ...b, avg: b.count ? b.total / b.count : 0 }));
    const overall = withAvg.reduce((a, b) => a + b.avg, 0) / (withAvg.filter((b) => b.avg > 0).length || 1);
    return withAvg.map((b) => ({ ...b, index: overall ? b.avg / overall - 1 : 0 }));
  }, [data]);

  if (!data) return null;

  return (
    <div className="space-y-4">
      {forecast && (
        <Card>
          <CardHeader
            title={`${formatMonth(forecast.month)} projection`}
            subtitle={`${forecast.daysElapsed} days in, ${forecast.daysRemaining} to go`}
            action={<Target size={15} className="text-ink-dim" />}
          />
          <div className="grid grid-cols-2 gap-4 px-5 pb-4 sm:grid-cols-4">
            <Stat label="Month to date" value={formatMoney(forecast.mtdRevenue, { decimals: 0 })} />
            <Stat
              label="Projected total"
              value={formatMoney(forecast.projectedRevenue, { decimals: 0 })}
              hint={`at ${formatMoney(forecast.trailingDailyAverage, { decimals: 0 })}/day`}
              tone="est"
            />
            <div>
              <p className="text-[11px] uppercase tracking-wide text-ink-dim">vs last month, same point</p>
              <div className="mt-0.5 flex items-baseline gap-2">
                <span className="text-sm font-semibold tabular text-ink">
                  {formatMoney(forecast.lastMonthToDate, { decimals: 0 })}
                </span>
                <Delta value={forecast.vsLastMonthToDatePct} />
              </div>
            </div>
            <div>
              <p className="text-[11px] uppercase tracking-wide text-ink-dim">vs last month, full</p>
              <div className="mt-0.5 flex items-baseline gap-2">
                <span className="text-sm font-semibold tabular text-ink">
                  {formatMoney(forecast.lastMonthTotal, { decimals: 0 })}
                </span>
                <Delta value={forecast.vsLastMonthTotalPct} />
              </div>
            </div>
          </div>
          <div className="border-t border-line px-5 py-3">
            <div className="h-2.5 w-full overflow-hidden rounded-full bg-line">
              <div className="flex h-full">
                <div
                  className="h-full bg-accent"
                  style={{
                    width: `${Math.min(100, (forecast.mtdRevenue / Math.max(forecast.projectedRevenue, 1)) * 100)}%`,
                  }}
                />
                <div
                  className="est-pattern h-full"
                  style={{
                    width: `${Math.max(0, 100 - (forecast.mtdRevenue / Math.max(forecast.projectedRevenue, 1)) * 100)}%`,
                  }}
                />
              </div>
            </div>
            <div className="mt-1.5 flex justify-between text-[11px] text-ink-dim">
              <span>Earned so far</span>
              <span>Projected remainder</span>
            </div>
          </div>
        </Card>
      )}

      <Card>
        <CardHeader
          title="Trend"
          subtitle="Daily revenue with 7-day and 28-day rolling averages"
          action={<Activity size={15} className="text-ink-dim" />}
        />
        <div className="h-[320px] px-2 pb-3">
          <ResponsiveContainer width="100%" height="100%">
            <ComposedChart data={trendData} margin={{ top: 8, right: 12, bottom: 4, left: 4 }}>
              <defs>
                <linearGradient id="trendFill" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor="#3b82f6" stopOpacity={0.22} />
                  <stop offset="100%" stopColor="#3b82f6" stopOpacity={0.01} />
                </linearGradient>
              </defs>
              <CartesianGrid stroke="#1c2230" strokeDasharray="3 3" vertical={false} />
              <XAxis
                dataKey="date"
                tickFormatter={(v) => formatDate(v, 'axis')}
                stroke="#4b5565"
                tick={{ fontSize: 11, fill: '#7c8497' }}
                tickLine={false}
                axisLine={{ stroke: '#1c2230' }}
                minTickGap={30}
              />
              <YAxis
                tickFormatter={formatMoneyShort}
                stroke="#4b5565"
                tick={{ fontSize: 11, fill: '#7c8497' }}
                tickLine={false}
                axisLine={false}
                width={52}
              />
              <Tooltip
                cursor={{ stroke: '#2f3747' }}
                content={({ active, payload, label }) =>
                  active && payload?.length ? (
                    <div className="rounded-lg border border-line bg-surface-2 px-2.5 py-2 text-xs shadow-xl">
                      <p className="mb-1 font-semibold text-ink">{formatDate(label, 'long')}</p>
                      {payload.map((p) => (
                        <div key={p.dataKey} className="flex justify-between gap-4">
                          <span style={{ color: p.color || p.stroke }}>{p.name}</span>
                          <span className="tabular text-ink">{formatMoney(p.value)}</span>
                        </div>
                      ))}
                    </div>
                  ) : null
                }
              />
              <Legend
                verticalAlign="top"
                height={26}
                iconType="plainline"
                iconSize={14}
                wrapperStyle={{ fontSize: 11, color: '#98a1b3' }}
              />
              <Area
                type="monotone"
                dataKey="actual"
                name="Daily"
                stroke="#3b82f6"
                strokeWidth={1}
                fill="url(#trendFill)"
                dot={false}
                isAnimationActive={false}
              />
              <Line
                type="monotone"
                dataKey="avg7"
                name="7-day avg"
                stroke="#22c55e"
                strokeWidth={2}
                dot={false}
                isAnimationActive={false}
              />
              <Line
                type="monotone"
                dataKey="avg28"
                name="28-day avg"
                stroke="#f59e0b"
                strokeWidth={2}
                strokeDasharray="5 4"
                dot={false}
                isAnimationActive={false}
              />
            </ComposedChart>
          </ResponsiveContainer>
        </div>
      </Card>

      <Card>
        <CardHeader
          title="Weekday profile"
          subtitle="How each weekday performs against the period average — the same signal the estimator corrects for"
          action={<CalendarDays size={15} className="text-ink-dim" />}
        />
        <div className="h-[220px] px-2 pb-3">
          <ResponsiveContainer width="100%" height="100%">
            <ComposedChart data={weekdayProfile} margin={{ top: 8, right: 12, bottom: 4, left: 4 }}>
              <CartesianGrid stroke="#1c2230" strokeDasharray="3 3" vertical={false} />
              <XAxis
                dataKey="name"
                stroke="#4b5565"
                tick={{ fontSize: 11, fill: '#7c8497' }}
                tickLine={false}
                axisLine={{ stroke: '#1c2230' }}
              />
              <YAxis
                tickFormatter={(v) => formatPct(v, { decimals: 0, sign: true })}
                stroke="#4b5565"
                tick={{ fontSize: 11, fill: '#7c8497' }}
                tickLine={false}
                axisLine={false}
                width={46}
              />
              <ReferenceLine y={0} stroke="#2f3747" />
              <Tooltip
                cursor={{ fill: 'rgba(255,255,255,0.03)' }}
                content={({ active, payload }) =>
                  active && payload?.length ? (
                    <div className="rounded-lg border border-line bg-surface-2 px-2.5 py-2 text-xs shadow-xl">
                      <p className="font-semibold text-ink">{payload[0].payload.name}</p>
                      <p className="tabular text-ink-dim">
                        avg {formatMoney(payload[0].payload.avg, { decimals: 0 })}
                      </p>
                      <p className="tabular text-ink-dim">
                        {formatPct(payload[0].payload.index, { sign: true })} vs average
                      </p>
                    </div>
                  ) : null
                }
              />
              <Bar dataKey="index" name="vs average" radius={[3, 3, 0, 0]} isAnimationActive={false}>
                {weekdayProfile.map((d) => (
                  <Cell key={d.name} fill={d.index >= 0 ? '#22c55e' : '#ef4444'} />
                ))}
              </Bar>
            </ComposedChart>
          </ResponsiveContainer>
        </div>
      </Card>
    </div>
  );
}
