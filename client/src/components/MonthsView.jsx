import { useMemo } from 'react';
import { Bar, BarChart, CartesianGrid, Cell, Legend, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts';
import clsx from 'clsx';
import { Card, CardHeader, Delta, EmptyState, Badge } from './ui';
import { formatMoney, formatMoneyShort, formatMonth, formatNumber, formatPct } from '../lib/format';

/**
 * Month-by-month view: a year × month revenue grid (heat-shaded so a strong
 * month is visible at a glance), a year-over-year bar comparison, and a table
 * with month-over-month and year-over-year deltas.
 */
export function MonthsView({ data, onPickMonth }) {
  const months = data?.monthly || [];

  const { years, byYear, max } = useMemo(() => {
    const map = new Map();
    let peak = 0;
    for (const m of months) {
      const [y, mo] = m.month.split('-').map(Number);
      if (!map.has(y)) map.set(y, {});
      map.get(y)[mo] = m;
      if (m.revenue > peak) peak = m.revenue;
    }
    return {
      years: [...map.keys()].sort((a, b) => b - a),
      byYear: map,
      max: peak,
    };
  }, [months]);

  if (!months.length) {
    return (
      <Card>
        <EmptyState title="No monthly data yet" description="Run a sync to backfill history." />
      </Card>
    );
  }

  const yoyData = buildYoYSeries(months);

  return (
    <div className="space-y-4">
      <Card className="overflow-hidden">
        <CardHeader
          title="Revenue by month"
          subtitle="Click any month to load it as the active date range"
          action={
            <div className="flex items-center gap-2 text-[11px] text-ink-dim">
              <span>low</span>
              <span className="h-2 w-24 rounded-full bg-gradient-to-r from-accent/15 to-accent" />
              <span>high</span>
            </div>
          }
        />
        <div className="overflow-x-auto px-4 pb-4">
          <table className="w-full min-w-[720px] border-separate border-spacing-1">
            <thead>
              <tr className="text-[11px] uppercase tracking-wide text-ink-dim">
                <th className="w-12 px-1 py-1 text-left font-medium">Year</th>
                {['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'].map(
                  (m) => (
                    <th key={m} className="px-1 py-1 text-center font-medium">
                      {m}
                    </th>
                  )
                )}
                <th className="px-1 py-1 text-right font-medium">Total</th>
              </tr>
            </thead>
            <tbody>
              {years.map((year) => {
                const row = byYear.get(year);
                const total = Object.values(row).reduce((a, m) => a + m.revenue, 0);
                return (
                  <tr key={year}>
                    <td className="px-1 text-xs font-semibold text-ink-dim">{year}</td>
                    {Array.from({ length: 12 }, (_, i) => i + 1).map((mo) => {
                      const cell = row[mo];
                      if (!cell) {
                        return (
                          <td key={mo}>
                            <div className="h-12 rounded-md border border-line-soft bg-surface-2/30" />
                          </td>
                        );
                      }
                      const intensity = max > 0 ? cell.revenue / max : 0;
                      return (
                        <td key={mo}>
                          <button
                            onClick={() => onPickMonth?.(cell.month)}
                            title={`${formatMonth(cell.month)} — ${formatMoney(cell.revenue)}${
                              cell.yoyPct !== null ? ` (${formatPct(cell.yoyPct, { sign: true })} YoY)` : ''
                            }`}
                            className="group relative h-12 w-full rounded-md border border-line-soft transition-transform hover:scale-[1.04] hover:border-accent/60"
                            style={{
                              background: `rgba(59,130,246,${0.08 + intensity * 0.55})`,
                            }}
                          >
                            <span className="block truncate px-1 text-[11px] font-semibold tabular text-ink">
                              {formatMoneyShort(cell.revenue)}
                            </span>
                            {cell.yoyPct !== null && (
                              <span
                                className={clsx(
                                  'block text-[9px] tabular',
                                  cell.yoyPct >= 0 ? 'text-pos' : 'text-neg'
                                )}
                              >
                                {formatPct(cell.yoyPct, { decimals: 0, sign: true })}
                              </span>
                            )}
                            {cell.isPartial && (
                              <span className="absolute right-0.5 top-0.5 h-1.5 w-1.5 rounded-full bg-warn" />
                            )}
                          </button>
                        </td>
                      );
                    })}
                    <td className="px-1 text-right text-xs font-semibold tabular text-ink">
                      {formatMoneyShort(total)}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
          <p className="mt-2 text-[11px] text-ink-dim">
            <span className="mr-1 inline-block h-1.5 w-1.5 rounded-full bg-warn align-middle" />
            Month still in progress · percentages compare with the same month last year
          </p>
        </div>
      </Card>

      {yoyData.length > 0 && (
        <Card>
          <CardHeader title="This year vs last year" subtitle="Monthly revenue, same months compared" />
          <div className="h-[260px] px-2 pb-3">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={yoyData} margin={{ top: 8, right: 12, bottom: 4, left: 4 }}>
                <CartesianGrid stroke="#1c2230" strokeDasharray="3 3" vertical={false} />
                <XAxis
                  dataKey="label"
                  stroke="#4b5565"
                  tick={{ fontSize: 11, fill: '#7c8497' }}
                  tickLine={false}
                  axisLine={{ stroke: '#1c2230' }}
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
                  cursor={{ fill: 'rgba(255,255,255,0.03)' }}
                  content={({ active, payload, label }) =>
                    active && payload?.length ? (
                      <div className="rounded-lg border border-line bg-surface-2 px-2.5 py-2 text-xs shadow-xl">
                        <p className="mb-1 font-semibold text-ink">{label}</p>
                        {payload.map((p) => (
                          <div key={p.dataKey} className="flex justify-between gap-4">
                            <span style={{ color: p.fill }}>{p.name}</span>
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
                  iconType="circle"
                  iconSize={7}
                  wrapperStyle={{ fontSize: 11, color: '#98a1b3' }}
                />
                <Bar dataKey="previous" name="Last year" fill="#3a4459" radius={[3, 3, 0, 0]} isAnimationActive={false} />
                <Bar dataKey="current" name="This year" fill="#3b82f6" radius={[3, 3, 0, 0]} isAnimationActive={false} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </Card>
      )}

      <Card className="overflow-hidden">
        <CardHeader title="Monthly detail" />
        <div className="overflow-x-auto">
          <table className="w-full min-w-[760px] border-collapse text-sm">
            <thead>
              <tr className="border-y border-line bg-surface-2/40 text-[11px] uppercase tracking-wide text-ink-dim">
                <th className="px-4 py-2 text-left font-medium">Month</th>
                <th className="px-3 py-2 text-right font-medium">Revenue</th>
                <th className="px-3 py-2 text-right font-medium">vs prev month</th>
                <th className="px-3 py-2 text-right font-medium">vs last year</th>
                <th className="px-3 py-2 text-right font-medium">Views</th>
                <th className="px-3 py-2 text-right font-medium">Long-form</th>
                <th className="px-3 py-2 text-right font-medium">RPM</th>
                <th className="px-3 py-2 text-right font-medium">Daily avg</th>
              </tr>
            </thead>
            <tbody>
              {[...months].reverse().map((m) => (
                <tr
                  key={m.month}
                  onClick={() => onPickMonth?.(m.month)}
                  className="cursor-pointer border-b border-line-soft transition-colors hover:bg-surface-2/40"
                >
                  <td className="px-4 py-2.5">
                    <span className="font-medium text-ink">{formatMonth(m.month)}</span>
                    {m.isPartial && (
                      <Badge tone="warn" className="ml-2">
                        in progress
                      </Badge>
                    )}
                    {m.estimatedRevenue > 0 && (
                      <Badge tone="est" className="ml-2">
                        incl. est.
                      </Badge>
                    )}
                  </td>
                  <td className="px-3 py-2.5 text-right font-medium tabular text-ink">
                    {formatMoney(m.revenue)}
                  </td>
                  <td className="px-3 py-2.5 text-right">
                    <Delta value={m.momPct} showIcon={false} />
                  </td>
                  <td className="px-3 py-2.5 text-right">
                    <Delta value={m.yoyPct} showIcon={false} />
                  </td>
                  <td className="px-3 py-2.5 text-right tabular text-ink-dim">{formatNumber(m.views)}</td>
                  <td className="px-3 py-2.5 text-right tabular text-ink-dim">{formatNumber(m.lfViews)}</td>
                  <td className="px-3 py-2.5 text-right tabular text-ink-dim">{formatMoney(m.rpm)}</td>
                  <td className="px-3 py-2.5 text-right tabular text-ink-dim">
                    {formatMoney(m.dailyAverage, { decimals: 0 })}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Card>
    </div>
  );
}

/** Align this year's months against last year's for the comparison bars. */
function buildYoYSeries(months) {
  const byKey = new Map(months.map((m) => [m.month, m]));
  const latest = months[months.length - 1];
  if (!latest) return [];
  const year = Number(latest.month.slice(0, 4));

  const out = [];
  for (let mo = 1; mo <= 12; mo++) {
    const key = `${year}-${String(mo).padStart(2, '0')}`;
    const prevKey = `${year - 1}-${String(mo).padStart(2, '0')}`;
    const current = byKey.get(key);
    const previous = byKey.get(prevKey);
    if (!current && !previous) continue;
    out.push({
      label: formatMonth(key, { short: true }).split(' ')[0],
      current: current?.revenue ?? 0,
      previous: previous?.revenue ?? 0,
    });
  }
  return out.some((r) => r.previous > 0) ? out : [];
}
