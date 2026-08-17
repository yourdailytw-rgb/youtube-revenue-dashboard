import { useState } from 'react';
import {
  Area,
  AreaChart,
  Bar,
  BarChart,
  Cell,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts';
import clsx from 'clsx';
import { ArrowUpDown } from 'lucide-react';
import { Card, CardHeader, Delta, ChannelAvatar, EmptyState } from './ui';
import { METRICS, channelColor } from '../lib/metrics';
import { formatMoney, formatNumber, formatPct, formatHours, formatDate } from '../lib/format';

const COLUMNS = [
  { id: 'revenue', label: 'Revenue', format: (v) => formatMoney(v), align: 'right' },
  { id: 'share', label: 'Share', format: (v) => formatPct(v, { decimals: 1 }), align: 'right' },
  { id: 'revenueDeltaPct', label: 'Change', type: 'delta', align: 'right' },
  { id: 'views', label: 'Views', format: formatNumber, align: 'right' },
  { id: 'lfViews', label: 'Long-form', format: formatNumber, align: 'right' },
  { id: 'sfViews', label: 'Shorts', format: formatNumber, align: 'right' },
  { id: 'rpm', label: 'RPM', format: (v) => formatMoney(v), align: 'right' },
  { id: 'watchHours', label: 'Watch time', format: formatHours, align: 'right' },
  { id: 'subsNet', label: 'Subs', format: (v) => (v > 0 ? `+${formatNumber(v)}` : formatNumber(v)), align: 'right' },
  { id: 'dailyAverage', label: 'Daily avg', format: (v) => formatMoney(v, { decimals: 0 }), align: 'right' },
];

/**
 * `compact` is used on the Overview tab: the ranking table and revenue share,
 * without the growth chart and per-channel small multiples that the dedicated
 * Channels tab shows in full.
 */
export function ChannelsView({ data, metric, compact = false }) {
  const [sort, setSort] = useState({ key: 'revenue', dir: 'desc' });

  if (!data || !data.breakdown?.rows.length) {
    return (
      <Card>
        <EmptyState
          title="No channel data for this period"
          description="Connect a channel or widen the date range."
        />
      </Card>
    );
  }

  const rows = [...data.breakdown.rows].sort((a, b) => {
    const dir = sort.dir === 'asc' ? 1 : -1;
    const av = a[sort.key] ?? -Infinity;
    const bv = b[sort.key] ?? -Infinity;
    return av === bv ? 0 : av > bv ? dir : -dir;
  });

  const toggleSort = (key) =>
    setSort((s) => ({ key, dir: s.key === key && s.dir === 'desc' ? 'asc' : 'desc' }));

  const pieData = data.breakdown.rows
    .filter((r) => r.revenue > 0)
    .map((r, i) => ({ name: r.title, value: r.revenue, color: channelColor(indexOfChannel(data, r.id)) }));

  return (
    <div className="space-y-4">
      <div className="grid gap-4 lg:grid-cols-[minmax(0,1fr)_340px]">
        <Card className="overflow-hidden">
          <CardHeader
            title="Channel performance"
            subtitle={`${data.range.days} days · sorted by ${COLUMNS.find((c) => c.id === sort.key)?.label.toLowerCase()}`}
          />
          <div className="overflow-x-auto">
            <table className="w-full min-w-[860px] border-collapse text-sm">
              <thead>
                <tr className="border-y border-line bg-surface-2/40 text-[11px] uppercase tracking-wide text-ink-dim">
                  <th className="px-4 py-2 text-left font-medium">Channel</th>
                  {COLUMNS.map((col) => (
                    <th key={col.id} className="px-3 py-2 text-right font-medium">
                      <button
                        onClick={() => toggleSort(col.id)}
                        className={clsx(
                          'inline-flex items-center gap-1 transition-colors hover:text-ink',
                          sort.key === col.id && 'text-ink'
                        )}
                      >
                        {col.label}
                        {sort.key === col.id && <ArrowUpDown size={10} />}
                      </button>
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {rows.map((row) => {
                  const idx = indexOfChannel(data, row.id);
                  return (
                    <tr key={row.id} className="border-b border-line-soft transition-colors hover:bg-surface-2/40">
                      <td className="px-4 py-2.5">
                        <div className="flex items-center gap-2">
                          <ChannelAvatar channel={row} size={22} index={idx} color={channelColor(idx)} />
                          <div className="min-w-0">
                            <p className="truncate font-medium text-ink">{row.title}</p>
                            {row.estimatedRevenue > 0 && (
                              <p className="truncate text-[11px] text-est">
                                incl. {formatMoney(row.estimatedRevenue, { decimals: 0 })} estimated
                              </p>
                            )}
                          </div>
                        </div>
                      </td>
                      {COLUMNS.map((col) => (
                        <td key={col.id} className="px-3 py-2.5 text-right tabular">
                          {col.type === 'delta' ? (
                            <Delta value={row[col.id]} showIcon={false} />
                          ) : col.id === 'share' ? (
                            <div className="flex items-center justify-end gap-2">
                              <span className="h-1.5 w-12 overflow-hidden rounded-full bg-line">
                                <span
                                  className="block h-full rounded-full"
                                  style={{
                                    width: `${Math.min(100, row.share * 100)}%`,
                                    background: channelColor(idx),
                                  }}
                                />
                              </span>
                              <span className="w-11 text-ink-dim">{col.format(row[col.id])}</span>
                            </div>
                          ) : (
                            <span className={col.id === 'revenue' ? 'font-medium text-ink' : 'text-ink-dim'}>
                              {col.format(row[col.id])}
                            </span>
                          )}
                        </td>
                      ))}
                    </tr>
                  );
                })}
              </tbody>
              <tfoot>
                <tr className="border-t border-line bg-surface-2/40 font-semibold">
                  <td className="px-4 py-2.5 text-ink">Total</td>
                  <td className="px-3 py-2.5 text-right tabular text-ink">
                    {formatMoney(data.summary.effectiveRevenue)}
                  </td>
                  <td className="px-3 py-2.5 text-right tabular text-ink-dim">100%</td>
                  <td className="px-3 py-2.5 text-right">
                    <Delta value={data.comparison?.deltas?.effectiveRevenue?.pct} showIcon={false} />
                  </td>
                  <td className="px-3 py-2.5 text-right tabular text-ink-dim">
                    {formatNumber(data.summary.views)}
                  </td>
                  <td className="px-3 py-2.5 text-right tabular text-ink-dim">
                    {formatNumber(data.summary.lf_views)}
                  </td>
                  <td className="px-3 py-2.5 text-right tabular text-ink-dim">
                    {formatNumber(data.summary.sf_views)}
                  </td>
                  <td className="px-3 py-2.5 text-right tabular text-ink-dim">
                    {formatMoney(data.summary.rpm)}
                  </td>
                  <td className="px-3 py-2.5 text-right tabular text-ink-dim">
                    {formatHours(data.summary.watch_hours)}
                  </td>
                  <td className="px-3 py-2.5 text-right tabular text-ink-dim">
                    {formatNumber(data.summary.subs_net)}
                  </td>
                  <td className="px-3 py-2.5 text-right tabular text-ink-dim">
                    {formatMoney(data.summary.dailyAverage, { decimals: 0 })}
                  </td>
                </tr>
              </tfoot>
            </table>
          </div>
        </Card>

        <div className="space-y-4">
          <Card>
            <CardHeader title="Revenue share" subtitle="Who is carrying the period" />
            <div className="h-[210px] px-2 pb-2">
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={pieData}
                    dataKey="value"
                    nameKey="name"
                    innerRadius={52}
                    outerRadius={82}
                    paddingAngle={2}
                    stroke="none"
                    isAnimationActive={false}
                  >
                    {pieData.map((entry) => (
                      <Cell key={entry.name} fill={entry.color} />
                    ))}
                  </Pie>
                  <Tooltip
                    content={({ active, payload }) =>
                      active && payload?.length ? (
                        <div className="rounded-lg border border-line bg-surface-2 px-2.5 py-1.5 text-xs shadow-xl">
                          <p className="font-medium text-ink">{payload[0].name}</p>
                          <p className="tabular text-ink-dim">{formatMoney(payload[0].value)}</p>
                        </div>
                      ) : null
                    }
                  />
                </PieChart>
              </ResponsiveContainer>
            </div>
            <div className="space-y-1.5 px-4 pb-4">
              {data.breakdown.rows.slice(0, 6).map((row) => {
                const idx = indexOfChannel(data, row.id);
                return (
                  <div key={row.id} className="flex items-center gap-2 text-xs">
                    <span
                      className="h-2 w-2 shrink-0 rounded-full"
                      style={{ background: channelColor(idx) }}
                    />
                    <span className="min-w-0 flex-1 truncate text-ink-dim">{row.title}</span>
                    <span className="shrink-0 tabular text-ink">{formatPct(row.share, { decimals: 1 })}</span>
                  </div>
                );
              })}
            </div>
          </Card>

          {!compact && (
          <Card>
            <CardHeader title="Growth vs previous period" subtitle="Change in revenue" />
            <div className="h-[180px] px-2 pb-3">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart
                  data={data.breakdown.rows
                    .filter((r) => r.revenueDeltaPct !== null)
                    .map((r) => ({ name: r.title, value: r.revenueDeltaPct }))}
                  layout="vertical"
                  margin={{ left: 4, right: 12, top: 4, bottom: 4 }}
                >
                  <XAxis type="number" hide />
                  <YAxis
                    type="category"
                    dataKey="name"
                    width={92}
                    tick={{ fontSize: 11, fill: '#7c8497' }}
                    tickLine={false}
                    axisLine={false}
                  />
                  <Tooltip
                    cursor={{ fill: 'rgba(255,255,255,0.03)' }}
                    content={({ active, payload }) =>
                      active && payload?.length ? (
                        <div className="rounded-lg border border-line bg-surface-2 px-2.5 py-1.5 text-xs shadow-xl">
                          <p className="font-medium text-ink">{payload[0].payload.name}</p>
                          <p className="tabular text-ink-dim">
                            {formatPct(payload[0].value, { sign: true })}
                          </p>
                        </div>
                      ) : null
                    }
                  />
                  <Bar dataKey="value" radius={[0, 3, 3, 0]} isAnimationActive={false}>
                    {data.breakdown.rows
                      .filter((r) => r.revenueDeltaPct !== null)
                      .map((r) => (
                        <Cell key={r.id} fill={r.revenueDeltaPct >= 0 ? '#22c55e' : '#ef4444'} />
                      ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            </div>
          </Card>
          )}
        </div>
      </div>

      {!compact && <PerChannelGrid data={data} metric={metric} />}
    </div>
  );
}

/** Small multiples — one sparkline card per channel. */
function PerChannelGrid({ data, metric }) {
  const config = METRICS[metric] || METRICS.revenue;

  return (
    <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-3">
      {data.breakdown.rows.map((row) => {
        const idx = indexOfChannel(data, row.id);
        const color = channelColor(idx);
        const series = (data.series.byChannel[row.id] || []).map((d) => ({
          date: d.date,
          value: d[config.dayKey] ?? 0,
          isEstimated: d.isEstimated,
        }));
        const value = row[config.channelKey] ?? row.revenue;

        return (
          <Card key={row.id} className="overflow-hidden">
            <div className="flex items-start justify-between gap-2 px-4 pt-3.5">
              <div className="flex min-w-0 items-center gap-2">
                <ChannelAvatar channel={row} size={22} index={idx} color={color} />
                <div className="min-w-0">
                  <p className="truncate text-sm font-medium text-ink">{row.title}</p>
                  <p className="text-[11px] text-ink-dim">{config.label}</p>
                </div>
              </div>
              <div className="shrink-0 text-right">
                <p className="text-sm font-semibold tabular text-ink">{config.format(value)}</p>
                <Delta value={row.revenueDeltaPct} showIcon={false} />
              </div>
            </div>
            <div className="mt-2 h-[70px]">
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={series} margin={{ top: 2, right: 0, bottom: 0, left: 0 }}>
                  <defs>
                    <linearGradient id={`ch-${row.id}`} x1="0" y1="0" x2="0" y2="1">
                      <stop offset="0%" stopColor={color} stopOpacity={0.4} />
                      <stop offset="100%" stopColor={color} stopOpacity={0} />
                    </linearGradient>
                  </defs>
                  <Tooltip
                    content={({ active, payload, label }) =>
                      active && payload?.length ? (
                        <div className="rounded-lg border border-line bg-surface-2 px-2.5 py-1.5 text-xs shadow-xl">
                          <p className="text-ink-dim">{formatDate(label, 'short')}</p>
                          <p className="font-medium tabular text-ink">{config.format(payload[0].value)}</p>
                        </div>
                      ) : null
                    }
                  />
                  <Area
                    type="monotone"
                    dataKey="value"
                    stroke={color}
                    strokeWidth={1.6}
                    fill={`url(#ch-${row.id})`}
                    dot={false}
                    isAnimationActive={false}
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

function indexOfChannel(data, id) {
  return Math.max(0, data.channels.findIndex((c) => c.id === id));
}
