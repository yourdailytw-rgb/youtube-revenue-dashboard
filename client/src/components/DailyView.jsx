import { useMemo, useState } from 'react';
import clsx from 'clsx';
import { Download, Zap, Search } from 'lucide-react';
import { Card, CardHeader, Button, Badge, EmptyState, Delta } from './ui';
import { formatMoney, formatNumber, formatDate, formatHours, weekdayName } from '../lib/format';
import { channelColor } from '../lib/metrics';

/**
 * Day-by-day log. Shows every metric per day, marks modelled days, and can
 * break the period out per channel. Also the CSV export entry point.
 */
export function DailyView({ data, exportUrl, channelExportUrl }) {
  const [scope, setScope] = useState('total');
  const [query, setQuery] = useState('');
  const [order, setOrder] = useState('desc');

  const rows = useMemo(() => {
    if (!data) return [];
    if (scope === 'total') {
      return data.series.totals.map((d) => ({ ...d, channelTitle: 'All channels' }));
    }
    const out = [];
    for (const channel of data.channels) {
      for (const day of data.series.byChannel[channel.id] || []) {
        if (!day.hasViews && !day.hasRevenue && !day.isEstimated) continue;
        out.push({ ...day, channelId: channel.id, channelTitle: channel.title });
      }
    }
    return out;
  }, [data, scope]);

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    const list = q
      ? rows.filter(
          (r) => r.date.includes(q) || r.channelTitle.toLowerCase().includes(q) || weekdayName(r.date, false).toLowerCase().includes(q)
        )
      : rows;
    return [...list].sort((a, b) =>
      order === 'desc' ? b.date.localeCompare(a.date) : a.date.localeCompare(b.date)
    );
  }, [rows, query, order]);

  if (!data) return null;

  const totalRow = data.summary;

  return (
    <Card className="overflow-hidden">
      <CardHeader
        title="Daily log"
        subtitle={`${filtered.length} rows · ${data.range.start} → ${data.range.end}`}
        action={
          <div className="flex flex-wrap items-center gap-2">
            <div className="relative">
              <Search size={13} className="absolute left-2.5 top-1/2 -translate-y-1/2 text-ink-dim" />
              <input
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                placeholder="Filter…"
                className="w-32 rounded-lg border border-line bg-surface-2 py-1.5 pl-7 pr-2 text-xs text-ink placeholder:text-ink-dim focus:border-accent/60 focus:outline-none"
              />
            </div>
            <div className="inline-flex gap-0.5 rounded-lg border border-line bg-surface p-0.5">
              {[
                { id: 'total', label: 'Combined' },
                { id: 'channel', label: 'Per channel' },
              ].map((t) => (
                <button
                  key={t.id}
                  onClick={() => setScope(t.id)}
                  className={clsx(
                    'rounded-md px-2.5 py-1 text-xs font-medium transition-colors',
                    scope === t.id ? 'bg-surface-2 text-ink' : 'text-ink-dim hover:text-ink'
                  )}
                >
                  {t.label}
                </button>
              ))}
            </div>
            <a href={scope === 'total' ? exportUrl : channelExportUrl} download>
              <Button size="sm">
                <Download size={13} />
                CSV
              </Button>
            </a>
          </div>
        }
      />

      {filtered.length === 0 ? (
        <EmptyState title="No rows" description="Try a different filter or date range." />
      ) : (
        <div className="max-h-[70vh] overflow-auto">
          <table className="w-full min-w-[900px] border-collapse text-sm">
            <thead className="sticky top-0 z-10">
              <tr className="border-y border-line bg-surface-2 text-[11px] uppercase tracking-wide text-ink-dim">
                <th className="px-4 py-2 text-left font-medium">
                  <button
                    onClick={() => setOrder((o) => (o === 'desc' ? 'asc' : 'desc'))}
                    className="hover:text-ink"
                  >
                    Date {order === 'desc' ? '↓' : '↑'}
                  </button>
                </th>
                {scope === 'channel' && <th className="px-3 py-2 text-left font-medium">Channel</th>}
                <th className="px-3 py-2 text-right font-medium">Revenue</th>
                <th className="px-3 py-2 text-right font-medium">Views</th>
                <th className="px-3 py-2 text-right font-medium">Long-form</th>
                <th className="px-3 py-2 text-right font-medium">Shorts</th>
                <th className="px-3 py-2 text-right font-medium">RPM</th>
                <th className="px-3 py-2 text-right font-medium">Watch time</th>
                <th className="px-3 py-2 text-right font-medium">Subs</th>
              </tr>
            </thead>
            <tbody>
              {filtered.map((row, i) => (
                <tr
                  key={`${row.date}-${row.channelId || 'all'}`}
                  className={clsx(
                    'border-b border-line-soft transition-colors hover:bg-surface-2/40',
                    row.isEstimated && 'bg-est/5'
                  )}
                >
                  <td className="whitespace-nowrap px-4 py-2">
                    <span className="font-medium text-ink">{formatDate(row.date)}</span>
                    <span className="ml-2 text-[11px] text-ink-dim">{weekdayName(row.date)}</span>
                    {row.isEstimated && (
                      <Badge tone="est" className="ml-2">
                        <Zap size={9} />
                        est
                      </Badge>
                    )}
                  </td>
                  {scope === 'channel' && (
                    <td className="whitespace-nowrap px-3 py-2 text-ink-dim">
                      <span className="flex items-center gap-1.5">
                        <span
                          className="h-2 w-2 rounded-full"
                          style={{
                            background: channelColor(
                              data.channels.findIndex((c) => c.id === row.channelId)
                            ),
                          }}
                        />
                        {row.channelTitle}
                      </span>
                    </td>
                  )}
                  <td
                    className={clsx(
                      'px-3 py-2 text-right font-medium tabular',
                      row.isEstimated ? 'text-est' : 'text-ink'
                    )}
                  >
                    {formatMoney(row.effectiveRevenue)}
                  </td>
                  <td className="px-3 py-2 text-right tabular text-ink-dim">{formatNumber(row.views)}</td>
                  <td className="px-3 py-2 text-right tabular text-ink-dim">{formatNumber(row.lf_views)}</td>
                  <td className="px-3 py-2 text-right tabular text-ink-dim">{formatNumber(row.sf_views)}</td>
                  <td className="px-3 py-2 text-right tabular text-ink-dim">{formatMoney(row.rpm)}</td>
                  <td className="px-3 py-2 text-right tabular text-ink-dim">{formatHours(row.watch_hours)}</td>
                  <td
                    className={clsx(
                      'px-3 py-2 text-right tabular',
                      row.subs_net > 0 ? 'text-pos' : row.subs_net < 0 ? 'text-neg' : 'text-ink-dim'
                    )}
                  >
                    {row.subs_net > 0 ? '+' : ''}
                    {formatNumber(row.subs_net)}
                  </td>
                </tr>
              ))}
            </tbody>
            {scope === 'total' && (
              <tfoot className="sticky bottom-0">
                <tr className="border-t border-line bg-surface-2 font-semibold">
                  <td className="px-4 py-2.5 text-ink">Total</td>
                  <td className="px-3 py-2.5 text-right tabular text-ink">
                    {formatMoney(totalRow.effectiveRevenue)}
                  </td>
                  <td className="px-3 py-2.5 text-right tabular text-ink-dim">
                    {formatNumber(totalRow.views)}
                  </td>
                  <td className="px-3 py-2.5 text-right tabular text-ink-dim">
                    {formatNumber(totalRow.lf_views)}
                  </td>
                  <td className="px-3 py-2.5 text-right tabular text-ink-dim">
                    {formatNumber(totalRow.sf_views)}
                  </td>
                  <td className="px-3 py-2.5 text-right tabular text-ink-dim">{formatMoney(totalRow.rpm)}</td>
                  <td className="px-3 py-2.5 text-right tabular text-ink-dim">
                    {formatHours(totalRow.watch_hours)}
                  </td>
                  <td className="px-3 py-2.5 text-right tabular text-ink-dim">
                    {formatNumber(totalRow.subs_net)}
                  </td>
                </tr>
              </tfoot>
            )}
          </table>
        </div>
      )}
    </Card>
  );
}
