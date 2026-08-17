import { useMemo, useState } from 'react';
import {
  Area,
  Bar,
  CartesianGrid,
  ComposedChart,
  Legend,
  Line,
  ReferenceArea,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts';
import clsx from 'clsx';
import { BarChart3, LineChart as LineIcon, Layers, Zap } from 'lucide-react';
import { Card, Tabs, Badge } from './ui';
import { METRICS, METRIC_ORDER, channelColor } from '../lib/metrics';
import { formatDate, formatMoney, weekdayName } from '../lib/format';

const CHART_TYPES = [
  { id: 'area', label: 'Area', icon: <LineIcon size={13} /> },
  { id: 'bar', label: 'Bars', icon: <BarChart3 size={13} /> },
  { id: 'stacked', label: 'By channel', icon: <Layers size={13} /> },
];

/**
 * The primary chart.
 *
 * Reported and modelled revenue are drawn as separate series so an estimate is
 * never mistaken for a reported figure: modelled days are a dashed purple line
 * with a shaded confidence band, and the region is tinted.
 */
export function MainChart({ data, metric, onMetricChange, compareLabel }) {
  const [chartType, setChartType] = useState('area');
  const config = METRICS[metric];

  const { chartData, estimatedFrom, estimatedTo, hasComparison } = useMemo(() => {
    if (!data) return { chartData: [], hasComparison: false };

    const totals = data.series.totals;
    const compare = data.comparison?.totals || [];
    const estimatedDates = new Set(data.estimation?.estimatedDates || []);

    let first = null;
    let last = null;

    const rows = totals.map((day, index) => {
      const isEst = day.isEstimated || estimatedDates.has(day.date);
      if (isEst) {
        if (!first) first = day.date;
        last = day.date;
      }

      // A day YouTube has not reported is a GAP, not a zero. Plotting it as 0
      // drops the line to the floor and makes it look like revenue collapsed.
      const isRevenueMetric = config.id === 'revenue';
      const noData = isRevenueMetric ? !day.hasRevenueData : !day.hasData;

      const value = noData ? null : (day[config.dayKey] ?? 0);
      const compareDay = compare[index];

      return {
        date: day.date,
        value,
        noData,
        // Reported series stops where estimation begins…
        reported: isEst || noData ? null : value,
        // …and the modelled series starts one day early so the lines join up.
        estimated: isEst ? value : null,
        awaitingData: noData && !isEst,
        low: isEst ? day.effectiveLow : null,
        band: isEst ? Math.max(0, (day.effectiveHigh ?? 0) - (day.effectiveLow ?? 0)) : null,
        isEstimated: isEst,
        compare: compareDay ? (compareDay[config.dayKey] ?? 0) : null,
        compareDate: compareDay?.date ?? null,
        raw: day,
      };
    });

    // Bridge the gap: give the modelled series the last reported value too.
    const firstEstIndex = rows.findIndex((r) => r.isEstimated);
    if (firstEstIndex > 0 && metric === 'revenue') {
      rows[firstEstIndex - 1].estimated = rows[firstEstIndex - 1].value;
      rows[firstEstIndex - 1].low = rows[firstEstIndex - 1].value;
      rows[firstEstIndex - 1].band = 0;
    }

    return {
      chartData: rows,
      estimatedFrom: first,
      estimatedTo: last,
      hasComparison: compare.length > 0,
    };
  }, [data, config.dayKey, metric]);

  const channels = data?.channels || [];
  const showEstimateSeries = metric === 'revenue' && Boolean(estimatedFrom);

  const stackedData = useMemo(() => {
    if (!data || chartType !== 'stacked') return [];
    const totals = data.series.totals;
    return totals.map((day, index) => {
      const row = { date: day.date, isEstimated: day.isEstimated };
      for (const channel of channels) {
        const series = data.series.byChannel[channel.id] || [];
        row[channel.id] = series[index]?.[config.dayKey] ?? 0;
      }
      return row;
    });
  }, [data, chartType, channels, config.dayKey]);

  const tickCount = chartData.length > 180 ? 8 : chartData.length > 60 ? 7 : 6;

  return (
    <Card className="overflow-hidden">
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-line px-4 py-3">
        <div className="flex min-w-0 flex-wrap items-center gap-2">
          <Tabs
            size="sm"
            tabs={METRIC_ORDER.map((id) => ({
              id,
              label: METRICS[id].shortLabel,
              description: METRICS[id].description,
            }))}
            value={metric}
            onChange={onMetricChange}
            className="max-w-full overflow-x-auto"
          />
        </div>
        <div className="flex items-center gap-2">
          {showEstimateSeries && (
            <Badge tone="est" title="Days YouTube has not reported yet, filled by the model">
              <Zap size={10} />
              {formatDate(estimatedFrom, 'short')}
              {estimatedTo !== estimatedFrom ? `–${formatDate(estimatedTo, 'short')}` : ''} estimated
            </Badge>
          )}
          <Tabs size="sm" tabs={CHART_TYPES} value={chartType} onChange={setChartType} />
        </div>
      </div>

      <div className="h-[340px] w-full px-2 py-3 sm:h-[400px]">
        <ResponsiveContainer width="100%" height="100%">
          <ComposedChart
            data={chartType === 'stacked' ? stackedData : chartData}
            margin={{ top: 8, right: 12, bottom: 4, left: 4 }}
          >
            <defs>
              <linearGradient id="fillMain" x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor={config.color} stopOpacity={0.35} />
                <stop offset="100%" stopColor={config.color} stopOpacity={0.02} />
              </linearGradient>
              <linearGradient id="fillEst" x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor="#a855f7" stopOpacity={0.3} />
                <stop offset="100%" stopColor="#a855f7" stopOpacity={0.02} />
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
              minTickGap={28}
              interval="preserveStartEnd"
            />
            <YAxis
              tickFormatter={config.formatShort}
              stroke="#4b5565"
              tick={{ fontSize: 11, fill: '#7c8497' }}
              tickLine={false}
              axisLine={false}
              width={52}
              tickCount={tickCount}
            />

            <Tooltip
              content={
                <ChartTooltip
                  config={config}
                  channels={channels}
                  chartType={chartType}
                  compareLabel={compareLabel}
                />
              }
              cursor={{ stroke: '#2f3747', strokeWidth: 1 }}
            />

            {estimatedFrom && chartType !== 'stacked' && (
              <ReferenceArea
                x1={estimatedFrom}
                x2={estimatedTo}
                fill="#a855f7"
                fillOpacity={0.06}
                stroke="none"
              />
            )}

            {chartType === 'stacked' ? (
              channels.map((channel, i) => (
                <Bar
                  key={channel.id}
                  dataKey={channel.id}
                  stackId="ch"
                  fill={channelColor(i)}
                  name={channel.title}
                  isAnimationActive={false}
                  radius={i === channels.length - 1 ? [3, 3, 0, 0] : 0}
                />
              ))
            ) : chartType === 'bar' ? (
              <>
                <Bar
                  dataKey="reported"
                  fill={config.color}
                  name={config.label}
                  isAnimationActive={false}
                  radius={[3, 3, 0, 0]}
                />
                {showEstimateSeries && (
                  <Bar
                    dataKey="estimated"
                    fill="#a855f7"
                    name="Estimated"
                    isAnimationActive={false}
                    radius={[3, 3, 0, 0]}
                  />
                )}
              </>
            ) : (
              <>
                {hasComparison && (
                  <Line
                    type="monotone"
                    dataKey="compare"
                    stroke="#5b6478"
                    strokeWidth={1.5}
                    strokeDasharray="4 4"
                    dot={false}
                    name={compareLabel || 'Previous'}
                    isAnimationActive={false}
                    connectNulls
                  />
                )}

                {/* Confidence band, drawn as an invisible base + visible spread. */}
                {showEstimateSeries && (
                  <>
                    <Area
                      dataKey="low"
                      stackId="band"
                      stroke="none"
                      fill="transparent"
                      isAnimationActive={false}
                      legendType="none"
                      connectNulls
                    />
                    <Area
                      dataKey="band"
                      stackId="band"
                      stroke="none"
                      fill="#a855f7"
                      fillOpacity={0.16}
                      name="Estimate range"
                      isAnimationActive={false}
                      connectNulls
                    />
                  </>
                )}

                <Area
                  type="monotone"
                  dataKey="reported"
                  stroke={config.color}
                  strokeWidth={2}
                  fill="url(#fillMain)"
                  name={config.label}
                  dot={false}
                  isAnimationActive={false}
                  connectNulls={false}
                />

                {showEstimateSeries && (
                  <Area
                    type="monotone"
                    dataKey="estimated"
                    stroke="#a855f7"
                    strokeWidth={2}
                    strokeDasharray="5 4"
                    fill="url(#fillEst)"
                    name="Estimated"
                    dot={{ r: 2.5, fill: '#a855f7', strokeWidth: 0 }}
                    isAnimationActive={false}
                    connectNulls
                  />
                )}
              </>
            )}

            {chartType === 'stacked' && (
              <Legend
                verticalAlign="bottom"
                height={28}
                iconType="circle"
                iconSize={7}
                wrapperStyle={{ fontSize: 11, color: '#98a1b3' }}
              />
            )}
          </ComposedChart>
        </ResponsiveContainer>
      </div>
    </Card>
  );
}

function ChartTooltip({ active, payload, label, config, channels, chartType, compareLabel }) {
  if (!active || !payload?.length) return null;
  const row = payload[0]?.payload;
  if (!row) return null;

  return (
    <div className="min-w-[190px] rounded-lg border border-line bg-surface-2/97 p-2.5 shadow-xl backdrop-blur">
      <div className="mb-1.5 flex items-baseline justify-between gap-3">
        <p className="text-xs font-semibold text-ink">{formatDate(label, 'long')}</p>
        <span className="text-[10px] uppercase text-ink-dim">{weekdayName(label)}</span>
      </div>

      {chartType === 'stacked' ? (
        <div className="space-y-1">
          {channels.map((channel, i) => {
            const value = row[channel.id] ?? 0;
            if (!value) return null;
            return (
              <div key={channel.id} className="flex items-center justify-between gap-4 text-xs">
                <span className="flex items-center gap-1.5 truncate text-ink-dim">
                  <span
                    className="h-2 w-2 shrink-0 rounded-full"
                    style={{ background: channelColor(i) }}
                  />
                  <span className="truncate">{channel.title}</span>
                </span>
                <span className="shrink-0 font-medium tabular text-ink">{config.format(value)}</span>
              </div>
            );
          })}
          <div className="mt-1 flex items-center justify-between gap-4 border-t border-line pt-1 text-xs">
            <span className="text-ink-dim">Total</span>
            <span className="font-semibold tabular text-ink">
              {config.format(channels.reduce((a, c) => a + (row[c.id] || 0), 0))}
            </span>
          </div>
        </div>
      ) : (
        <div className="space-y-1">
          <div className="flex items-center justify-between gap-4 text-xs">
            <span className="text-ink-dim">
              {row.awaitingData ? 'Not reported yet' : row.isEstimated ? 'Estimated' : config.label}
            </span>
            <span
              className={clsx(
                'font-semibold tabular',
                row.awaitingData ? 'text-ink-dim' : row.isEstimated ? 'text-est' : 'text-ink'
              )}
            >
              {row.awaitingData ? '—' : config.format(row.value)}
            </span>
          </div>

          {row.awaitingData && (
            <p className="text-[10px] text-ink-dim">
              YouTube has not published this day yet — it is not zero.
            </p>
          )}

          {row.isEstimated && row.band > 0 && (
            <div className="flex items-center justify-between gap-4 text-xs">
              <span className="text-ink-dim">Likely range</span>
              <span className="tabular text-ink-dim">
                {formatMoney(row.low, { decimals: 0 })} – {formatMoney(row.low + row.band, { decimals: 0 })}
              </span>
            </div>
          )}

          {row.compare !== null && row.compare !== undefined && (
            <div className="flex items-center justify-between gap-4 border-t border-line pt-1 text-xs">
              <span className="text-ink-dim">{compareLabel || 'Previous'}</span>
              <span className="tabular text-ink-dim">{config.format(row.compare)}</span>
            </div>
          )}

          {row.raw && config.id === 'revenue' && (
            <div className="mt-1 flex items-center justify-between gap-4 border-t border-line pt-1 text-[11px] text-ink-dim">
              <span>{row.raw.lf_views?.toLocaleString('sv-SE')} long-form views</span>
              <span>RPM {formatMoney(row.raw.rpm)}</span>
            </div>
          )}

          {row.isEstimated && (
            <p className="mt-1 flex items-center gap-1 text-[10px] text-est">
              <Zap size={9} />
              Modelled — YouTube has not reported this day yet
            </p>
          )}
        </div>
      )}
    </div>
  );
}
