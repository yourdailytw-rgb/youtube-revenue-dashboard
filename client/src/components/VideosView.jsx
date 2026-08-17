import { useEffect, useMemo, useState } from 'react';
import clsx from 'clsx';
import {
  ExternalLink,
  Film,
  Clapperboard,
  Flame,
  Trophy,
  Clock,
  TrendingUp,
  Info,
} from 'lucide-react';
import { Card, CardHeader, Badge, EmptyState, Skeleton, Tabs, Stat } from './ui';
import { api } from '../lib/api';
import {
  formatMoney,
  formatNumber,
  formatNumberShort,
  formatDate,
  formatDuration,
  formatHours,
  formatPct,
} from '../lib/format';
import { channelColor } from '../lib/metrics';

/**
 * Ranking dimensions. Each one is a legitimate way to ask "which video is
 * performing best" — revenue answers a different question from views-per-hour,
 * and both are useful.
 */
const RANKINGS = [
  {
    id: 'revenue',
    label: 'Revenue',
    group: 'Money',
    field: 'revenue',
    format: (v) => formatMoney(v),
    help: 'Estimated revenue earned in the selected period.',
  },
  {
    id: 'rpm',
    label: 'RPM',
    group: 'Money',
    field: 'rpm',
    format: (v) => formatMoney(v),
    help: 'Revenue per 1000 views — how efficiently a video monetises, independent of size.',
  },
  {
    id: 'views',
    label: 'Views in period',
    group: 'Reach',
    field: 'views',
    format: formatNumber,
    help: 'Views within the selected date range.',
  },
  {
    id: 'lifetimeViews',
    label: 'All-time views',
    group: 'Reach',
    field: 'lifetimeViews',
    format: formatNumber,
    help: 'Total views since publication, live from YouTube — not limited to the date range.',
  },
  {
    id: 'viewsPerHour',
    label: 'Views / hour (now)',
    group: 'Momentum',
    field: 'viewsPerHour',
    format: (v) => (v == null ? '—' : `${formatNumberShort(v)}/h`),
    help: 'Actual recent pace, measured from our own snapshots of the live view counter. This is what is taking off right now.',
    needsVelocity: true,
  },
  {
    id: 'lifetimeViewsPerHour',
    label: 'Views / hour (lifetime)',
    group: 'Momentum',
    field: 'lifetimeViewsPerHour',
    format: (v) => (v == null ? '—' : `${formatNumberShort(v)}/h`),
    help: 'Average pace across the whole life of the video — all-time views divided by hours since publishing.',
  },
  {
    id: 'watchHours',
    label: 'Watch time',
    group: 'Engagement',
    field: 'watchHours',
    format: formatHours,
    help: 'Total hours watched in the period — what actually drives the algorithm.',
  },
  {
    id: 'avgViewPercentage',
    label: 'Retention',
    group: 'Engagement',
    field: 'avgViewPercentage',
    format: (v) => (v == null ? '—' : `${v.toFixed(1)}%`),
    help: 'Average percentage of the video watched.',
  },
  {
    id: 'subscribersGained',
    label: 'Subscribers',
    group: 'Engagement',
    field: 'subscribersGained',
    format: (v) => (v == null ? '—' : `+${formatNumber(v)}`),
    help: 'Subscribers gained from this video in the period.',
  },
  {
    id: 'engagementRate',
    label: 'Engagement rate',
    group: 'Engagement',
    field: 'engagementRate',
    format: (v) => (v == null ? '—' : formatPct(v, { decimals: 2 })),
    help: 'All-time likes + comments divided by all-time views.',
  },
  {
    id: 'newest',
    label: 'Newest',
    group: 'Engagement',
    field: 'publishedAt',
    format: (v) => (v ? formatDate(String(v).slice(0, 10), 'short') : '—'),
    help: 'Most recently published first.',
  },
];

const GROUPS = ['Money', 'Reach', 'Momentum', 'Engagement'];

export function VideosView({ range, channels, allChannels = [] }) {
  const [state, setState] = useState({ loading: true, videos: [] });
  const [sort, setSort] = useState('revenue');
  const [filter, setFilter] = useState('all');
  const [velocityHours, setVelocityHours] = useState(24);

  useEffect(() => {
    let cancelled = false;
    setState((s) => ({ ...s, loading: true }));
    api
      .videos({
        start: range.start,
        end: range.end,
        channels,
        limit: 60,
        sort,
        velocityHours,
      })
      .then((res) => !cancelled && setState({ loading: false, ...res }))
      .catch((err) => !cancelled && setState({ loading: false, videos: [], error: err.message }));
    return () => {
      cancelled = true;
    };
  }, [range.start, range.end, channels?.join(','), sort, velocityHours]);

  const active = RANKINGS.find((r) => r.id === sort) || RANKINGS[0];

  const videos = useMemo(
    () =>
      (state.videos || []).filter((v) =>
        filter === 'all' ? true : filter === 'shorts' ? v.isShort : !v.isShort
      ),
    [state.videos, filter]
  );

  const maxValue = Math.max(...videos.map((v) => Number(v[active.field]) || 0), 1);

  if (state.loading && !state.videos?.length) {
    return (
      <div className="space-y-3">
        <Skeleton className="h-24" />
        {[0, 1, 2, 3, 4].map((i) => (
          <Skeleton key={i} className="h-20" />
        ))}
      </div>
    );
  }

  if (state.error) {
    return (
      <Card>
        <EmptyState title="Could not load videos" description={state.error} />
      </Card>
    );
  }

  return (
    <div className="space-y-4">
      {/* Ranking controls */}
      <Card>
        <CardHeader
          title="Rank videos by"
          subtitle={active.help}
          action={
            <Tabs
              size="sm"
              value={filter}
              onChange={setFilter}
              tabs={[
                { id: 'all', label: 'All' },
                { id: 'longform', label: 'Long-form', icon: <Film size={12} /> },
                { id: 'shorts', label: 'Shorts', icon: <Clapperboard size={12} /> },
              ]}
            />
          }
        />
        <div className="space-y-2 px-5 pb-4">
          {GROUPS.map((group) => (
            <div key={group} className="flex flex-wrap items-center gap-1.5">
              <span className="w-full text-[10px] font-semibold uppercase tracking-wider text-ink-dim sm:w-20 sm:shrink-0">
                {group}
              </span>
              {RANKINGS.filter((r) => r.group === group).map((r) => {
                const unavailable = r.needsVelocity && !state.velocityReady;
                return (
                  <button
                    key={r.id}
                    onClick={() => setSort(r.id)}
                    disabled={unavailable}
                    title={unavailable ? 'Needs a few hours of view-counter snapshots first' : r.help}
                    className={clsx(
                      'rounded-lg border px-2.5 py-1 text-xs font-medium transition-colors',
                      sort === r.id
                        ? 'border-accent bg-accent/15 text-accent'
                        : unavailable
                          ? 'cursor-not-allowed border-line-soft text-ink-dim opacity-40'
                          : 'border-line bg-surface-2 text-ink-dim hover:border-accent/40 hover:text-ink'
                    )}
                  >
                    {r.id === 'viewsPerHour' && <Flame size={10} className="mr-1 inline" />}
                    {r.label}
                  </button>
                );
              })}
            </div>
          ))}

          {sort === 'viewsPerHour' && (
            <div className="flex items-center gap-2 border-t border-line pt-3">
              <span className="text-[10px] font-semibold uppercase tracking-wider text-ink-dim">
                Window
              </span>
              {[6, 12, 24, 48, 72].map((h) => (
                <button
                  key={h}
                  onClick={() => setVelocityHours(h)}
                  className={clsx(
                    'rounded-md px-2 py-0.5 text-xs transition-colors',
                    velocityHours === h
                      ? 'bg-accent/15 text-accent'
                      : 'text-ink-dim hover:text-ink'
                  )}
                >
                  {h}h
                </button>
              ))}
              <span className="ml-auto text-[11px] text-ink-dim">
                {state.velocityCoverage || 0} video(s) with enough snapshots
              </span>
            </div>
          )}
        </div>
      </Card>

      {state.velocityReady === false && (
        <Card className="border-est/30 bg-est/5">
          <div className="flex items-start gap-3 px-4 py-3">
            <Info size={15} className="mt-0.5 shrink-0 text-est" />
            <p className="text-xs text-ink-dim">
              <strong className="text-est">Views-per-hour is still warming up.</strong> It is measured
              from our own snapshots of YouTube's live view counter, taken every 20 minutes, so it
              needs a couple of hours of history before it can rank anything. Every other ranking
              works now. <em>Views / hour (lifetime)</em> is available immediately, since it only
              needs all-time views and the publish date.
            </p>
          </div>
        </Card>
      )}

      {/* Summary */}
      {videos.length > 0 && (
        <Card className="grid grid-cols-2 divide-x divide-line sm:grid-cols-4">
          <div className="px-4 py-3">
            <Stat label="Videos ranked" value={String(videos.length)} hint={`${formatDate(range.start, 'short')} – ${formatDate(range.end, 'short')}`} />
          </div>
          <div className="px-4 py-3">
            <Stat label="Revenue" value={formatMoney(state.totals?.revenue ?? 0, { decimals: 0 })} hint="across ranked videos" />
          </div>
          <div className="px-4 py-3">
            <Stat label="Views in period" value={formatNumber(state.totals?.views ?? 0)} />
          </div>
          <div className="px-4 py-3">
            <Stat
              label="Top by "
              value={active.format(videos[0]?.[active.field])}
              hint={videos[0]?.title?.slice(0, 28)}
              tone="pos"
            />
          </div>
        </Card>
      )}

      {/* Ranking */}
      <Card className="overflow-hidden">
        <CardHeader
          title={`Ranked by ${active.label.toLowerCase()}`}
          subtitle={`${videos.length} videos · candidates pooled across revenue, views and watch-time queries so the ranking is not biased by one sort order`}
          action={<Trophy size={15} className="text-ink-dim" />}
        />

        {videos.length === 0 ? (
          <EmptyState
            title="No videos in this range"
            description="Video analytics need a period where the channel actually published or earned."
          />
        ) : (
          <div className="divide-y divide-line-soft">
            {videos.map((video, index) => {
              const primary = video[active.field];
              const barPct = Math.max(1.5, ((Number(primary) || 0) / maxValue) * 100);
              const channelIndex = Math.max(
                0,
                allChannels.findIndex((c) => c.id === video.channelId)
              );

              return (
                <a
                  key={`${video.channelId}-${video.videoId}`}
                  href={`https://www.youtube.com/watch?v=${video.videoId}`}
                  target="_blank"
                  rel="noreferrer"
                  className="group grid grid-cols-[22px_72px_minmax(0,1fr)] items-center gap-2.5 px-3 py-3 transition-colors hover:bg-surface-2/40 sm:grid-cols-[28px_92px_minmax(0,1fr)_auto] sm:gap-3 sm:px-4"
                >
                  <span
                    className={clsx(
                      'text-center text-sm font-semibold tabular',
                      index === 0 ? 'text-warn' : index < 3 ? 'text-ink' : 'text-ink-dim'
                    )}
                  >
                    {index + 1}
                  </span>

                  <span className="relative overflow-hidden rounded-md bg-surface-2" style={{ height: 44 }}>
                    {video.thumbnail ? (
                      <img src={video.thumbnail} alt="" className="h-full w-full object-cover" loading="lazy" />
                    ) : (
                      <span className="grid h-full w-full place-items-center text-ink-dim">
                        <Film size={16} />
                      </span>
                    )}
                    {video.durationSec != null && (
                      <span className="absolute bottom-0.5 right-0.5 rounded bg-black/80 px-1 text-[10px] tabular text-white">
                        {formatDuration(video.durationSec)}
                      </span>
                    )}
                  </span>

                  <span className="min-w-0">
                    <span className="flex items-center gap-1.5">
                      <span className="truncate text-sm font-medium text-ink group-hover:text-accent">
                        {video.title}
                      </span>
                      <ExternalLink
                        size={11}
                        className="shrink-0 text-ink-dim opacity-0 transition-opacity group-hover:opacity-100"
                      />
                    </span>

                    <span className="mt-0.5 flex flex-wrap items-center gap-x-2 gap-y-0.5 text-[11px] text-ink-dim">
                      <span className="flex items-center gap-1">
                        <span
                          className="h-1.5 w-1.5 rounded-full"
                          style={{ background: channelColor(channelIndex) }}
                        />
                        {video.channelTitle}
                      </span>
                      {video.publishedAt && (
                        <span>· {formatDate(video.publishedAt.slice(0, 10), 'short')}</span>
                      )}
                      {video.ageDays != null && (
                        <span className="flex items-center gap-0.5">
                          <Clock size={9} />
                          {video.ageDays < 1
                            ? `${Math.round(video.ageHours)}h old`
                            : `${Math.round(video.ageDays)}d old`}
                        </span>
                      )}
                      {video.isShort && <Badge tone="accent">Short</Badge>}
                      {video.viewsPerHour != null && video.viewsPerHour > 0 && sort !== 'viewsPerHour' && (
                        <Badge tone="warn" title={`${formatNumberShort(video.viewsPerHour)} views/hour over the last ${Math.round(video.velocityWindowHours)}h`}>
                          <Flame size={9} />
                          {formatNumberShort(video.viewsPerHour)}/h
                        </Badge>
                      )}
                    </span>

                    <span className="mt-1 block h-1 w-full max-w-[280px] overflow-hidden rounded-full bg-line">
                      <span
                        className="block h-full rounded-full transition-all"
                        style={{
                          width: `${barPct}%`,
                          background: index === 0 ? '#f59e0b' : 'var(--color-accent)',
                        }}
                      />
                    </span>
                  </span>

                  {/* On phones the metrics move to their own row spanning the
                      full width, so nothing gets clipped. */}
                  <span className="col-span-3 flex items-center justify-between gap-3 border-t border-line-soft pt-2 sm:col-span-1 sm:justify-end sm:gap-5 sm:border-0 sm:pt-0">
                    <MetricCell label="Revenue" value={formatMoney(video.revenue ?? 0, { decimals: 0 })} dim={sort !== 'revenue'} />
                    <MetricCell label="Period" value={formatNumberShort(video.views)} dim={sort !== 'views'} />
                    <MetricCell label="All-time" value={formatNumberShort(video.lifetimeViews)} dim={sort !== 'lifetimeViews'} className="hidden sm:block" />
                    <MetricCell label="RPM" value={video.rpm != null ? formatMoney(video.rpm) : '—'} dim={sort !== 'rpm'} className="hidden xl:block" />
                    <MetricCell
                      label={active.label}
                      value={active.format(primary)}
                      dim={false}
                      highlight
                    />
                  </span>
                </a>
              );
            })}
          </div>
        )}

        {state.errors?.length > 0 && (
          <p className="border-t border-line px-4 py-2 text-[11px] text-warn">
            {state.errors.length} query issue(s): {state.errors[0].message}
          </p>
        )}
      </Card>
    </div>
  );
}

function MetricCell({ label, value, dim, highlight, className }) {
  return (
    <span className={clsx('min-w-0 text-right sm:w-20', className)}>
      <span className="block text-[10px] uppercase tracking-wide text-ink-dim">{label}</span>
      <span
        className={clsx(
          'block text-xs tabular',
          highlight ? 'text-sm font-semibold text-ink' : dim ? 'text-ink-dim' : 'text-ink'
        )}
      >
        {value}
      </span>
    </span>
  );
}
