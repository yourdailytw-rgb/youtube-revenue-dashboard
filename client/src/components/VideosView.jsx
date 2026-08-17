import { useEffect, useState } from 'react';
import clsx from 'clsx';
import { ExternalLink, Film, Clapperboard } from 'lucide-react';
import { Card, CardHeader, Badge, EmptyState, Skeleton, Tabs } from './ui';
import { api } from '../lib/api';
import { formatMoney, formatNumber, formatDate, formatDuration, formatHours } from '../lib/format';

/** Top videos for the selected range, ranked by revenue. */
export function VideosView({ range, channels }) {
  const [state, setState] = useState({ loading: true, videos: [], errors: [] });
  const [filter, setFilter] = useState('all');

  useEffect(() => {
    let cancelled = false;
    setState((s) => ({ ...s, loading: true }));
    api
      .videos({ start: range.start, end: range.end, channels, limit: 30 })
      .then((res) => !cancelled && setState({ loading: false, ...res }))
      .catch((err) => !cancelled && setState({ loading: false, videos: [], error: err.message }))
    return () => {
      cancelled = true;
    };
  }, [range.start, range.end, channels?.join(',')]);

  if (state.loading) {
    return (
      <div className="space-y-3">
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

  const videos = state.videos.filter((v) =>
    filter === 'all' ? true : filter === 'shorts' ? v.isShort : !v.isShort
  );

  const maxRevenue = Math.max(...videos.map((v) => v.revenue ?? 0), 1);

  return (
    <Card className="overflow-hidden">
      <CardHeader
        title="Top videos"
        subtitle={`${formatDate(range.start)} → ${formatDate(range.end)} · ranked by revenue`}
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

      {state.errors?.length > 0 && (
        <p className="mx-4 mb-2 rounded-lg border border-warn/30 bg-warn/10 px-3 py-2 text-xs text-warn">
          {state.errors.length} channel(s) could not be queried: {state.errors[0].message}
        </p>
      )}

      {videos.length === 0 ? (
        <EmptyState
          title="No videos in this range"
          description="Video-level analytics need a range where the channel actually published or earned."
        />
      ) : (
        <div className="divide-y divide-line-soft">
          {videos.map((video, index) => (
            <a
              key={`${video.channelId}-${video.videoId}`}
              href={`https://www.youtube.com/watch?v=${video.videoId}`}
              target="_blank"
              rel="noreferrer"
              className="group flex items-center gap-3 px-4 py-3 transition-colors hover:bg-surface-2/40"
            >
              <span className="w-5 shrink-0 text-center text-xs tabular text-ink-dim">{index + 1}</span>

              <span className="relative shrink-0 overflow-hidden rounded-md bg-surface-2" style={{ width: 84, height: 47 }}>
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

              <span className="min-w-0 flex-1">
                <span className="flex items-center gap-1.5">
                  <span className="truncate text-sm font-medium text-ink group-hover:text-accent">
                    {video.title}
                  </span>
                  <ExternalLink size={11} className="shrink-0 text-ink-dim opacity-0 transition-opacity group-hover:opacity-100" />
                </span>
                <span className="mt-0.5 flex flex-wrap items-center gap-x-2 gap-y-0.5 text-[11px] text-ink-dim">
                  <span>{video.channelTitle}</span>
                  {video.publishedAt && <span>· {formatDate(video.publishedAt.slice(0, 10), 'short')}</span>}
                  {video.isShort && <Badge tone="accent">Short</Badge>}
                </span>
                <span className="mt-1 block h-1 w-full max-w-[220px] overflow-hidden rounded-full bg-line">
                  <span
                    className="block h-full rounded-full bg-pos/70"
                    style={{ width: `${Math.max(2, ((video.revenue ?? 0) / maxRevenue) * 100)}%` }}
                  />
                </span>
              </span>

              <span className="hidden shrink-0 gap-6 text-right sm:flex">
                <Metric label="Views" value={formatNumber(video.views)} />
                <Metric label="Watch time" value={formatHours(video.watchMinutes / 60)} />
                <Metric label="RPM" value={video.rpm != null ? formatMoney(video.rpm) : '—'} />
              </span>

              <span className="w-24 shrink-0 text-right">
                <span className="block text-sm font-semibold tabular text-ink">
                  {video.revenue != null ? formatMoney(video.revenue) : '—'}
                </span>
                <span className="block text-[11px] text-ink-dim sm:hidden">
                  {formatNumber(video.views)} views
                </span>
              </span>
            </a>
          ))}
        </div>
      )}
    </Card>
  );
}

function Metric({ label, value }) {
  return (
    <span className="w-20 text-right">
      <span className="block text-[10px] uppercase tracking-wide text-ink-dim">{label}</span>
      <span className="block text-xs tabular text-ink">{value}</span>
    </span>
  );
}
