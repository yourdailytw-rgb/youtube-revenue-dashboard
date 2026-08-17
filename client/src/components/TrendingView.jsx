import { useEffect, useState } from 'react';
import clsx from 'clsx';
import {
  Flame,
  Rocket,
  Undo2,
  Sparkles,
  ExternalLink,
  Film,
  ArrowUpRight,
  Info,
  Snowflake,
  Clock,
} from 'lucide-react';
import { Card, CardHeader, Badge, EmptyState, Skeleton, Stat, Button } from './ui';
import { api } from '../lib/api';
import { formatNumber, formatNumberShort, formatDate, formatDuration } from '../lib/format';
import { channelColor } from '../lib/metrics';

/**
 * Viral / spike detection.
 *
 * Ranks tracked videos by how far their current pace runs ahead of their own
 * normal pace, so a two-year-old video waking up ranks alongside a launch that
 * is taking off. Ratio alone would surface noise, so the heat score weights it
 * by absolute views per hour.
 */

const KINDS = {
  breakout: {
    label: 'Breakout',
    icon: Flame,
    tone: 'neg',
    blurb: 'Running 5x or more above its own normal pace',
  },
  'launch-surge': {
    label: 'Launch surge',
    icon: Rocket,
    tone: 'warn',
    blurb: 'A fresh upload climbing fast',
  },
  resurgence: {
    label: 'Picking up',
    icon: Undo2,
    tone: 'est',
    blurb: 'An older video getting traction again',
  },
  new: { label: 'New upload', icon: Sparkles, tone: 'accent', blurb: 'Published in the last 48h' },
  steady: { label: 'Steady', icon: ArrowUpRight, tone: 'neutral', blurb: 'Tracking its usual pace' },
  cooling: { label: 'Cooling off', icon: Snowflake, tone: 'neutral', blurb: 'Slowing down' },
};

const WINDOWS = [
  { hours: 3, label: '3h' },
  { hours: 6, label: '6h' },
  { hours: 12, label: '12h' },
  { hours: 24, label: '24h' },
];

export function TrendingView({ channels, allChannels = [] }) {
  const [state, setState] = useState({ loading: true });
  const [recentHours, setRecentHours] = useState(6);
  const [kind, setKind] = useState(null);

  useEffect(() => {
    let cancelled = false;
    setState((s) => ({ ...s, loading: true }));
    api
      .trending({ channels, recentHours, kind, limit: 60 })
      .then((res) => !cancelled && setState({ loading: false, ...res }))
      .catch((err) => !cancelled && setState({ loading: false, error: err.message }));
    const timer = setInterval(() => {
      api
        .trending({ channels, recentHours, kind, limit: 60 })
        .then((res) => !cancelled && setState({ loading: false, ...res }))
        .catch(() => {});
    }, 120000); // refresh every 2 minutes — this is the "right now" view
    return () => {
      cancelled = true;
      clearInterval(timer);
    };
  }, [channels?.join(','), recentHours, kind]);

  if (state.loading && !state.videos) {
    return (
      <div className="space-y-3">
        <Skeleton className="h-28" />
        {[0, 1, 2, 3].map((i) => (
          <Skeleton key={i} className="h-20" />
        ))}
      </div>
    );
  }

  if (state.error) {
    return (
      <Card>
        <EmptyState title="Could not load trending data" description={state.error} />
      </Card>
    );
  }

  if (!state.ready) {
    return (
      <Card>
        <EmptyState
          icon={<Flame size={22} />}
          title="Spike detection is warming up"
          description={
            state.reason ||
            'It compares each video’s pace over the last few hours against its own baseline, using snapshots of YouTube’s live view counter taken every 20 minutes. It needs at least two polls before anything can be ranked — so give it about 40 minutes from first start.'
          }
        />
      </Card>
    );
  }

  const videos = state.videos || [];
  const counts = state.counts || {};

  return (
    <div className="space-y-4">
      <Card>
        <CardHeader
          title="What's heating up"
          subtitle={`Each video's pace over the last ${recentHours}h compared with its own baseline. Refreshes every 2 minutes.`}
          action={
            <div className="flex items-center gap-1 rounded-lg border border-line bg-surface p-0.5">
              {WINDOWS.map((w) => (
                <button
                  key={w.hours}
                  onClick={() => setRecentHours(w.hours)}
                  className={clsx(
                    'rounded-md px-2.5 py-1 text-xs font-medium transition-colors',
                    recentHours === w.hours ? 'bg-surface-2 text-ink' : 'text-ink-dim hover:text-ink'
                  )}
                >
                  {w.label}
                </button>
              ))}
            </div>
          }
        />
        <div className="grid grid-cols-2 gap-4 px-5 pb-4 sm:grid-cols-4">
          <Stat label="Spiking now" value={String(counts.spiking ?? 0)} hint="2x or more above baseline" tone={counts.spiking ? 'neg' : undefined} />
          <Stat label="Breakouts" value={String(counts.breakouts ?? 0)} hint="5x or more" tone={counts.breakouts ? 'neg' : undefined} />
          <Stat label="Old videos waking up" value={String(counts.resurgences ?? 0)} hint="back catalogue picking up" tone={counts.resurgences ? 'est' : undefined} />
          <Stat label="Videos tracked" value={`${counts.withVelocity ?? 0}/${counts.tracked ?? 0}`} hint="with enough snapshots" />
        </div>

        <div className="flex flex-wrap items-center gap-1.5 border-t border-line px-5 py-3">
          <span className="mr-1 text-[10px] font-semibold uppercase tracking-wider text-ink-dim">
            Filter
          </span>
          <button
            onClick={() => setKind(null)}
            className={clsx(
              'rounded-lg border px-2.5 py-1 text-xs font-medium transition-colors',
              kind === null
                ? 'border-accent bg-accent/15 text-accent'
                : 'border-line bg-surface-2 text-ink-dim hover:text-ink'
            )}
          >
            Everything
          </button>
          {Object.entries(KINDS)
            .filter(([k]) => k !== 'steady' && k !== 'cooling')
            .map(([k, meta]) => {
              const Icon = meta.icon;
              return (
                <button
                  key={k}
                  onClick={() => setKind(kind === k ? null : k)}
                  title={meta.blurb}
                  className={clsx(
                    'inline-flex items-center gap-1 rounded-lg border px-2.5 py-1 text-xs font-medium transition-colors',
                    kind === k
                      ? 'border-accent bg-accent/15 text-accent'
                      : 'border-line bg-surface-2 text-ink-dim hover:text-ink'
                  )}
                >
                  <Icon size={11} />
                  {meta.label}
                </button>
              );
            })}
        </div>
      </Card>

      {videos.length === 0 ? (
        <Card>
          <EmptyState
            icon={<Snowflake size={22} />}
            title="Nothing spiking right now"
            description={`No video is running meaningfully above its own baseline in the last ${recentHours} hours. Try a longer window, or check back later — this is genuinely quiet, not an error.`}
          />
        </Card>
      ) : (
        <Card className="overflow-hidden">
          <CardHeader
            title={`${videos.length} video${videos.length === 1 ? '' : 's'} ranked by heat`}
            subtitle="Heat combines how far above baseline a video is running with how many views per hour it is actually doing, so a big multiple on tiny numbers doesn't win."
          />
          <div className="divide-y divide-line-soft">
            {videos.map((video, index) => {
              const meta = KINDS[video.classification.kind] || KINDS.steady;
              const Icon = meta.icon;
              const channelIndex = Math.max(
                0,
                allChannels.findIndex((c) => c.id === video.channelId)
              );

              return (
                <a
                  key={video.videoId}
                  href={`https://www.youtube.com/watch?v=${video.videoId}`}
                  target="_blank"
                  rel="noreferrer"
                  className="group flex items-center gap-3 px-4 py-3 transition-colors hover:bg-surface-2/40"
                >
                  <span
                    className={clsx(
                      'w-6 text-center text-sm font-semibold tabular',
                      index === 0 ? 'text-neg' : index < 3 ? 'text-warn' : 'text-ink-dim'
                    )}
                  >
                    {index + 1}
                  </span>

                  <span className="relative shrink-0 overflow-hidden rounded-md bg-surface-2" style={{ width: 92, height: 52 }}>
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

                    <span className="mt-0.5 flex flex-wrap items-center gap-x-2 gap-y-1 text-[11px] text-ink-dim">
                      <Badge tone={meta.tone} title={meta.blurb}>
                        <Icon size={9} />
                        {meta.label}
                      </Badge>
                      <span className="flex items-center gap-1">
                        <span className="h-1.5 w-1.5 rounded-full" style={{ background: channelColor(channelIndex) }} />
                        {video.channelTitle}
                      </span>
                      {video.ageDays != null && (
                        <span className="flex items-center gap-0.5">
                          <Clock size={9} />
                          {video.ageDays < 2
                            ? `${Math.round(video.ageHours)}h old`
                            : video.ageDays < 60
                              ? `${Math.round(video.ageDays)}d old`
                              : `${(video.ageDays / 365).toFixed(1)}y old`}
                        </span>
                      )}
                      {video.accelerating && (
                        <Badge tone="warn" title="The short window is running ahead of the 24h window — still climbing">
                          <ArrowUpRight size={9} />
                          accelerating
                        </Badge>
                      )}
                      {video.isShort && <Badge tone="accent">Short</Badge>}
                    </span>

                    <span className="mt-1 flex flex-wrap items-center gap-x-3 text-[11px] text-ink-dim">
                      <span>
                        now <strong className="text-ink">{formatNumberShort(video.recentViewsPerHour)}/h</strong>
                      </span>
                      <span>
                        normal {formatNumberShort(video.baselineViewsPerHour)}/h
                        <span className="ml-1 opacity-60">({video.baselineSource})</span>
                      </span>
                      <span>
                        +{formatNumber(video.recentGained)} views in {video.recentWindowHours?.toFixed(1)}h
                      </span>
                    </span>
                  </span>

                  <span className="shrink-0 text-right">
                    <span
                      className={clsx(
                        'block text-lg font-bold tabular',
                        video.spikeRatio >= 5
                          ? 'text-neg'
                          : video.spikeRatio >= 2
                            ? 'text-warn'
                            : 'text-ink-dim'
                      )}
                    >
                      {video.spikeRatio.toFixed(1)}×
                    </span>
                    <span className="block text-[10px] uppercase tracking-wide text-ink-dim">
                      vs normal
                    </span>
                    <span className="mt-0.5 block text-[11px] text-ink-dim">
                      ~{formatNumberShort(video.projected24h)} next 24h
                    </span>
                  </span>
                </a>
              );
            })}
          </div>
        </Card>
      )}

      <Card>
        <CardHeader title="How this works" action={<Info size={15} className="text-ink-dim" />} />
        <ul className="space-y-2 px-5 pb-5 text-[13px] leading-relaxed text-ink-dim">
          <li>
            <strong className="text-ink">The signal.</strong> Every tracked video's view counter is
            snapshotted every 20 minutes. A video's pace over the last {recentHours} hours is compared
            with its own baseline — either its 72-hour pace, or its lifetime average when there isn't
            that much snapshot history yet.
          </li>
          <li>
            <strong className="text-ink">Why old videos show up.</strong> Comparing against a video's{' '}
            <em>own</em> lifetime average is what catches a resurgence. A two-year-old video that
            averaged 40 views/hour across its life and is suddenly doing 1,800 is unmistakable — and
            invisible in any revenue or all-time-views ranking.
          </li>
          <li>
            <strong className="text-ink">What's tracked.</strong> The 40 newest uploads plus the 40
            most-viewed videos per channel, so both launches and the back catalogue are covered.
          </li>
          <li>
            <strong className="text-ink">The projection.</strong> "next 24h" simply extends the current
            pace forward. It is arithmetic, not a prediction — a spike can stop as fast as it started.
          </li>
        </ul>
      </Card>
    </div>
  );
}
