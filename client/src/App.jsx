import { useCallback, useEffect, useMemo, useState } from 'react';
import {
  LayoutDashboard,
  Users,
  CalendarRange,
  Table2,
  Film,
  Zap,
  TrendingUp,
  Flame,
  Settings,
  AlertCircle,
  Download,
  RefreshCw,
} from 'lucide-react';
import { Header } from './components/Header';
import { DateRangePicker } from './components/DateRangePicker';
import { ChannelFilter } from './components/ChannelFilter';
import { StatCards, QuickStats } from './components/StatCards';
import { MainChart } from './components/MainChart';
import { ChannelsView } from './components/ChannelsView';
import { MonthsView } from './components/MonthsView';
import { DailyView } from './components/DailyView';
import { TrendsView } from './components/TrendsView';
import { VideosView } from './components/VideosView';
import { TrendingView } from './components/TrendingView';
import { EstimatorView } from './components/EstimatorView';
import { SettingsView } from './components/SettingsView';
import { Tabs, Card, Button, EmptyState, Skeleton } from './components/ui';
import { api } from './lib/api';
import { setCurrency, formatDate, formatMonth } from './lib/format';
import { todayISO, addDays, startOfMonth, endOfMonth, alignToMonth } from './lib/ranges';

const TABS = [
  { id: 'overview', label: 'Overview', icon: <LayoutDashboard size={13} /> },
  { id: 'channels', label: 'Channels', icon: <Users size={13} /> },
  { id: 'months', label: 'Months', icon: <CalendarRange size={13} /> },
  { id: 'trends', label: 'Trends', icon: <TrendingUp size={13} /> },
  { id: 'videos', label: 'Videos', icon: <Film size={13} /> },
  { id: 'trending', label: 'Viral', icon: <Flame size={13} /> },
  { id: 'daily', label: 'Daily log', icon: <Table2 size={13} /> },
  { id: 'estimator', label: 'Estimator', icon: <Zap size={13} /> },
  { id: 'settings', label: 'Settings', icon: <Settings size={13} /> },
];

const COMPARE_OPTIONS = [
  { id: 'previous', label: 'Previous period' },
  { id: 'year', label: 'Same period last year' },
  { id: 'none', label: 'No comparison' },
];

function readCompare(params) {
  const mode = params.get('compare') || 'previous';
  const valid = (v) => typeof v === 'string' && /^\d{4}-\d{2}-\d{2}$/.test(v);
  const empty = { compareMonth: null, compareStart: null, compareEnd: null };

  // A month comparison is stored as the month itself, not as dates, so it stays
  // aligned date-for-date with whatever range is being viewed.
  if (mode === 'month') {
    const key = params.get('compareMonth');
    return /^\d{4}-\d{2}$/.test(key || '')
      ? { ...empty, compare: 'month', compareMonth: key }
      : { ...empty, compare: 'previous' };
  }
  if (mode === 'custom') {
    const cs = params.get('compareStart');
    const ce = params.get('compareEnd');
    return valid(cs) && valid(ce) && cs <= ce
      ? { ...empty, compare: 'custom', compareStart: cs, compareEnd: ce }
      : { ...empty, compare: 'previous' };
  }
  return { ...empty, compare: mode };
}

/** Tab/metric/channel state persists in the URL; the date range does not. */
function readUrlState() {
  const params = new URLSearchParams(window.location.search);
  const today = todayISO();
  return {
    tab: params.get('tab') || 'overview',
    // Default period is the current month — that is what you want to see on
    // opening the dashboard. An explicit range in the URL still wins.
    start: params.get('start') || startOfMonth(today),
    end: params.get('end') || today,
    channels: params.get('channels') ? params.get('channels').split(',').filter(Boolean) : [],
    // Same rule as the main range: an explicit comparison range in the URL is
    // honoured (so "this month vs August" can be shared as a link) but never
    // written back, so a plain reload returns to the previous-period default.
    ...readCompare(params),
    metric: params.get('metric') || 'revenue',
  };
}

/**
 * The date range is deliberately NOT written back to the URL: opening or
 * reloading the dashboard should always land on the current month, not on
 * whatever range happened to be open last time. A range passed in explicitly is
 * still honoured on load, so shared links keep working.
 */
function writeUrlState(state) {
  const params = new URLSearchParams();
  params.set('tab', state.tab);
  params.set('compare', state.compare);
  if (state.compare === 'month' && state.compareMonth) params.set('compareMonth', state.compareMonth);
  params.set('metric', state.metric);
  if (state.channels.length) params.set('channels', state.channels.join(','));
  window.history.replaceState(null, '', `?${params.toString()}`);
}

/**
 * What to send the API for the current comparison choice. Month comparisons are
 * resolved here, against the range being viewed, into explicit dates.
 */
function comparisonParams(state) {
  if (state.compare === 'month' && state.compareMonth) {
    const aligned = alignToMonth(state.start, state.end, state.compareMonth);
    return { compare: 'custom', compareStart: aligned.start, compareEnd: aligned.end };
  }
  if (state.compare === 'custom') {
    return { compare: 'custom', compareStart: state.compareStart, compareEnd: state.compareEnd };
  }
  return { compare: state.compare };
}

export default function App() {
  const [state, setState] = useState(readUrlState);
  const [me, setMe] = useState(null);
  const [channels, setChannels] = useState([]);
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [syncing, setSyncing] = useState(false);
  const [connectedToast, setConnectedToast] = useState(null);

  const patch = useCallback((changes) => setState((s) => ({ ...s, ...changes })), []);

  useEffect(() => writeUrlState(state), [state]);

  // One-time bootstrap.
  useEffect(() => {
    api
      .me()
      .then((res) => {
        setMe(res.user);
        setCurrency(res.currency);
      })
      .catch(() => {});

    const params = new URLSearchParams(window.location.search);
    const connected = params.get('connected');
    if (connected) {
      setConnectedToast(connected);
      setTimeout(() => setConnectedToast(null), 6000);
    }
  }, []);

  const loadChannels = useCallback(async () => {
    const list = await api.channels();
    setChannels(list);
    return list;
  }, []);

  useEffect(() => {
    loadChannels().catch((err) => setError(err.message));
  }, [loadChannels]);

  // Main data load — refetches whenever the range, channel filter or
  // comparison mode changes.
  const loadAnalytics = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await api.analytics({
        start: state.start,
        end: state.end,
        channels: state.channels,
        compare: state.compare,
        ...comparisonParams(state),
      });
      setData(res);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }, [state.start, state.end, state.channels, state.compare, state.compareMonth, state.compareStart, state.compareEnd]);

  useEffect(() => {
    loadAnalytics();
  }, [loadAnalytics]);

  // Poll while a sync is running so the UI updates when it lands.
  useEffect(() => {
    if (!syncing) return;
    const timer = setInterval(async () => {
      try {
        const status = await api.syncStatus();
        if (!status.running) {
          setSyncing(false);
          await Promise.all([loadAnalytics(), loadChannels()]);
        }
      } catch {
        setSyncing(false);
      }
    }, 3000);
    return () => clearInterval(timer);
  }, [syncing, loadAnalytics, loadChannels]);

  const runSync = async (full = false) => {
    try {
      setSyncing(true);
      await api.runSync(full);
    } catch (err) {
      setSyncing(false);
      setError(err.message);
    }
  };

  // Bounds the calendar and the "All time" preset to what actually exists.
  const earliest = data?.dataRange?.min || undefined;

  /**
   * Whole months available as one-click comparison targets: the current month
   * (so far) and the twelve before it, bounded by the data we actually hold.
   */
  const monthChoices = useMemo(() => {
    const today = todayISO();
    const out = [];
    let cursor = startOfMonth(today);
    for (let i = 0; i < 13; i++) {
      const monthEnd = endOfMonth(cursor);
      if (earliest && monthEnd < earliest) break;
      out.push({
        key: cursor.slice(0, 7),
        start: cursor,
        end: monthEnd > today ? today : monthEnd,
        partial: monthEnd > today,
      });
      cursor = startOfMonth(addDays(cursor, -1));
    }
    return out;
  }, [earliest]);

  const compareSelectValue =
    state.compare === 'month' && state.compareMonth ? `month:${state.compareMonth}` : state.compare;

  const onCompareChange = (value) => {
    if (value.startsWith('month:')) {
      patch({ compare: 'month', compareMonth: value.slice(6) });
      return;
    }
    if (value === 'custom') {
      // Open the custom picker on last month's matching dates — the most likely
      // starting point — rather than on nothing.
      const seed = monthChoices[1] || monthChoices[0];
      const aligned = seed ? alignToMonth(state.start, state.end, seed.key) : null;
      patch({
        compare: 'custom',
        compareStart: state.compareStart || aligned?.start,
        compareEnd: state.compareEnd || aligned?.end,
      });
      return;
    }
    patch({ compare: value });
  };

  const compareLabel = useMemo(() => {
    if (state.compare === 'none' || !data?.comparison) return null;
    const { start, end } = data.comparison.range;
    const name = `${formatDate(start, 'short')} – ${formatDate(end, 'short')}`;
    // Only flagged when the two periods still differ in days with data — e.g.
    // today is partly measured, or a month is shorter than the range.
    return data.comparison.perDay ? `${name} · per day` : name;
  }, [state.compare, data]);

  const tokenIssues = channels.filter((c) => c.health && c.health.status !== 'ok').length;

  const exportUrl = api.exportUrl({
    start: state.start,
    end: state.end,
    channels: state.channels,
    scope: 'total',
  });
  const channelExportUrl = api.exportUrl({
    start: state.start,
    end: state.end,
    channels: state.channels,
    scope: 'channel',
  });

  const noChannels = channels.length === 0;

  return (
    <div className="min-h-full">
      <Header
        user={me}
        sync={data?.sync}
        estimation={data?.estimation}
        onSync={() => runSync(false)}
        syncing={syncing || data?.sync?.running}
        tokenIssues={tokenIssues}
      />

      {connectedToast && (
        <div className="fade-up mx-auto mt-3 max-w-[1600px] px-4 sm:px-6">
          <div className="rounded-lg border border-pos/30 bg-pos/10 px-4 py-2.5 text-sm text-pos">
            <strong>{connectedToast}</strong> connected. Its history is being pulled in the background — give it a
            minute, then hit Sync.
          </div>
        </div>
      )}

      {/* Controls */}
      <div className="sticky top-[53px] z-30 border-b border-line bg-bg/85 backdrop-blur-xl sm:top-[57px]">
        <div className="mx-auto max-w-[1600px] px-3 py-2 sm:flex sm:flex-wrap sm:items-center sm:gap-2 sm:px-6 sm:py-2.5">
          {/* Tabs get their own scrollable row on phones so they never squeeze
              the date picker off screen. */}
          <div className="scroll-x -mx-3 px-3 pb-2 sm:mx-0 sm:px-0 sm:pb-0">
            <Tabs
              tabs={TABS}
              value={state.tab}
              onChange={(tab) => patch({ tab })}
              size="sm"
              className="w-max"
            />
          </div>

          <div className="flex flex-wrap items-center gap-2 sm:ml-auto">
            {state.tab !== 'settings' && state.tab !== 'estimator' && state.tab !== 'trending' && (
              <>
                <ChannelFilter
                  channels={channels}
                  selected={state.channels}
                  onChange={(next) => patch({ channels: next })}
                />
                <select
                  value={compareSelectValue}
                  onChange={(e) => onCompareChange(e.target.value)}
                  className="max-w-[46vw] truncate rounded-lg border border-line bg-surface px-2.5 py-2 text-[13px] font-medium text-ink focus:border-accent/60 focus:outline-none sm:max-w-none"
                  title="What the current period is compared against"
                >
                  {COMPARE_OPTIONS.filter((o) => o.id !== 'none').map((opt) => (
                    <option key={opt.id} value={opt.id}>
                      {opt.label}
                    </option>
                  ))}
                  <optgroup label="Same dates in another month">
                    {monthChoices.map((m) => (
                      <option key={m.key} value={`month:${m.key}`}>
                        {formatMonth(m.key)} · same dates
                      </option>
                    ))}
                  </optgroup>
                  <option value="custom">Custom range…</option>
                  <option value="none">No comparison</option>
                </select>
                {state.compare === 'custom' && state.compareStart && (
                  <span className="flex items-center gap-1">
                    <span className="text-[11px] font-medium uppercase tracking-wide text-ink-dim">vs</span>
                    <DateRangePicker
                      start={state.compareStart}
                      end={state.compareEnd}
                      earliest={earliest}
                      onChange={({ start, end }) => patch({ compareStart: start, compareEnd: end })}
                    />
                  </span>
                )}
                <DateRangePicker
                  start={state.start}
                  end={state.end}
                  earliest={earliest}
                  onChange={({ start, end }) => patch({ start, end })}
                />
                <a href={exportUrl} download title="Download this period as CSV">
                  <Button size="sm" variant="ghost" className="px-2">
                    <Download size={14} />
                  </Button>
                </a>
              </>
            )}
          </div>
        </div>
      </div>

      <main className="mx-auto max-w-[1600px] space-y-3 px-3 py-3 sm:space-y-4 sm:px-6 sm:py-5">
        {error && (
          <Card className="border-neg/30 bg-neg/5">
            <div className="flex items-start gap-3 px-4 py-3">
              <AlertCircle size={16} className="mt-0.5 shrink-0 text-neg" />
              <div className="min-w-0 flex-1">
                <p className="text-sm font-medium text-neg">Something went wrong</p>
                <p className="mt-0.5 text-xs text-ink-dim">{error}</p>
              </div>
              <Button size="sm" onClick={loadAnalytics}>
                Retry
              </Button>
            </div>
          </Card>
        )}

        {noChannels && !loading && (
          <Card>
            <EmptyState
              title="No channels connected"
              description="Authorise a YouTube channel to start pulling revenue and view data. You can connect as many as you like — they all roll up into one dashboard."
              action={
                <Button variant="primary" onClick={() => (window.location.href = '/auth')}>
                  Connect your first channel
                </Button>
              }
            />
          </Card>
        )}

        {/* First run: channels are connected but the backfill has not landed. */}
        {!noChannels && data && !data.dataRange?.min && (
          <Card className="border-accent/30 bg-accent/5">
            <div className="flex items-start gap-3 px-4 py-3">
              <RefreshCw size={16} className="mt-0.5 shrink-0 animate-spin text-accent" />
              <div className="min-w-0 flex-1">
                <p className="text-sm font-medium text-accent">First sync in progress</p>
                <p className="mt-0.5 text-xs text-ink-dim">
                  Pulling history for {channels.length} channel{channels.length === 1 ? '' : 's'} from the
                  YouTube Analytics API. This takes a few minutes on the first run — the dashboard fills in as
                  it lands. Revenue estimates need about two weeks of history per channel before they mean
                  much.
                </p>
              </div>
              <Button size="sm" onClick={() => runSync(true)} disabled={syncing}>
                Start backfill
              </Button>
            </div>
          </Card>
        )}

        {!noChannels && (
          <>
            {state.tab === 'overview' && (
              <div className="space-y-4">
                <StatCards data={data} loading={loading && !data} compareLabel={compareLabel} />
                {data && <QuickStats data={data} />}
                {loading && !data ? (
                  <Skeleton className="h-[400px]" />
                ) : (
                  <MainChart
                    data={data}
                    metric={state.metric}
                    onMetricChange={(metric) => patch({ metric })}
                    compareLabel={compareLabel}
                  />
                )}
                {data && <ChannelsView data={data} metric={state.metric} compact />}
              </div>
            )}

            {state.tab === 'channels' &&
              (loading && !data ? <Skeleton className="h-96" /> : <ChannelsView data={data} metric={state.metric} />)}

            {state.tab === 'months' &&
              (loading && !data ? (
                <Skeleton className="h-96" />
              ) : (
                <MonthsView
                  data={data}
                  onPickMonth={(month) => {
                    const start = `${month}-01`;
                    const monthEnd = endOfMonth(start);
                    patch({ start, end: monthEnd > todayISO() ? todayISO() : monthEnd, tab: 'overview' });
                  }}
                />
              ))}

            {state.tab === 'trends' && (loading && !data ? <Skeleton className="h-96" /> : <TrendsView data={data} />)}

            {state.tab === 'videos' && (
              <VideosView
                range={{ start: state.start, end: state.end }}
                channels={state.channels}
                allChannels={channels}
              />
            )}

            {state.tab === 'daily' &&
              (loading && !data ? (
                <Skeleton className="h-96" />
              ) : (
                <DailyView data={data} exportUrl={exportUrl} channelExportUrl={channelExportUrl} />
              ))}

            {state.tab === 'trending' && (
              <TrendingView channels={state.channels} allChannels={channels} />
            )}

            {state.tab === 'estimator' && <EstimatorView data={data} />}

            {state.tab === 'settings' && (
              <SettingsView
                channels={channels}
                onChannelsChanged={async () => {
                  await loadChannels();
                  await loadAnalytics();
                }}
                onSync={runSync}
                syncing={syncing || data?.sync?.running}
              />
            )}
          </>
        )}

        <footer className="pt-2 text-center text-[11px] text-ink-dim">
          Revenue in {data?.currency || 'SEK'} · reported figures come from the YouTube Analytics API ·
          modelled days are marked in purple everywhere they appear
        </footer>
      </main>
    </div>
  );
}
