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
import { setCurrency, formatDate } from './lib/format';
import { todayISO, addDays, startOfMonth, endOfMonth } from './lib/ranges';

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

/** URL state so a view can be shared or reloaded without losing context. */
function readUrlState() {
  const params = new URLSearchParams(window.location.search);
  const today = todayISO();
  return {
    tab: params.get('tab') || 'overview',
    start: params.get('start') || addDays(today, -29),
    end: params.get('end') || today,
    channels: params.get('channels') ? params.get('channels').split(',').filter(Boolean) : [],
    compare: params.get('compare') || 'previous',
    metric: params.get('metric') || 'revenue',
  };
}

function writeUrlState(state) {
  const params = new URLSearchParams();
  params.set('tab', state.tab);
  params.set('start', state.start);
  params.set('end', state.end);
  params.set('compare', state.compare);
  params.set('metric', state.metric);
  if (state.channels.length) params.set('channels', state.channels.join(','));
  window.history.replaceState(null, '', `?${params.toString()}`);
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
      });
      setData(res);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }, [state.start, state.end, state.channels, state.compare]);

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

  const compareLabel = useMemo(() => {
    if (state.compare === 'none' || !data?.comparison) return null;
    const { start, end } = data.comparison.range;
    return `${formatDate(start, 'short')} – ${formatDate(end, 'short')}`;
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
                  value={state.compare}
                  onChange={(e) => patch({ compare: e.target.value })}
                  className="max-w-[46vw] truncate rounded-lg border border-line bg-surface px-2.5 py-2 text-[13px] font-medium text-ink focus:border-accent/60 focus:outline-none sm:max-w-none"
                  title="What the current period is compared against"
                >
                  {COMPARE_OPTIONS.map((opt) => (
                    <option key={opt.id} value={opt.id}>
                      {opt.label}
                    </option>
                  ))}
                </select>
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
