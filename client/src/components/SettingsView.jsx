import { useEffect, useState } from 'react';
import clsx from 'clsx';
import {
  RefreshCw,
  Trash2,
  Plus,
  Database,
  KeyRound,
  CheckCircle2,
  AlertTriangle,
  HardDrive,
} from 'lucide-react';
import { Card, CardHeader, Button, Badge, Stat, ChannelAvatar, Skeleton } from './ui';
import { api } from '../lib/api';
import { relativeTime, formatDate, formatNumber } from '../lib/format';
import { channelColor } from '../lib/metrics';

/** Channels, token health, sync controls and storage diagnostics. */
export function SettingsView({ channels, onChannelsChanged, onSync, syncing }) {
  const [status, setStatus] = useState(null);
  const [storage, setStorage] = useState(null);
  const [busy, setBusy] = useState(null);
  const [editing, setEditing] = useState(null);
  const [draft, setDraft] = useState({});

  const load = () => {
    api.syncStatus().then(setStatus).catch(() => {});
    api.storageStatus().then(setStorage).catch(() => {});
  };

  useEffect(load, []);
  useEffect(() => {
    if (!syncing) load();
  }, [syncing]);

  const disconnect = async (channel) => {
    if (!window.confirm(`Disconnect ${channel.title}? Its stored history stays in the database unless you also purge it.`)) {
      return;
    }
    setBusy(channel.id);
    try {
      await api.disconnectChannel(channel.id, false);
      await onChannelsChanged();
    } finally {
      setBusy(null);
    }
  };

  const saveChannel = async (channel) => {
    setBusy(channel.id);
    try {
      await api.updateChannel(channel.id, draft);
      setEditing(null);
      await onChannelsChanged();
    } finally {
      setBusy(null);
    }
  };

  const refreshTokens = async () => {
    setBusy('tokens');
    try {
      await api.refreshTokens();
      load();
      await onChannelsChanged();
    } finally {
      setBusy(null);
    }
  };

  return (
    <div className="space-y-4">
      <Card>
        <CardHeader
          title="Connected channels"
          subtitle={`${channels.length} channel${channels.length === 1 ? '' : 's'} — OAuth tokens are stored on the Railway volume and backed up to the STORED_TOKENS env var`}
          action={
            <Button size="sm" variant="primary" onClick={() => (window.location.href = '/auth')}>
              <Plus size={13} />
              Connect
            </Button>
          }
        />
        <div className="divide-y divide-line-soft">
          {channels.map((channel, index) => {
            const health = channel.health;
            const ok = !health || health.status === 'ok';
            const isEditing = editing === channel.id;

            return (
              <div key={channel.id} className="flex flex-wrap items-center gap-3 px-4 py-3">
                <ChannelAvatar channel={channel} size={34} index={index} color={channelColor(index)} />

                <div className="min-w-0 flex-1">
                  {isEditing ? (
                    <div className="flex flex-wrap items-center gap-2">
                      <input
                        value={draft.customName ?? ''}
                        onChange={(e) => setDraft((d) => ({ ...d, customName: e.target.value }))}
                        placeholder={channel.originalTitle}
                        className="w-44 rounded-lg border border-line bg-surface-2 px-2 py-1.5 text-sm text-ink focus:border-accent/60 focus:outline-none"
                      />
                      <input
                        value={draft.groupName ?? ''}
                        onChange={(e) => setDraft((d) => ({ ...d, groupName: e.target.value }))}
                        placeholder="Group (optional)"
                        className="w-36 rounded-lg border border-line bg-surface-2 px-2 py-1.5 text-sm text-ink focus:border-accent/60 focus:outline-none"
                      />
                      <Button size="sm" variant="primary" onClick={() => saveChannel(channel)} disabled={busy === channel.id}>
                        Save
                      </Button>
                      <Button size="sm" variant="ghost" onClick={() => setEditing(null)}>
                        Cancel
                      </Button>
                    </div>
                  ) : (
                    <>
                      <p className="truncate text-sm font-medium text-ink">
                        {channel.title}
                        {channel.group && (
                          <Badge tone="neutral" className="ml-2">
                            {channel.group}
                          </Badge>
                        )}
                      </p>
                      <p className="truncate text-[11px] text-ink-dim">
                        Connected {channel.connectedAt ? formatDate(channel.connectedAt.slice(0, 10)) : '—'}
                        {channel.lastSync && <> · synced {relativeTime(channel.lastSync)}</>}
                      </p>
                    </>
                  )}
                </div>

                <div className="flex shrink-0 items-center gap-2">
                  {ok ? (
                    <Badge tone="pos" title={health?.lastChecked ? `Checked ${relativeTime(health.lastChecked)}` : undefined}>
                      <CheckCircle2 size={11} />
                      healthy
                    </Badge>
                  ) : (
                    <Badge tone={health.status === 'expired' ? 'neg' : 'warn'} title={health.error}>
                      <AlertTriangle size={11} />
                      {health.status === 'expired' ? 'reconnect needed' : 'error'}
                    </Badge>
                  )}

                  {!isEditing && (
                    <>
                      <Button
                        size="sm"
                        variant="ghost"
                        onClick={() => {
                          setEditing(channel.id);
                          setDraft({ customName: channel.title, groupName: channel.group || '' });
                        }}
                      >
                        Rename
                      </Button>
                      {health?.status === 'expired' && (
                        <Button size="sm" variant="primary" onClick={() => (window.location.href = '/auth')}>
                          Reconnect
                        </Button>
                      )}
                      <Button
                        size="sm"
                        variant="danger"
                        onClick={() => disconnect(channel)}
                        disabled={busy === channel.id}
                        title="Disconnect this channel"
                      >
                        <Trash2 size={13} />
                      </Button>
                    </>
                  )}
                </div>

                {!ok && health?.error && (
                  <p className="w-full rounded-lg bg-neg/10 px-3 py-2 text-[11px] text-neg">{health.error}</p>
                )}
              </div>
            );
          })}
          {channels.length === 0 && (
            <p className="px-4 py-8 text-center text-sm text-ink-dim">
              No channels connected yet. Click <strong className="text-ink">Connect</strong> to authorise one.
            </p>
          )}
        </div>
      </Card>

      <div className="grid gap-4 lg:grid-cols-2">
        <Card>
          <CardHeader
            title="Data sync"
            subtitle="Pulls the YouTube Analytics API into the local database"
            action={<Database size={15} className="text-ink-dim" />}
          />
          <div className="grid grid-cols-2 gap-4 px-5 pb-3">
            <Stat
              label="Last sync"
              value={status?.lastRun ? relativeTime(status.lastRun.at) : 'never'}
              hint={status?.lastRun ? `${status.lastRun.channels} channels · ${Math.round((status.lastRun.durationMs || 0) / 1000)}s` : undefined}
            />
            <Stat label="Interval" value={`every ${status?.intervalMinutes ?? '—'} min`} />
            <Stat label="Days stored" value={formatNumber(status?.db?.dailyRows ?? 0)} hint="channel-days" />
            <Stat
              label="History"
              value={
                status?.db?.dateRange?.min
                  ? `${formatDate(status.db.dateRange.min, 'short')} → ${formatDate(status.db.dateRange.max, 'short')}`
                  : '—'
              }
            />
          </div>
          <div className="flex flex-wrap gap-2 border-t border-line px-5 py-3">
            <Button size="sm" onClick={() => onSync(false)} disabled={syncing || status?.running}>
              <RefreshCw size={13} className={clsx((syncing || status?.running) && 'animate-spin')} />
              Sync recent
            </Button>
            <Button
              size="sm"
              onClick={() => {
                if (window.confirm('Re-fetch all history from scratch? This makes many API calls and can take a few minutes.')) {
                  onSync(true);
                }
              }}
              disabled={syncing || status?.running}
            >
              Full backfill
            </Button>
            <Button size="sm" variant="ghost" onClick={refreshTokens} disabled={busy === 'tokens'}>
              <KeyRound size={13} />
              Refresh tokens
            </Button>
          </div>
        </Card>

        <Card>
          <CardHeader
            title="Storage"
            subtitle="Where tokens and metrics live"
            action={<HardDrive size={15} className="text-ink-dim" />}
          />
          {!storage ? (
            <div className="p-4">
              <Skeleton className="h-24" />
            </div>
          ) : (
            <div className="space-y-3 px-5 pb-4">
              <div
                className={clsx(
                  'rounded-lg border px-3 py-2 text-xs',
                  storage.tokens.onVolume
                    ? 'border-pos/30 bg-pos/10 text-pos'
                    : 'border-warn/30 bg-warn/10 text-warn'
                )}
              >
                {storage.tokens.onVolume
                  ? 'Railway Volume mounted at /data — tokens and history survive deploys.'
                  : 'No Railway Volume at /data. Data will be lost on the next deploy unless the volume is mounted.'}
              </div>

              <div className="grid grid-cols-2 gap-3">
                <Stat
                  label="Volume tokens"
                  value={storage.tokens.volumeFile.exists ? `${storage.tokens.volumeFile.channels} channels` : 'absent'}
                />
                <Stat
                  label="Local tokens"
                  value={storage.tokens.localFile.exists ? `${storage.tokens.localFile.channels} channels` : 'absent'}
                />
                <Stat
                  label="STORED_TOKENS backup"
                  value={storage.tokens.storedTokensEnv.present ? 'present' : 'missing'}
                  tone={storage.tokens.storedTokensEnv.present ? 'pos' : undefined}
                />
                <Stat
                  label="Railway API backup"
                  value={storage.tokens.railwayBackupConfigured ? 'configured' : 'not configured'}
                  tone={storage.tokens.railwayBackupConfigured ? 'pos' : undefined}
                />
              </div>

              <div className="rounded-lg bg-surface-2/50 px-3 py-2 text-[11px] text-ink-dim">
                <p className="mb-1 font-medium text-ink">Database</p>
                <p className="truncate">{storage.db.file}</p>
                <p>
                  {formatNumber(storage.db.dailyRows)} daily rows · {storage.db.estimates} live estimates ·{' '}
                  {storage.db.videos} videos cached
                </p>
              </div>
            </div>
          )}
        </Card>
      </div>
    </div>
  );
}
