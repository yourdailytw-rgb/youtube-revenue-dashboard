import clsx from 'clsx';
import { RefreshCw, Plus, LogOut, Zap, AlertTriangle } from 'lucide-react';
import { Button, Badge } from './ui';
import { relativeTime, formatDate } from '../lib/format';

export function Header({ user, sync, estimation, onSync, syncing, tokenIssues }) {
  const delay = estimation?.delayDays;

  return (
    <header className="sticky top-0 z-40 border-b border-line bg-bg/85 backdrop-blur-xl">
      <div className="mx-auto flex max-w-[1600px] items-center gap-2 px-3 py-2.5 sm:gap-3 sm:px-6 sm:py-3">
        <div className="flex min-w-0 items-center gap-2.5">
          <span className="grid h-7 w-7 shrink-0 place-items-center rounded-lg bg-neg/90">
            <svg viewBox="0 0 24 24" width="13" height="13" fill="white" aria-hidden="true">
              <path d="M9 7.5l8 4.5-8 4.5z" />
            </svg>
          </span>
          <div className="min-w-0">
            <h1 className="truncate text-[15px] font-semibold leading-tight tracking-tight">
              Revenue Dashboard
            </h1>
            <p className="hidden text-[11px] leading-tight text-ink-dim sm:block">
              {sync?.lastRun ? `Synced ${relativeTime(sync.lastRun.at)}` : 'Not synced yet'}
              {estimation?.lastRevenueDate && (
                <> · YouTube reported through {formatDate(estimation.lastRevenueDate, 'short')}</>
              )}
            </p>
          </div>
        </div>

        <div className="ml-auto flex shrink-0 items-center gap-1.5 sm:gap-2">
          {delay > 0 && (
            <Badge
              tone="est"
              title={`YouTube's revenue reporting lags ${delay} day${delay > 1 ? 's' : ''} behind views. Those days are filled with modelled revenue.`}
            >
              <Zap size={11} />
              {delay} day{delay > 1 ? 's' : ''} estimated
            </Badge>
          )}

          {tokenIssues > 0 && (
            <Badge tone="neg" title="One or more channels need reconnecting">
              <AlertTriangle size={11} />
              {tokenIssues} channel{tokenIssues > 1 ? 's' : ''} need attention
            </Badge>
          )}

          <Button size="sm" onClick={onSync} disabled={syncing} title="Pull the latest data from YouTube">
            <RefreshCw size={13} className={clsx(syncing && 'animate-spin')} />
            <span className="hidden sm:inline">{syncing ? 'Syncing…' : 'Sync'}</span>
          </Button>

          <Button size="sm" variant="primary" onClick={() => (window.location.href = '/auth')}>
            <Plus size={13} />
            <span className="hidden sm:inline">Connect channel</span>
          </Button>

          {user?.username && user.username !== 'open-access' && (
            <a
              href="/logout"
              title={`Signed in as ${user.username}`}
              className="inline-flex items-center gap-1.5 rounded-lg px-2 py-2 text-xs text-ink-dim transition-colors hover:bg-surface-2 hover:text-ink"
            >
              <LogOut size={13} />
              <span className="hidden lg:inline">{user.username}</span>
            </a>
          )}
        </div>
      </div>
    </header>
  );
}
