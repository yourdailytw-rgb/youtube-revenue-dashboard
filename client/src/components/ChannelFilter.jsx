import { useEffect, useRef, useState } from 'react';
import clsx from 'clsx';
import { ChevronDown, Check, AlertTriangle } from 'lucide-react';
import { ChannelAvatar } from './ui';
import { channelColor } from '../lib/metrics';

/** Multi-select channel filter. Empty selection means "all channels". */
export function ChannelFilter({ channels, selected, onChange }) {
  const [open, setOpen] = useState(false);
  const ref = useRef(null);

  useEffect(() => {
    if (!open) return;
    const onDocClick = (e) => ref.current && !ref.current.contains(e.target) && setOpen(false);
    document.addEventListener('mousedown', onDocClick);
    return () => document.removeEventListener('mousedown', onDocClick);
  }, [open]);

  const allSelected = selected.length === 0 || selected.length === channels.length;
  const toggle = (id) => {
    const current = selected.length === 0 ? channels.map((c) => c.id) : selected;
    const next = current.includes(id) ? current.filter((c) => c !== id) : [...current, id];
    onChange(next.length === channels.length ? [] : next);
  };

  const label = allSelected
    ? `All channels (${channels.length})`
    : selected.length === 1
      ? channels.find((c) => c.id === selected[0])?.title || '1 channel'
      : `${selected.length} channels`;

  return (
    <div className="relative" ref={ref}>
      <button
        onClick={() => setOpen((v) => !v)}
        className={clsx(
          'inline-flex items-center gap-2 rounded-lg border border-line bg-surface px-3 py-2 text-[13px] font-medium text-ink transition-colors hover:bg-surface-2',
          open && 'ring-2 ring-accent/40'
        )}
      >
        <span className="flex -space-x-1.5">
          {channels
            .filter((c) => allSelected || selected.includes(c.id))
            .slice(0, 3)
            .map((c, i) => (
              <span key={c.id} className="rounded-full ring-2 ring-surface">
                <ChannelAvatar channel={c} size={16} index={i} color={channelColor(i)} />
              </span>
            ))}
        </span>
        <span className="max-w-[140px] truncate">{label}</span>
        <ChevronDown size={13} className={clsx('text-ink-dim transition-transform', open && 'rotate-180')} />
      </button>

      {open && (
        <div className="fade-up absolute left-0 top-full z-50 mt-2 w-72 overflow-hidden rounded-xl border border-line bg-surface p-1.5 shadow-2xl shadow-black/50">
          <button
            onClick={() => onChange([])}
            className={clsx(
              'flex w-full items-center justify-between rounded-md px-2 py-1.5 text-[13px] transition-colors',
              allSelected ? 'bg-accent/15 text-accent' : 'text-ink-dim hover:bg-surface-2 hover:text-ink'
            )}
          >
            All channels
            {allSelected && <Check size={14} />}
          </button>

          <div className="my-1 h-px bg-line" />

          <div className="max-h-72 overflow-y-auto">
            {channels.map((channel, i) => {
              const isSelected = allSelected || selected.includes(channel.id);
              const unhealthy = channel.health && channel.health.status !== 'ok';
              return (
                <button
                  key={channel.id}
                  onClick={() => toggle(channel.id)}
                  className="flex w-full items-center gap-2 rounded-md px-2 py-1.5 text-left text-[13px] text-ink transition-colors hover:bg-surface-2"
                >
                  <span
                    className={clsx(
                      'grid h-4 w-4 shrink-0 place-items-center rounded border transition-colors',
                      isSelected ? 'border-accent bg-accent' : 'border-line'
                    )}
                  >
                    {isSelected && <Check size={11} className="text-white" strokeWidth={3} />}
                  </span>
                  <ChannelAvatar channel={channel} size={18} index={i} color={channelColor(i)} />
                  <span className="min-w-0 flex-1 truncate">{channel.title}</span>
                  {unhealthy && (
                    <AlertTriangle
                      size={13}
                      className="shrink-0 text-warn"
                      title={channel.health.error || 'Needs reconnecting'}
                    />
                  )}
                  <span
                    className="h-2 w-2 shrink-0 rounded-full"
                    style={{ background: channelColor(i) }}
                    aria-hidden="true"
                  />
                </button>
              );
            })}
          </div>

          {channels.length > 1 && (
            <>
              <div className="my-1 h-px bg-line" />
              <div className="flex gap-1 px-1 pb-0.5">
                <button
                  onClick={() => onChange([])}
                  className="flex-1 rounded-md px-2 py-1 text-xs text-ink-dim hover:bg-surface-2 hover:text-ink"
                >
                  Select all
                </button>
                <button
                  onClick={() => onChange(channels.slice(0, 1).map((c) => c.id))}
                  className="flex-1 rounded-md px-2 py-1 text-xs text-ink-dim hover:bg-surface-2 hover:text-ink"
                >
                  Clear
                </button>
              </div>
            </>
          )}
        </div>
      )}
    </div>
  );
}
