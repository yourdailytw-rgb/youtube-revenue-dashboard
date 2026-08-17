import clsx from 'clsx';
import { TrendingUp, TrendingDown, Minus } from 'lucide-react';
import { formatPct } from '../lib/format';

export function Card({ className, children, ...props }) {
  return (
    <div
      className={clsx('rounded-xl border border-line bg-surface', className)}
      {...props}
    >
      {children}
    </div>
  );
}

export function CardHeader({ title, subtitle, action, className }) {
  return (
    <div
      className={clsx(
        'flex flex-wrap items-start justify-between gap-2 px-4 pt-3.5 pb-3 sm:flex-nowrap sm:gap-4 sm:px-5 sm:pt-4',
        className
      )}
    >
      <div className="min-w-0">
        <h3 className="text-sm font-semibold tracking-tight text-ink">{title}</h3>
        {subtitle && <p className="mt-0.5 text-xs text-ink-dim">{subtitle}</p>}
      </div>
      {action && <div className="w-full shrink-0 sm:w-auto">{action}</div>}
    </div>
  );
}

export function Button({ variant = 'default', size = 'md', className, children, ...props }) {
  return (
    <button
      className={clsx(
        'inline-flex items-center justify-center gap-1.5 rounded-lg font-medium transition-colors',
        'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent/50',
        'disabled:cursor-not-allowed disabled:opacity-50',
        size === 'sm' && 'px-2.5 py-1.5 text-xs max-sm:py-2',
        size === 'md' && 'px-3 py-2 text-sm',
        variant === 'default' && 'border border-line bg-surface-2 text-ink hover:bg-line',
        variant === 'primary' && 'bg-accent text-white hover:bg-accent/85',
        variant === 'ghost' && 'text-ink-dim hover:bg-surface-2 hover:text-ink',
        variant === 'danger' && 'border border-neg/40 bg-neg/10 text-neg hover:bg-neg/20',
        className
      )}
      {...props}
    >
      {children}
    </button>
  );
}

export function Badge({ tone = 'neutral', className, children, title }) {
  return (
    <span
      title={title}
      className={clsx(
        'inline-flex items-center gap-1 rounded-md px-1.5 py-0.5 text-[11px] font-medium',
        tone === 'neutral' && 'bg-surface-2 text-ink-dim',
        tone === 'accent' && 'bg-accent/15 text-accent',
        tone === 'pos' && 'bg-pos/15 text-pos',
        tone === 'neg' && 'bg-neg/15 text-neg',
        tone === 'warn' && 'bg-warn/15 text-warn',
        tone === 'est' && 'bg-est/15 text-est',
        className
      )}
    >
      {children}
    </span>
  );
}

/**
 * A percentage change. `inverse` flips the colour logic for metrics where down
 * is good (nothing uses it yet, but subs lost / churn would).
 */
export function Delta({ value, className, showIcon = true, inverse = false, size = 'sm' }) {
  if (value === null || value === undefined || !Number.isFinite(value)) {
    return <span className={clsx('text-ink-dim', className)}>—</span>;
  }
  const positive = inverse ? value < 0 : value > 0;
  const flat = Math.abs(value) < 0.0005;
  const Icon = flat ? Minus : positive ? TrendingUp : TrendingDown;

  return (
    <span
      className={clsx(
        'inline-flex items-center gap-1 font-medium tabular',
        size === 'sm' ? 'text-xs' : 'text-sm',
        flat ? 'text-ink-dim' : positive ? 'text-pos' : 'text-neg',
        className
      )}
    >
      {showIcon && <Icon size={size === 'sm' ? 12 : 14} strokeWidth={2.5} />}
      {formatPct(value, { sign: true })}
    </span>
  );
}

export function Tabs({ tabs, value, onChange, className, size = 'md' }) {
  return (
    <div
      className={clsx(
        'inline-flex items-center gap-0.5 rounded-lg border border-line bg-surface p-0.5',
        className
      )}
      role="tablist"
    >
      {tabs.map((tab) => (
        <button
          key={tab.id}
          role="tab"
          aria-selected={value === tab.id}
          onClick={() => onChange(tab.id)}
          title={tab.description}
          className={clsx(
            'inline-flex items-center gap-1.5 rounded-md font-medium transition-colors whitespace-nowrap',
            size === 'sm' ? 'px-2.5 py-1 text-xs' : 'px-3 py-1.5 text-[13px]',
            value === tab.id ? 'bg-surface-2 text-ink shadow-sm' : 'text-ink-dim hover:text-ink'
          )}
        >
          {tab.icon}
          {tab.label}
        </button>
      ))}
    </div>
  );
}

export function Skeleton({ className }) {
  return <div className={clsx('skeleton rounded-lg', className)} />;
}

export function EmptyState({ icon, title, description, action }) {
  return (
    <div className="flex flex-col items-center justify-center gap-3 px-6 py-14 text-center">
      {icon && <div className="text-ink-dim opacity-60">{icon}</div>}
      <div>
        <p className="text-sm font-medium text-ink">{title}</p>
        {description && <p className="mx-auto mt-1 max-w-sm text-xs text-ink-dim">{description}</p>}
      </div>
      {action}
    </div>
  );
}

/** Small label + value pair used across panels. */
export function Stat({ label, value, hint, tone }) {
  return (
    <div className="min-w-0">
      <p className="text-[11px] uppercase tracking-wide text-ink-dim">{label}</p>
      <p
        className={clsx(
          'mt-0.5 truncate text-sm font-semibold tabular',
          tone === 'pos' && 'text-pos',
          tone === 'neg' && 'text-neg',
          tone === 'est' && 'text-est',
          !tone && 'text-ink'
        )}
      >
        {value}
      </p>
      {hint && <p className="mt-0.5 truncate text-[11px] text-ink-dim">{hint}</p>}
    </div>
  );
}

export function ChannelAvatar({ channel, size = 20, index = 0, color }) {
  const initials = (channel.title || '?')
    .split(/\s+/)
    .slice(0, 2)
    .map((w) => w[0])
    .join('')
    .toUpperCase();

  if (channel.thumbnail) {
    return (
      <img
        src={channel.thumbnail}
        alt=""
        width={size}
        height={size}
        className="shrink-0 rounded-full object-cover"
        style={{ width: size, height: size }}
      />
    );
  }
  return (
    <span
      className="inline-flex shrink-0 items-center justify-center rounded-full font-semibold text-white"
      style={{
        width: size,
        height: size,
        fontSize: size * 0.4,
        background: color || `hsl(${(index * 67) % 360} 55% 45%)`,
      }}
    >
      {initials}
    </span>
  );
}
