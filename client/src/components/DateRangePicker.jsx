import { useEffect, useMemo, useRef, useState } from 'react';
import { DayPicker } from 'react-day-picker';
import 'react-day-picker/style.css';
import clsx from 'clsx';
import { Calendar, ChevronDown, ChevronLeft, ChevronRight, Check } from 'lucide-react';
import { Button } from './ui';
import { formatDate, formatMonth } from '../lib/format';
import {
  buildPresets,
  matchPreset,
  monthOptions,
  toISO,
  parseISO,
  todayISO,
  addDays,
  addMonths,
  diffDays,
  startOfMonth,
  endOfMonth,
} from '../lib/ranges';

/**
 * Range picker built for "take me to a specific month" as much as for
 * "last 30 days":
 *   - preset list down the left
 *   - a month grid per year so any month is two clicks away
 *   - a two-month calendar for exact day selection
 *   - ← → step buttons that shift the whole range by its own length
 */
export function DateRangePicker({ start, end, onChange, earliest }) {
  const [open, setOpen] = useState(false);
  const [tab, setTab] = useState('presets');
  const [draft, setDraft] = useState({ from: parseISO(start), to: parseISO(end) });
  const [monthYear, setMonthYear] = useState(Number(end.slice(0, 4)));
  const ref = useRef(null);

  const presets = useMemo(() => buildPresets(earliest), [earliest]);
  const activePreset = matchPreset(start, end, presets);

  useEffect(() => {
    setDraft({ from: parseISO(start), to: parseISO(end) });
  }, [start, end]);

  useEffect(() => {
    if (!open) return;
    const onDocClick = (e) => {
      if (ref.current && !ref.current.contains(e.target)) setOpen(false);
    };
    const onKey = (e) => e.key === 'Escape' && setOpen(false);
    document.addEventListener('mousedown', onDocClick);
    document.addEventListener('keydown', onKey);
    return () => {
      document.removeEventListener('mousedown', onDocClick);
      document.removeEventListener('keydown', onKey);
    };
  }, [open]);

  const apply = (nextStart, nextEnd) => {
    onChange({ start: nextStart, end: nextEnd });
    setOpen(false);
  };

  const shift = (direction) => {
    const len = diffDays(start, end) + 1;
    onChange({ start: addDays(start, direction * len), end: addDays(end, direction * len) });
  };

  const label = activePreset
    ? presets.find((p) => p.id === activePreset).label
    : `${formatDate(start, 'short')} – ${formatDate(end)}`;

  const groups = ['Recent', 'Months', 'Years'];

  return (
    <div className="relative flex items-center gap-1" ref={ref}>
      <Button
        variant="ghost"
        size="sm"
        onClick={() => shift(-1)}
        title="Previous period"
        aria-label="Previous period"
        className="px-1.5"
      >
        <ChevronLeft size={15} />
      </Button>

      <button
        onClick={() => setOpen((v) => !v)}
        className={clsx(
          'inline-flex items-center gap-2 rounded-lg border border-line bg-surface px-3 py-2 text-[13px] font-medium text-ink transition-colors hover:bg-surface-2',
          open && 'ring-2 ring-accent/40'
        )}
      >
        <Calendar size={14} className="text-ink-dim" />
        <span className="tabular">{label}</span>
        <span className="text-[11px] text-ink-dim">{diffDays(start, end) + 1}d</span>
        <ChevronDown size={13} className={clsx('text-ink-dim transition-transform', open && 'rotate-180')} />
      </button>

      <Button
        variant="ghost"
        size="sm"
        onClick={() => shift(1)}
        disabled={end >= todayISO()}
        title="Next period"
        aria-label="Next period"
        className="px-1.5"
      >
        <ChevronRight size={15} />
      </Button>

      {open && (
        <div className="fade-up absolute right-0 top-full z-50 mt-2 w-[min(94vw,720px)] overflow-hidden rounded-xl border border-line bg-surface shadow-2xl shadow-black/50">
          <div className="flex flex-col sm:flex-row">
            {/* Presets */}
            <div className="w-full shrink-0 border-b border-line p-2 sm:w-44 sm:border-b-0 sm:border-r">
              <div className="max-h-[360px] overflow-y-auto">
                {groups.map((group) => (
                  <div key={group} className="mb-1">
                    <p className="px-2 py-1 text-[10px] font-semibold uppercase tracking-wider text-ink-dim">
                      {group}
                    </p>
                    {presets
                      .filter((p) => p.group === group)
                      .map((preset) => (
                        <button
                          key={preset.id}
                          onClick={() => apply(preset.start, preset.end)}
                          className={clsx(
                            'flex w-full items-center justify-between rounded-md px-2 py-1.5 text-left text-[13px] transition-colors',
                            activePreset === preset.id
                              ? 'bg-accent/15 text-accent'
                              : 'text-ink-dim hover:bg-surface-2 hover:text-ink'
                          )}
                        >
                          {preset.label}
                          {activePreset === preset.id && <Check size={13} />}
                        </button>
                      ))}
                  </div>
                ))}
              </div>
            </div>

            {/* Calendar / month grid */}
            <div className="min-w-0 flex-1">
              <div className="flex items-center justify-between border-b border-line px-3 py-2">
                <div className="inline-flex gap-0.5 rounded-lg bg-surface-2 p-0.5">
                  {[
                    { id: 'presets', label: 'Calendar' },
                    { id: 'months', label: 'Pick a month' },
                  ].map((t) => (
                    <button
                      key={t.id}
                      onClick={() => setTab(t.id)}
                      className={clsx(
                        'rounded-md px-2.5 py-1 text-xs font-medium transition-colors',
                        tab === t.id ? 'bg-surface text-ink' : 'text-ink-dim hover:text-ink'
                      )}
                    >
                      {t.label}
                    </button>
                  ))}
                </div>
                <p className="tabular text-[11px] text-ink-dim">
                  {formatDate(start)} → {formatDate(end)}
                </p>
              </div>

              {tab === 'presets' ? (
                <div className="p-2">
                  <DayPicker
                    mode="range"
                    numberOfMonths={windowWidthMonths()}
                    defaultMonth={parseISO(start)}
                    selected={draft}
                    onSelect={(range) => setDraft(range || {})}
                    weekStartsOn={1}
                    showOutsideDays
                    captionLayout="dropdown"
                    startMonth={parseISO(earliest || '2020-01-01')}
                    endMonth={new Date()}
                    disabled={{ after: new Date() }}
                  />
                  <div className="flex items-center justify-between border-t border-line px-2 pt-2">
                    <p className="text-[11px] text-ink-dim">
                      {draft?.from && draft?.to
                        ? `${diffDays(toISO(draft.from), toISO(draft.to)) + 1} days selected`
                        : 'Pick a start and end date'}
                    </p>
                    <div className="flex gap-2">
                      <Button size="sm" variant="ghost" onClick={() => setOpen(false)}>
                        Cancel
                      </Button>
                      <Button
                        size="sm"
                        variant="primary"
                        disabled={!draft?.from}
                        onClick={() => apply(toISO(draft.from), toISO(draft.to || draft.from))}
                      >
                        Apply
                      </Button>
                    </div>
                  </div>
                </div>
              ) : (
                <MonthGrid
                  year={monthYear}
                  onYearChange={setMonthYear}
                  earliest={earliest}
                  onPick={apply}
                  currentStart={start}
                  currentEnd={end}
                />
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

function windowWidthMonths() {
  if (typeof window === 'undefined') return 2;
  return window.innerWidth < 720 ? 1 : 2;
}

/** Year selector + 12 month buttons + whole-year and quarter shortcuts. */
function MonthGrid({ year, onYearChange, earliest, onPick, currentStart, currentEnd }) {
  const thisYear = new Date().getFullYear();
  const firstYear = Number((earliest || '2024-01-01').slice(0, 4));
  const years = [];
  for (let y = thisYear; y >= firstYear; y--) years.push(y);

  const months = monthOptions(year);
  const today = todayISO();

  return (
    <div className="p-3">
      <div className="mb-3 flex items-center justify-center gap-1">
        <Button
          variant="ghost"
          size="sm"
          className="px-1.5"
          disabled={year <= firstYear}
          onClick={() => onYearChange(year - 1)}
        >
          <ChevronLeft size={15} />
        </Button>
        <select
          value={year}
          onChange={(e) => onYearChange(Number(e.target.value))}
          className="rounded-md border border-line bg-surface-2 px-2 py-1 text-sm font-semibold text-ink"
        >
          {years.map((y) => (
            <option key={y} value={y}>
              {y}
            </option>
          ))}
        </select>
        <Button
          variant="ghost"
          size="sm"
          className="px-1.5"
          disabled={year >= thisYear}
          onClick={() => onYearChange(year + 1)}
        >
          <ChevronRight size={15} />
        </Button>
      </div>

      <div className="grid grid-cols-3 gap-1.5 sm:grid-cols-4">
        {months.map((m) => {
          const disabled = m.start > today;
          const selected = currentStart === m.start && currentEnd === m.end;
          const capped = m.end > today ? today : m.end;
          return (
            <button
              key={m.month}
              disabled={disabled}
              onClick={() => onPick(m.start, capped)}
              className={clsx(
                'rounded-lg border px-2 py-2 text-xs font-medium transition-colors',
                disabled && 'cursor-not-allowed border-line-soft text-ink-dim opacity-40',
                !disabled && selected
                  ? 'border-accent bg-accent/15 text-accent'
                  : !disabled && 'border-line bg-surface-2 text-ink-dim hover:border-accent/40 hover:text-ink'
              )}
            >
              {formatMonth(m.start, { short: true }).split(' ')[0]}
            </button>
          );
        })}
      </div>

      <div className="mt-3 border-t border-line pt-3">
        <p className="mb-1.5 text-[10px] font-semibold uppercase tracking-wider text-ink-dim">
          Quarters &amp; full year
        </p>
        <div className="grid grid-cols-5 gap-1.5">
          {[1, 2, 3, 4].map((q) => {
            const qStart = `${year}-${String((q - 1) * 3 + 1).padStart(2, '0')}-01`;
            const qEnd = endOfMonth(`${year}-${String(q * 3).padStart(2, '0')}-01`);
            const disabled = qStart > today;
            return (
              <button
                key={q}
                disabled={disabled}
                onClick={() => onPick(qStart, qEnd > today ? today : qEnd)}
                className={clsx(
                  'rounded-lg border border-line bg-surface-2 px-2 py-1.5 text-xs font-medium transition-colors',
                  disabled
                    ? 'cursor-not-allowed opacity-40 text-ink-dim'
                    : 'text-ink-dim hover:border-accent/40 hover:text-ink'
                )}
              >
                Q{q}
              </button>
            );
          })}
          <button
            onClick={() => {
              const yEnd = `${year}-12-31`;
              onPick(`${year}-01-01`, yEnd > today ? today : yEnd);
            }}
            className="rounded-lg border border-line bg-surface-2 px-2 py-1.5 text-xs font-medium text-ink-dim transition-colors hover:border-accent/40 hover:text-ink"
          >
            {year}
          </button>
        </div>
      </div>
    </div>
  );
}
