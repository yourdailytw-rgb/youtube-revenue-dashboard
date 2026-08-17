/** Date helpers + range presets. All dates are 'YYYY-MM-DD' strings. */

const DAY = 86400000;

export const toISO = (date) =>
  `${date.getFullYear()}-${String(date.getMonth() + 1).padStart(2, '0')}-${String(date.getDate()).padStart(2, '0')}`;

export const parseISO = (iso) => {
  const [y, m, d] = iso.split('-').map(Number);
  return new Date(y, m - 1, d);
};

export const todayISO = () => toISO(new Date());

export const addDays = (iso, n) => toISO(new Date(parseISO(iso).getTime() + n * DAY));

export const diffDays = (a, b) => Math.round((parseISO(b) - parseISO(a)) / DAY);

export const startOfMonth = (iso) => `${iso.slice(0, 7)}-01`;

export const endOfMonth = (iso) => {
  const [y, m] = iso.split('-').map(Number);
  return toISO(new Date(y, m, 0));
};

export const addMonths = (iso, n) => {
  const [y, m, d] = iso.split('-').map(Number);
  const target = new Date(y, m - 1 + n, 1);
  const lastDay = new Date(target.getFullYear(), target.getMonth() + 1, 0).getDate();
  target.setDate(Math.min(d, lastDay));
  return toISO(target);
};

/**
 * Preset ranges. `end` is today — the dashboard fills the last two days with
 * modelled revenue rather than hiding them, which is the whole point of the
 * estimator, so there is no reason to end ranges two days in the past.
 */
export function buildPresets(earliest) {
  const today = todayISO();
  const thisMonthStart = startOfMonth(today);
  const lastMonthEnd = addDays(thisMonthStart, -1);
  const lastMonthStart = startOfMonth(lastMonthEnd);
  const year = today.slice(0, 4);

  return [
    { id: '7d', label: 'Last 7 days', group: 'Recent', start: addDays(today, -6), end: today },
    { id: '28d', label: 'Last 28 days', group: 'Recent', start: addDays(today, -27), end: today },
    { id: '90d', label: 'Last 90 days', group: 'Recent', start: addDays(today, -89), end: today },
    { id: 'mtd', label: 'This month', group: 'Months', start: thisMonthStart, end: today },
    { id: 'lastmonth', label: 'Last month', group: 'Months', start: lastMonthStart, end: lastMonthEnd },
    {
      id: '3m',
      label: 'Last 3 months',
      group: 'Months',
      start: startOfMonth(addMonths(today, -2)),
      end: today,
    },
    {
      id: '6m',
      label: 'Last 6 months',
      group: 'Months',
      start: startOfMonth(addMonths(today, -5)),
      end: today,
    },
    { id: 'ytd', label: 'This year', group: 'Years', start: `${year}-01-01`, end: today },
    {
      id: 'lastyear',
      label: 'Last year',
      group: 'Years',
      start: `${Number(year) - 1}-01-01`,
      end: `${Number(year) - 1}-12-31`,
    },
    { id: '12m', label: 'Last 12 months', group: 'Years', start: addMonths(today, -12), end: today },
    { id: 'all', label: 'All time', group: 'Years', start: earliest || '2024-01-01', end: today },
  ];
}

/** Which preset (if any) matches the current range exactly. */
export function matchPreset(start, end, presets) {
  return presets.find((p) => p.start === start && p.end === end)?.id || null;
}

/** Month shortcuts for the "jump to a month" grid in the picker. */
export function monthOptions(year) {
  return Array.from({ length: 12 }, (_, i) => {
    const month = String(i + 1).padStart(2, '0');
    const start = `${year}-${month}-01`;
    return { month: i + 1, label: start, start, end: endOfMonth(start) };
  });
}

export function describeRange(start, end) {
  const days = diffDays(start, end) + 1;
  if (days === 1) return '1 day';
  return `${days} days`;
}
