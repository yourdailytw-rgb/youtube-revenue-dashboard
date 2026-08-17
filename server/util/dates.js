/**
 * Date helpers. Everything in this app speaks 'YYYY-MM-DD' strings in the
 * channel's reporting timezone (YouTube reports in Pacific Time, but the API
 * hands us date strings directly so we never convert — we only ever compare,
 * add and subtract days on the string form).
 */

const DAY_MS = 24 * 60 * 60 * 1000;

function toISO(date) {
  return date.toISOString().slice(0, 10);
}

function parseISO(iso) {
  return new Date(`${iso}T00:00:00Z`);
}

function today() {
  return toISO(new Date());
}

function addDays(iso, n) {
  return toISO(new Date(parseISO(iso).getTime() + n * DAY_MS));
}

function diffDays(a, b) {
  return Math.round((parseISO(b).getTime() - parseISO(a).getTime()) / DAY_MS);
}

/** 0 = Sunday … 6 = Saturday */
function dayOfWeek(iso) {
  return parseISO(iso).getUTCDay();
}

function minISO(a, b) {
  return a < b ? a : b;
}

function maxISO(a, b) {
  return a > b ? a : b;
}

/** Inclusive list of every date between start and end. */
function eachDay(start, end) {
  const out = [];
  for (let d = start; d <= end; d = addDays(d, 1)) out.push(d);
  return out;
}

function startOfMonth(iso) {
  return `${iso.slice(0, 7)}-01`;
}

function endOfMonth(iso) {
  const [y, m] = iso.split('-').map(Number);
  return toISO(new Date(Date.UTC(y, m, 0)));
}

function monthKey(iso) {
  return iso.slice(0, 7);
}

/**
 * The immediately preceding period of equal length.
 * 2026-03-01..2026-03-31 -> 2026-01-29..2026-02-28
 */
function previousPeriod(start, end) {
  const len = diffDays(start, end) + 1;
  return { start: addDays(start, -len), end: addDays(start, -1) };
}

/** Same range shifted back exactly one year (calendar-aligned). */
function previousYearPeriod(start, end) {
  const shift = (iso) => {
    const [y, m, d] = iso.split('-').map(Number);
    const dt = new Date(Date.UTC(y - 1, m - 1, d));
    // Guard Feb 29 -> Feb 28
    if (dt.getUTCMonth() !== m - 1) dt.setUTCDate(0);
    return toISO(dt);
  };
  return { start: shift(start), end: shift(end) };
}

function isValidISO(value) {
  return typeof value === 'string' && /^\d{4}-\d{2}-\d{2}$/.test(value) && !Number.isNaN(parseISO(value).getTime());
}

module.exports = {
  DAY_MS,
  toISO,
  parseISO,
  today,
  addDays,
  diffDays,
  dayOfWeek,
  minISO,
  maxISO,
  eachDay,
  startOfMonth,
  endOfMonth,
  monthKey,
  previousPeriod,
  previousYearPeriod,
  isValidISO,
};
