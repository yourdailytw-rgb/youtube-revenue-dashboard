/**
 * Formatting. Swedish locale throughout — revenue reads as "1 234,56 kr",
 * matching what the old dashboard showed and what YouTube Studio shows in SEK.
 */

const LOCALE = 'sv-SE';

let currencySuffix = 'kr';
export function setCurrency(code) {
  currencySuffix = code === 'SEK' ? 'kr' : code;
}

const nf = (min, max) => new Intl.NumberFormat(LOCALE, { minimumFractionDigits: min, maximumFractionDigits: max });

const money2 = nf(2, 2);
const money0 = nf(0, 0);
const int0 = nf(0, 0);
const dec1 = nf(1, 1);

export function formatMoney(value, { decimals = 2, suffix = true } = {}) {
  if (value === null || value === undefined || !Number.isFinite(value)) return '—';
  const formatted = decimals === 0 ? money0.format(value) : money2.format(value);
  return suffix ? `${formatted} ${currencySuffix}` : formatted;
}

/** Compact money for chart axes: 12,4k kr */
export function formatMoneyShort(value) {
  if (value === null || value === undefined || !Number.isFinite(value)) return '—';
  const abs = Math.abs(value);
  if (abs >= 1_000_000) return `${dec1.format(value / 1_000_000)}M`;
  if (abs >= 1_000) return `${dec1.format(value / 1_000)}k`;
  return money0.format(value);
}

export function formatNumber(value) {
  if (value === null || value === undefined || !Number.isFinite(value)) return '—';
  return int0.format(Math.round(value));
}

export function formatNumberShort(value) {
  if (value === null || value === undefined || !Number.isFinite(value)) return '—';
  const abs = Math.abs(value);
  if (abs >= 1_000_000) return `${dec1.format(value / 1_000_000)}M`;
  if (abs >= 1_000) return `${dec1.format(value / 1_000)}k`;
  return int0.format(value);
}

export function formatPct(value, { decimals = 1, sign = false } = {}) {
  if (value === null || value === undefined || !Number.isFinite(value)) return '—';
  const pct = value * 100;
  const formatted = new Intl.NumberFormat(LOCALE, {
    minimumFractionDigits: decimals,
    maximumFractionDigits: decimals,
  }).format(pct);
  return `${sign && pct > 0 ? '+' : ''}${formatted}%`;
}

export function formatDuration(seconds) {
  if (!Number.isFinite(seconds) || seconds <= 0) return '—';
  const m = Math.floor(seconds / 60);
  const s = Math.round(seconds % 60);
  if (m >= 60) {
    const h = Math.floor(m / 60);
    return `${h}h ${m % 60}m`;
  }
  return `${m}:${String(s).padStart(2, '0')}`;
}

export function formatHours(hours) {
  if (!Number.isFinite(hours)) return '—';
  if (hours >= 1000) return `${formatNumberShort(hours)} h`;
  return `${dec1.format(hours)} h`;
}

const MONTHS = [
  'January', 'February', 'March', 'April', 'May', 'June',
  'July', 'August', 'September', 'October', 'November', 'December',
];

export function formatDate(iso, style = 'medium') {
  if (!iso) return '—';
  const [y, m, d] = iso.split('-').map(Number);
  if (style === 'short') return `${d} ${MONTHS[m - 1].slice(0, 3)}`;
  if (style === 'axis') return `${d}/${m}`;
  if (style === 'long') return `${d} ${MONTHS[m - 1]} ${y}`;
  return `${d} ${MONTHS[m - 1].slice(0, 3)} ${y}`;
}

export function formatMonth(monthKey, { short = false } = {}) {
  if (!monthKey) return '—';
  const [y, m] = monthKey.split('-').map(Number);
  const name = MONTHS[m - 1];
  return short ? `${name.slice(0, 3)} ${String(y).slice(2)}` : `${name} ${y}`;
}

export function weekdayName(iso, short = true) {
  const names = ['Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday'];
  const day = new Date(`${iso}T00:00:00Z`).getUTCDay();
  return short ? names[day].slice(0, 3) : names[day];
}

export function relativeTime(isoTimestamp) {
  if (!isoTimestamp) return 'never';
  const diff = Date.now() - new Date(isoTimestamp).getTime();
  const minutes = Math.round(diff / 60000);
  if (minutes < 1) return 'just now';
  if (minutes < 60) return `${minutes} min ago`;
  const hours = Math.round(minutes / 60);
  if (hours < 24) return `${hours} h ago`;
  const days = Math.round(hours / 24);
  return `${days} d ago`;
}
