// Pure logic for the relay admin page: no DOM, no network. Imported by
// app.mjs in the browser and by src/__tests__/adminCore.test.ts in vitest.

/** Must match STATS_MAX_RANGE_DAYS in src/stats.ts; the server refuses longer ranges. */
export const MAX_RANGE_DAYS = 400;
export const PRESET_DAYS = [7, 30, 90];
export const DEFAULT_PRESET_DAYS = 7;

const DAY_MS = 86_400_000;
const DATE_RE = /^(\d{4})-(\d{2})-(\d{2})$/;

/** `YYYY-MM-DD` of an instant, in UTC (the stats are bucketed by UTC day). */
export function utcDay(ms) {
  return new Date(ms).toISOString().slice(0, 10);
}

/** The last `days` UTC days ending today, inclusive. */
export function rangeForPreset(days, nowMs) {
  if (!Number.isInteger(days) || days < 1 || days > MAX_RANGE_DAYS) {
    throw new Error(`Preset must be 1..${MAX_RANGE_DAYS} days, got ${days}`);
  }
  const to = utcDay(nowMs);
  const from = utcDay(Date.parse(`${to}T00:00:00Z`) - (days - 1) * DAY_MS);
  return { from, to };
}

function parseDay(value) {
  if (typeof value !== 'string') return null;
  const m = DATE_RE.exec(value);
  if (!m) return null;
  const ms = Date.UTC(Number(m[1]), Number(m[2]) - 1, Number(m[3]));
  return utcDay(ms) === value ? ms : null;
}

/** Same rules as the server's checkRange, so the page can say why before asking. */
export function checkRange(from, to) {
  const f = parseDay(from);
  if (f === null) return { ok: false, error: '시작일이 올바른 날짜가 아닙니다 (YYYY-MM-DD).' };
  const t = parseDay(to);
  if (t === null) return { ok: false, error: '종료일이 올바른 날짜가 아닙니다 (YYYY-MM-DD).' };
  if (f > t) return { ok: false, error: '시작일이 종료일보다 늦습니다.' };
  const span = Math.round((t - f) / DAY_MS) + 1;
  if (span > MAX_RANGE_DAYS) return { ok: false, error: `기간은 최대 ${MAX_RANGE_DAYS}일입니다 (선택: ${span}일).` };
  return { ok: true, days: span };
}

/** completed / requested as a percentage; an em dash when nothing was requested. */
export function successRate(completed, requested) {
  if (!(requested > 0)) return '—';
  return `${((completed / requested) * 100).toFixed(1)}%`;
}

/**
 * Short labels for the app's error codes, copied from the titles in
 * proofport-app/src/constants/errorCodes.ts (the page cannot import the app).
 * A code not listed here is shown as the bare code -- a display value with no
 * behaviour behind it, so an unknown code is not an error.
 */
export const ERROR_LABELS = {
  E1001: 'Invalid Proof Request (parse)',
  E1002: 'Invalid Proof Request (validation)',
  E1003: 'Expired Request',
  E1004: 'Missing Required Input',
  E1005: 'Unsupported Circuit',
  E1006: 'Unregistered Request',
  E1007: 'Request Already Answered',
  E2001: 'Proof Generation Failed',
  E2002: 'Circuit Download Failed',
  E2003: 'Verification Failed',
  E2004: 'Missing Inputs',
  E2005: 'Attestation Not Found',
  E2006: 'Unsupported Proof Type',
  E2007: 'No Dojang Playground Issuance',
  E2008: 'Sign-In Failed',
  E3001: 'Network Error',
  E3002: 'Server Error',
  E3003: 'Callback Failed',
  E3004: 'Request Timeout',
  E3005: 'Circuit Files Missing',
  E4001: 'Wallet Not Connected',
  E4002: 'Signing Failed',
  E4003: 'Wallet Connection Failed',
  E4004: 'Disconnect Failed',
  E5001: 'Storage Error',
  E5002: 'Data Load Failed',
  E9999: 'Something Went Wrong',
};

/** `none` is how the relay stores an error that carried no code. */
export function errorLabel(code) {
  if (code === 'none') return '코드 없음';
  return Object.prototype.hasOwnProperty.call(ERROR_LABELS, code) ? ERROR_LABELS[code] : '';
}

function zero() {
  return { requested: 0, completed: 0, error: 0, cancelled: 0, expired: 0 };
}

function flatten(counts) {
  return {
    requested: counts.requested,
    completed: counts.completed,
    error: counts.error.total,
    cancelled: counts.cancelled,
    expired: counts.expired,
  };
}

/** True when the range holds nothing at all, unrecognized fields included. */
export function isEmpty(report) {
  const a = report.totals.all;
  const total = a.requested + a.completed + a.error.total + a.cancelled + a.expired;
  return total === 0 && Object.keys(report.unrecognized || {}).length === 0;
}

/** One row per circuit, busiest first, then by name. */
export function circuitRows(report) {
  return Object.entries(report.totals.circuits)
    .map(([circuit, counts]) => ({ circuit, ...flatten(counts), rate: successRate(counts.completed, counts.requested) }))
    .sort((a, b) => b.requested - a.requested || a.circuit.localeCompare(b.circuit));
}

/** Overall totals across every circuit. */
export function totalsRow(report) {
  const all = flatten(report.totals.all);
  return { ...all, rate: successRate(all.completed, all.requested) };
}

/** Error counts by circuit and code, most frequent first. */
export function errorRows(report, circuit = 'all') {
  const rows = [];
  for (const [name, counts] of Object.entries(report.totals.circuits)) {
    if (circuit !== 'all' && name !== circuit) continue;
    for (const [code, count] of Object.entries(counts.error.byCode)) {
      rows.push({ circuit: name, code, label: errorLabel(code), count });
    }
  }
  return rows.sort((a, b) => b.count - a.count || a.circuit.localeCompare(b.circuit) || a.code.localeCompare(b.code));
}

/** Per-day sums for one circuit, or for all of them; every day of the range is present. */
export function dailyRows(report, circuit = 'all') {
  return report.days.map((day) => {
    const row = { date: day.date, ...zero() };
    for (const [name, counts] of Object.entries(day.circuits)) {
      if (circuit !== 'all' && name !== circuit) continue;
      const f = flatten(counts);
      for (const k of Object.keys(f)) row[k] += f[k];
    }
    return row;
  });
}

/** Widest a bar is drawn, in viewBox units (the chart is 800 wide). */
export const MAX_BAR_WIDTH = 24;

/** A round axis maximum at or above `max`: 1, 2, 5 x 10^n. */
export function niceMax(max) {
  if (!(max > 0)) return 1;
  const exp = Math.pow(10, Math.floor(Math.log10(max)));
  for (const m of [1, 2, 5, 10]) {
    if (m * exp >= max) return m * exp;
  }
  return 10 * exp;
}

/**
 * Bar geometry for a grouped chart of `series` per day, in a viewBox of
 * `width` x `height`. Pure numbers; app.mjs turns them into SVG.
 */
export function chartGeometry(rows, series, { width = 800, height = 240, left = 40, right = 8, top = 8, bottom = 24 } = {}) {
  const plotW = width - left - right;
  const plotH = height - top - bottom;
  const peak = Math.max(0, ...rows.flatMap((r) => series.map((s) => r[s])));
  const yMax = niceMax(peak);
  const slot = rows.length > 0 ? plotW / rows.length : plotW;
  const gap = Math.min(2, slot * 0.2);
  // Thin marks: a short range would otherwise draw bars half the chart wide.
  const barW = Math.min(MAX_BAR_WIDTH, Math.max(0.5, (slot - gap * (series.length + 1)) / series.length));
  // Each day's group is centred in its slot.
  const offset = (slot - (series.length * barW + (series.length - 1) * gap)) / 2;
  const bars = [];
  rows.forEach((r, i) => {
    series.forEach((s, j) => {
      const h = (r[s] / yMax) * plotH;
      bars.push({
        series: s,
        date: r.date,
        value: r[s],
        x: left + i * slot + offset + j * (barW + gap),
        y: top + plotH - h,
        width: barW,
        height: h,
      });
    });
  });
  const ticks = [0, yMax / 2, yMax].map((v) => ({ value: v, y: top + plotH - (v / yMax) * plotH }));
  return { bars, ticks, yMax, plot: { left, top, width: plotW, height: plotH, bottom: top + plotH } };
}

/**
 * Why a typed token cannot be sent, or '' when it can. An HTTP header carries
 * visible ASCII only; `fetch` throws on anything else, which would otherwise
 * read as "cannot reach the server".
 */
export function tokenFormatError(token) {
  if (typeof token !== 'string' || token.length === 0) return '토큰을 입력하세요.';
  if (!/^[\x21-\x7e]+$/.test(token)) return '토큰에는 영문·숫자·기호만 들어갑니다. 공백이나 한글이 섞이지 않았는지 확인하세요.';
  return '';
}

/** Seconds from a Retry-After header, as minutes for a person; null when absent or unreadable. */
export function retryAfterMinutes(header) {
  const s = Number(header);
  if (!Number.isFinite(s) || s <= 0) return null;
  return Math.ceil(s / 60);
}
