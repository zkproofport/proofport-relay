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

// ---------------------------------------------------------------------------
// Labels: the page that asked (origin), the dApp's scope, the country the
// app answered from. Totals over the range only; the relay does not keep them
// per day per circuit per error code.
// ---------------------------------------------------------------------------

export const DIMENSIONS = ['origin', 'scope', 'country'];

/** How each marker reads on the page; a stored value is shown as itself. */
export const MARKER_TEXT = {
  none: '(보내지 않음)',
  invalid: '(형식이 맞지 않음)',
  'too-long': '(너무 김)',
  unknown: '(위치를 알 수 없음)',
  other: '(기타 — 그날 종류가 500개를 넘음)',
};

function flatOutcomes(counts) {
  return {
    requested: counts.requested,
    completed: counts.completed,
    error: counts.error,
    cancelled: counts.cancelled,
    expired: counts.expired,
  };
}

/** The rows of one label kind, or an empty object from a relay that has none. */
function labelRows(report, kind) {
  if (!DIMENSIONS.includes(kind)) throw new Error(`Unknown label kind '${kind}'. Known: ${DIMENSIONS.join(', ')}.`);
  const all = report.dimensions || {};
  return Object.prototype.hasOwnProperty.call(all, kind) ? all[kind] : {};
}

/** What a label shows on the page. Display only; a code with no country name shows the code. */
export function labelText(row, kind) {
  if (row.marker !== null && row.marker !== undefined) {
    return Object.prototype.hasOwnProperty.call(MARKER_TEXT, row.marker) ? MARKER_TEXT[row.marker] : `(${row.marker})`;
  }
  if (kind === 'country') return countryName(row.value);
  return row.value;
}

/** "대한민국 (KR)"; the bare code when the runtime has no name for it. */
export function countryName(code) {
  try {
    const name = new Intl.DisplayNames(['ko'], { type: 'region' }).of(code);
    return name && name !== code ? `${name} (${code})` : code;
  } catch {
    return code;
  }
}

/**
 * One row per label of `kind`, busiest first: requests, then answers (country
 * has no requests: it is recorded only when the app answers), then the label.
 * With a circuit, only that circuit's counts.
 */
export function dimensionRows(report, kind, circuit = 'all') {
  const rows = [];
  for (const [key, row] of Object.entries(labelRows(report, kind))) {
    const counts = circuit === 'all' ? row.all : row.circuits[circuit];
    if (!counts) continue;
    const f = flatOutcomes(counts);
    rows.push({ key, label: labelText(row, kind), ...f, rate: successRate(f.completed, f.requested) });
  }
  const answered = (r) => r.completed + r.error + r.cancelled;
  return rows.sort((a, b) => b.requested - a.requested || answered(b) - answered(a) || a.label.localeCompare(b.label));
}

/** Per-circuit rows for one label, in the shape circuitRows() returns. */
export function labelCircuitRows(report, kind, key) {
  const row = labelRows(report, kind)[key];
  if (!row) return [];
  return Object.entries(row.circuits)
    .map(([circuit, counts]) => {
      const f = flatOutcomes(counts);
      return { circuit, ...f, rate: successRate(f.completed, f.requested) };
    })
    .sort((a, b) => b.requested - a.requested || a.circuit.localeCompare(b.circuit));
}

/** Totals for one label (one circuit or all); zeros when the label has none of that circuit. */
export function labelTotals(report, kind, key, circuit = 'all') {
  const row = labelRows(report, kind)[key];
  const counts = row && (circuit === 'all' ? row.all : row.circuits[circuit]);
  const f = counts ? flatOutcomes(counts) : { requested: 0, completed: 0, error: 0, cancelled: 0, expired: 0 };
  return { ...f, rate: successRate(f.completed, f.requested) };
}

// ---------------------------------------------------------------------------
// Country map
// ---------------------------------------------------------------------------

/** Number of shades on the map, lightest (1) to darkest; 0 = no answers. */
export const MAP_SHADES = 5;

/** Answers the app sent from a country: completed + error + cancelled. */
export function answered(counts) {
  return counts.completed + counts.error + counts.cancelled;
}

/**
 * Shade 0..MAP_SHADES for a count, on a log scale so one busy country does not
 * wash every other one out to the lightest shade.
 */
export function shadeFor(count, max) {
  if (!(count > 0) || !(max > 0)) return 0;
  if (max === 1) return MAP_SHADES;
  const step = Math.ceil((Math.log(count) / Math.log(max)) * (MAP_SHADES - 1)) + 1;
  return Math.min(MAP_SHADES, Math.max(1, step));
}

/**
 * Per-country answers for the map: { [code]: { count, shade } } for countries
 * with at least one answer. Markers (unknown, invalid, other) have no shape
 * and are left to the table.
 */
export function mapShades(report, circuit = 'all') {
  const counts = {};
  for (const [, row] of Object.entries(labelRows(report, 'country'))) {
    if (row.marker !== null || typeof row.value !== 'string') continue;
    const c = circuit === 'all' ? row.all : row.circuits[circuit];
    if (!c || answered(c) === 0) continue;
    counts[row.value] = answered(c);
  }
  const max = Math.max(0, ...Object.values(counts));
  const out = {};
  for (const [code, count] of Object.entries(counts)) out[code] = { count, shade: shadeFor(count, max) };
  return out;
}

/** What one country shows when clicked: per-circuit answers, busiest first. */
export function countryDetail(report, code) {
  const row = labelRows(report, 'country')[`v:${encodeURIComponent(code)}`];
  const empty = { code, name: countryName(code), total: { completed: 0, error: 0, cancelled: 0, answered: 0 }, circuits: [] };
  if (!row) return empty;
  const circuits = Object.entries(row.circuits)
    .map(([circuit, c]) => ({ circuit, completed: c.completed, error: c.error, cancelled: c.cancelled, answered: answered(c) }))
    .filter((r) => r.answered > 0)
    .sort((a, b) => b.answered - a.answered || a.circuit.localeCompare(b.circuit));
  const a = row.all;
  return { code, name: countryName(code), total: { completed: a.completed, error: a.error, cancelled: a.cancelled, answered: answered(a) }, circuits };
}
