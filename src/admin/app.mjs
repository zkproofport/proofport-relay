// Relay admin page. Every value from the API reaches the DOM through
// textContent or an SVG attribute set with setAttribute -- never innerHTML --
// so a circuit name or error code can never become markup.
import {
  DEFAULT_PRESET_DAYS,
  chartGeometry,
  checkRange,
  circuitRows,
  dailyRows,
  errorRows,
  isEmpty,
  rangeForPreset,
  retryAfterMinutes,
  successRate,
  tokenFormatError,
  totalsRow,
} from './core.mjs';

// sessionStorage only: gone when the tab closes, never sent anywhere by the
// browser on its own (unlike a cookie), never in the URL.
const TOKEN_KEY = 'relay-admin-stats-token';
const SVG_NS = 'http://www.w3.org/2000/svg';

const $ = (id) => {
  const el = document.getElementById(id);
  if (!el) throw new Error(`Admin page element #${id} is missing`);
  return el;
};

function readToken() {
  try { return sessionStorage.getItem(TOKEN_KEY); } catch { return null; }
}
function storeToken(token) {
  try { sessionStorage.setItem(TOKEN_KEY, token); } catch { /* the page still works for this load */ }
}
function clearToken() {
  try { sessionStorage.removeItem(TOKEN_KEY); } catch { /* nothing stored */ }
}

// The token for this page load. Kept in memory too, so a browser that refuses
// sessionStorage still works until the tab is reloaded.
let token = null;
let range = rangeForPreset(DEFAULT_PRESET_DAYS, Date.now());
let preset = DEFAULT_PRESET_DAYS;
let report = null;
let circuit = 'all';

function show(el, visible) { el.hidden = !visible; }
function setText(el, text) { el.textContent = text; }
function fmt(n) { return Number(n).toLocaleString('ko-KR'); }

function showLogin(message) {
  show($('dashboard-view'), false);
  show($('login-view'), true);
  setText($('login-error'), message || '');
  show($('login-error'), Boolean(message));
  $('token-input').value = '';
  $('token-input').focus();
}

function showDashboard() {
  show($('login-view'), false);
  show($('dashboard-view'), true);
}

function logout(message) {
  token = null;
  report = null;
  clearToken();
  showLogin(message);
}

/** Calls the stats API. Resolves to { ok, report } or { ok: false, status, message }. */
async function fetchStats(withToken, from, to) {
  let res;
  try {
    res = await fetch(`/api/v1/stats?from=${encodeURIComponent(from)}&to=${encodeURIComponent(to)}`, {
      headers: { Authorization: `Bearer ${withToken}` },
      cache: 'no-store',
      credentials: 'omit',
      referrerPolicy: 'no-referrer',
    });
  } catch {
    return { ok: false, status: 0, message: '서버에 연결하지 못했습니다.' };
  }
  if (res.ok) return { ok: true, report: await res.json() };
  if (res.status === 401) return { ok: false, status: 401, message: '토큰이 올바르지 않습니다.' };
  if (res.status === 429) {
    const minutes = retryAfterMinutes(res.headers.get('Retry-After'));
    return { ok: false, status: 429, message: minutes ? `시도가 너무 많습니다. 약 ${minutes}분 뒤에 다시 시도하세요.` : '시도가 너무 많습니다. 잠시 뒤에 다시 시도하세요.' };
  }
  let detail = '';
  try { detail = (await res.json()).error || ''; } catch { /* not JSON */ }
  return { ok: false, status: res.status, message: `조회 실패 (${res.status})${detail ? `: ${detail}` : ''}` };
}

async function onLogin(event) {
  event.preventDefault();
  const candidate = $('token-input').value.trim();
  const formatError = tokenFormatError(candidate);
  if (formatError) {
    setText($('login-error'), formatError);
    show($('login-error'), true);
    return;
  }
  const button = $('login-button');
  button.disabled = true;
  try {
    const result = await fetchStats(candidate, range.from, range.to);
    if (!result.ok) {
      setText($('login-error'), result.message);
      show($('login-error'), true);
      return;
    }
    token = candidate;
    storeToken(candidate);
    $('token-input').value = '';
    show($('login-error'), false);
    showDashboard();
    render(result.report);
  } finally {
    button.disabled = false;
  }
}

async function load() {
  const check = checkRange(range.from, range.to);
  if (!check.ok) {
    setText($('dashboard-error'), check.error);
    show($('dashboard-error'), true);
    return;
  }
  show($('dashboard-error'), false);
  show($('loading'), true);
  try {
    const result = await fetchStats(token, range.from, range.to);
    if (!result.ok) {
      if (result.status === 401) {
        logout('토큰이 더 이상 유효하지 않습니다. 다시 로그인하세요.');
        return;
      }
      setText($('dashboard-error'), result.message);
      show($('dashboard-error'), true);
      return;
    }
    render(result.report);
  } finally {
    show($('loading'), false);
  }
}

function syncControls() {
  $('from-input').value = range.from;
  $('to-input').value = range.to;
  for (const b of document.querySelectorAll('.preset')) {
    b.setAttribute('aria-pressed', String(Number(b.dataset.days) === preset));
  }
}

function cell(row, text) {
  const td = document.createElement('td');
  td.textContent = text;
  row.appendChild(td);
}

function fillTable(id, rows, columns) {
  const tbody = $(id).querySelector('tbody');
  tbody.replaceChildren();
  for (const r of rows) {
    const tr = document.createElement('tr');
    for (const c of columns) cell(tr, c(r));
    tbody.appendChild(tr);
  }
}

function renderCircuitOptions() {
  const select = $('circuit-select');
  const names = Object.keys(report.totals.circuits).sort();
  if (circuit !== 'all' && !names.includes(circuit)) circuit = 'all';
  select.replaceChildren();
  const all = document.createElement('option');
  all.value = 'all';
  all.textContent = '전체';
  select.appendChild(all);
  for (const name of names) {
    const o = document.createElement('option');
    o.value = name;
    o.textContent = name;
    select.appendChild(o);
  }
  select.value = circuit;
}

function svg(tag, attrs, text) {
  const el = document.createElementNS(SVG_NS, tag);
  for (const [k, v] of Object.entries(attrs)) el.setAttribute(k, String(v));
  if (text !== undefined) el.textContent = text;
  return el;
}

const SERIES_LABEL = { requested: '요청', completed: '완료' };

function renderChart(days) {
  const width = 800;
  const height = 240;
  const g = chartGeometry(days, ['requested', 'completed'], { width, height });
  const root = svg('svg', { viewBox: `0 0 ${width} ${height}`, role: 'img', 'aria-label': '일별 요청과 완료 막대 차트 (UTC)' });
  for (const t of g.ticks) {
    root.appendChild(svg('line', { class: 'grid', x1: g.plot.left, x2: g.plot.left + g.plot.width, y1: t.y, y2: t.y }));
    root.appendChild(svg('text', { class: 'axis-label', x: g.plot.left - 6, y: t.y + 4, 'text-anchor': 'end' }, fmt(t.value)));
  }
  for (const b of g.bars) {
    if (b.height <= 0) continue;
    const rect = svg('rect', { class: `bar-${b.series}`, x: b.x, y: b.y, width: b.width, height: b.height, rx: Math.min(2, b.width / 2) });
    rect.appendChild(svg('title', {}, `${b.date} ${SERIES_LABEL[b.series]} ${fmt(b.value)}`));
    root.appendChild(rect);
  }
  if (days.length > 0) {
    const labelIdx = [...new Set([0, Math.floor((days.length - 1) / 2), days.length - 1])];
    const slot = g.plot.width / days.length;
    for (const i of labelIdx) {
      // First and last labels hug the plot edges so they never overflow the viewBox.
      let anchor = 'middle';
      let x = g.plot.left + slot * (i + 0.5);
      if (i === 0) {
        anchor = 'start';
        x = g.plot.left;
      } else if (i === days.length - 1) {
        anchor = 'end';
        x = g.plot.left + g.plot.width;
      }
      root.appendChild(svg('text', { class: 'axis-label', x, y: height - 6, 'text-anchor': anchor }, days[i].date));
    }
  }
  $('chart').replaceChildren(root);
}

function render(next) {
  report = next;
  syncControls();
  setText($('range-label'), `${report.from} ~ ${report.to} (UTC, 양 끝 포함) · 날짜는 모두 UTC 기준`);
  setText($('fetched-at'), `조회 시각 ${new Date().toISOString().replace('T', ' ').slice(0, 19)} UTC`);
  renderCircuitOptions();

  const empty = isEmpty(report);
  show($('empty-state'), empty);
  show($('content'), !empty);
  if (empty) return;

  const days = dailyRows(report, circuit);
  const rows = circuitRows(report);
  const selected = circuit === 'all' ? totalsRow(report) : rows.find((r) => r.circuit === circuit);
  setText($('tile-requested'), fmt(selected.requested));
  setText($('tile-completed'), fmt(selected.completed));
  setText($('tile-error'), fmt(selected.error));
  setText($('tile-cancelled'), fmt(selected.cancelled));
  setText($('tile-expired'), fmt(selected.expired));
  setText($('tile-rate'), selected.rate);

  renderChart(days);
  fillTable('circuit-table', rows, [(r) => r.circuit, (r) => fmt(r.requested), (r) => fmt(r.completed), (r) => fmt(r.error), (r) => fmt(r.cancelled), (r) => fmt(r.expired), (r) => r.rate]);

  const errors = errorRows(report, circuit);
  show($('no-errors'), errors.length === 0);
  show($('error-table'), errors.length > 0);
  fillTable('error-table', errors, [(r) => r.circuit, (r) => r.code, (r) => r.label, (r) => fmt(r.count)]);

  fillTable('day-table', [...days].reverse(), [(r) => r.date, (r) => fmt(r.requested), (r) => fmt(r.completed), (r) => fmt(r.error), (r) => fmt(r.cancelled), (r) => fmt(r.expired), (r) => successRate(r.completed, r.requested)]);

  const unknown = Object.keys(report.unrecognized || {});
  show($('unrecognized'), unknown.length > 0);
  setText($('unrecognized'), unknown.length > 0 ? `해석하지 못한 항목 ${unknown.length}개: ${unknown.join(', ')}` : '');
}

function init() {
  $('login-form').addEventListener('submit', onLogin);
  $('logout-button').addEventListener('click', () => logout(''));
  for (const b of document.querySelectorAll('.preset')) {
    b.addEventListener('click', () => {
      preset = Number(b.dataset.days);
      range = rangeForPreset(preset, Date.now());
      syncControls();
      load();
    });
  }
  $('range-form').addEventListener('submit', (event) => {
    event.preventDefault();
    preset = null;
    range = { from: $('from-input').value, to: $('to-input').value };
    syncControls();
    load();
  });
  $('circuit-select').addEventListener('change', () => {
    circuit = $('circuit-select').value;
    if (report) render(report);
  });

  syncControls();
  const saved = readToken();
  if (saved) {
    token = saved;
    showDashboard();
    load();
  } else {
    showLogin('');
  }
}

init();
