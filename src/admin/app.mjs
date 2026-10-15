// Relay admin page. Every value from the API reaches the DOM through
// textContent or an SVG attribute set with setAttribute -- never innerHTML --
// so a circuit name or error code can never become markup.
import {
  DEFAULT_PRESET_DAYS,
  chartGeometry,
  checkRange,
  circuitRows,
  countryDetail,
  mapShades,
  dailyRows,
  errorRows,
  dimensionRows,
  isEmpty,
  labelCircuitRows,
  labelTotals,
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
// One label filter at a time: the relay keeps sites and scopes as separate
// totals, so "this site AND this scope" cannot be answered.
let labelFilter = null; // { kind: 'origin' | 'scope', key }

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

function renderLabelOptions(kind) {
  const select = $(`${kind}-select`);
  const rows = dimensionRows(report, kind);
  if (labelFilter && labelFilter.kind === kind && !rows.some((r) => r.key === labelFilter.key)) labelFilter = null;
  select.replaceChildren();
  const all = document.createElement('option');
  all.value = 'all';
  all.textContent = '전체';
  select.appendChild(all);
  for (const r of rows) {
    const o = document.createElement('option');
    o.value = r.key;
    o.textContent = r.label;
    select.appendChild(o);
  }
  select.value = labelFilter && labelFilter.kind === kind ? labelFilter.key : 'all';
}

// The map shapes, fetched once per page load from this origin.
let world = null;
let worldLoad = null;
let selectedCountry = null;

function loadWorld() {
  worldLoad ??= fetch('/admin/world.json', { credentials: 'omit', referrerPolicy: 'no-referrer' })
    .then((res) => {
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      return res.json();
    })
    .then((data) => {
      world = data;
      if (report) render(report);
    })
    .catch(() => {
      worldLoad = null;
      $('world-map').replaceChildren();
      const p = document.createElement('p');
      p.className = 'error small';
      p.textContent = '지도를 불러오지 못했습니다. 아래 표는 그대로 볼 수 있습니다.';
      $('world-map').appendChild(p);
    });
  return worldLoad;
}

function selectCountry(code) {
  selectedCountry = code;
  if (report) render(report);
}

function renderCountryDetail() {
  const box = $('country-detail');
  box.replaceChildren();
  if (!selectedCountry) {
    const p = document.createElement('p');
    p.className = 'muted small';
    p.textContent = '지도의 나라나 아래 표의 행을 누르세요.';
    box.appendChild(p);
    return;
  }
  const d = countryDetail(report, selectedCountry);
  const h = document.createElement('h3');
  h.textContent = d.name;
  box.appendChild(h);
  const sum = document.createElement('p');
  sum.textContent = `응답 ${fmt(d.total.answered)} · 완료 ${fmt(d.total.completed)} · 오류 ${fmt(d.total.error)} · 취소 ${fmt(d.total.cancelled)}`;
  box.appendChild(sum);
  if (d.circuits.length === 0) {
    const p = document.createElement('p');
    p.className = 'muted small';
    p.textContent = '이 기간에 이 나라에서 온 응답이 없습니다.';
    box.appendChild(p);
    return;
  }
  const table = document.createElement('table');
  const head = document.createElement('tr');
  for (const t of ['회로', '완료', '오류', '취소']) {
    const th = document.createElement('th');
    th.scope = 'col';
    th.textContent = t;
    head.appendChild(th);
  }
  const thead = document.createElement('thead');
  thead.appendChild(head);
  table.appendChild(thead);
  const tbody = document.createElement('tbody');
  for (const r of d.circuits) {
    const tr = document.createElement('tr');
    for (const v of [r.circuit, fmt(r.completed), fmt(r.error), fmt(r.cancelled)]) cell(tr, v);
    tbody.appendChild(tr);
  }
  table.appendChild(tbody);
  box.appendChild(table);
}

function renderMap() {
  if (!world) {
    loadWorld();
    return;
  }
  const shades = mapShades(report, circuit);
  const root = svg('svg', { viewBox: `0 0 ${world.width} ${world.height}`, role: 'group', 'aria-label': '증명을 보낸 국가 지도' });
  for (const c of world.countries) {
    const hit = c.code ? shades[c.code] : undefined;
    const shade = hit ? hit.shade : 0;
    const path = svg('path', { d: c.d, class: `country shade-${shade}${c.code && c.code === selectedCountry ? ' selected' : ''}` });
    const label = c.code ? `${countryDetail(report, c.code).name} · 응답 ${fmt(hit ? hit.count : 0)}` : c.name;
    path.appendChild(svg('title', {}, label));
    if (c.code) {
      path.setAttribute('tabindex', hit ? '0' : '-1');
      path.setAttribute('role', 'button');
      path.setAttribute('aria-label', label);
      path.addEventListener('click', () => selectCountry(c.code));
      path.addEventListener('keydown', (e) => {
        if (e.key === 'Enter' || e.key === ' ') {
          e.preventDefault();
          selectCountry(c.code);
        }
      });
    }
    root.appendChild(path);
  }
  $('world-map').replaceChildren(root);
}

function fillLabelTable(kind, emptyId, columns) {
  const rows = dimensionRows(report, kind, circuit);
  show($(emptyId), rows.length === 0);
  show($(`${kind}-table`), rows.length > 0);
  fillTable(`${kind}-table`, rows, columns);
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
  renderLabelOptions('origin');
  renderLabelOptions('scope');

  const empty = isEmpty(report);
  show($('empty-state'), empty);
  show($('content'), !empty);
  if (empty) return;

  const days = dailyRows(report, circuit);
  const rows = labelFilter ? labelCircuitRows(report, labelFilter.kind, labelFilter.key) : circuitRows(report);
  const selected = labelFilter
    ? labelTotals(report, labelFilter.kind, labelFilter.key, circuit)
    : circuit === 'all' ? totalsRow(report) : rows.find((r) => r.circuit === circuit);
  show($('label-filter-note'), Boolean(labelFilter));
  for (const id of ['chart-panel', 'error-panel', 'day-panel']) show($(id), !labelFilter);
  setText($('tile-requested'), fmt(selected.requested));
  setText($('tile-completed'), fmt(selected.completed));
  setText($('tile-error'), fmt(selected.error));
  setText($('tile-cancelled'), fmt(selected.cancelled));
  setText($('tile-expired'), fmt(selected.expired));
  setText($('tile-rate'), selected.rate);

  renderChart(days);
  const countColumns = [(r) => r.label, (r) => fmt(r.requested), (r) => fmt(r.completed), (r) => fmt(r.error), (r) => fmt(r.cancelled), (r) => fmt(r.expired), (r) => r.rate];
  fillLabelTable('origin', 'no-origins', countColumns);
  fillLabelTable('scope', 'no-scopes', countColumns);
  fillLabelTable('country', 'no-countries', [(r) => r.label, (r) => fmt(r.completed), (r) => fmt(r.error), (r) => fmt(r.cancelled)]);
  // A country row opens its detail, like a click on the map.
  const countryRows = dimensionRows(report, 'country', circuit);
  $('country-table').querySelectorAll('tbody tr').forEach((tr, i) => {
    const key = countryRows[i].key;
    if (!key.startsWith('v:')) return;
    tr.classList.add('clickable');
    tr.tabIndex = 0;
    const open = () => selectCountry(decodeURIComponent(key.slice(2)));
    tr.addEventListener('click', open);
    tr.addEventListener('keydown', (e) => { if (e.key === 'Enter') open(); });
  });
  renderMap();
  renderCountryDetail();

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
  for (const kind of ['origin', 'scope']) {
    $(`${kind}-select`).addEventListener('change', () => {
      const key = $(`${kind}-select`).value;
      labelFilter = key === 'all' ? null : { kind, key };
      if (report) render(report);
    });
  }

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
