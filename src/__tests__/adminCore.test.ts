/**
 * Unit tests for the admin page's pure logic (src/admin/core.mjs): the date
 * presets and range rules, success rate, error-code labels, the tables' rows
 * and the chart geometry. The DOM half (app.mjs) is exercised in a real
 * browser by admin-browser-e2e.test.ts.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import type { StatsReport, CircuitCounts } from '../stats';
import { STATS_MAX_RANGE_DAYS } from '../stats';

// core.mjs is an ES module and this file compiles as CommonJS, so it is
// loaded with a dynamic import (a static one would become `require`).
let core: typeof import('../admin/core.mjs', { with: { 'resolution-mode': 'import' } });
beforeAll(async () => {
  core = await import('../admin/core.mjs');
});

const NOW = Date.parse('2026-10-14T23:59:59.999Z');

function counts(c: Partial<{ requested: number; completed: number; cancelled: number; expired: number; byCode: Record<string, number> }>): CircuitCounts {
  const byCode = c.byCode ?? {};
  const total = Object.values(byCode).reduce((a, b) => a + b, 0);
  return {
    requested: c.requested ?? 0,
    completed: c.completed ?? 0,
    cancelled: c.cancelled ?? 0,
    expired: c.expired ?? 0,
    abandoned: (c.cancelled ?? 0) + (c.expired ?? 0),
    error: { total, byCode },
  };
}

function report(days: Array<{ date: string; circuits: Record<string, CircuitCounts> }>, unrecognized: Record<string, number> = {}): StatsReport {
  const totals: Record<string, CircuitCounts> = {};
  const all = counts({});
  for (const d of days) {
    for (const [name, c] of Object.entries(d.circuits)) {
      const t = (totals[name] ??= counts({}));
      for (const target of [t, all]) {
        target.requested += c.requested;
        target.completed += c.completed;
        target.cancelled += c.cancelled;
        target.expired += c.expired;
        target.abandoned += c.abandoned;
        target.error.total += c.error.total;
        for (const [code, n] of Object.entries(c.error.byCode)) target.error.byCode[code] = (target.error.byCode[code] ?? 0) + n;
      }
    }
  }
  return { from: days[0]?.date ?? '', to: days[days.length - 1]?.date ?? '', days, totals: { circuits: totals, all }, dimensions: { origin: {}, scope: {}, country: {} }, unrecognized };
}

type Outcomes = { requested: number; completed: number; error: number; cancelled: number; expired: number; abandoned: number };
function outcomes(o: Partial<Outcomes>): Outcomes {
  const r = { requested: 0, completed: 0, error: 0, cancelled: 0, expired: 0, ...o };
  return { ...r, abandoned: r.cancelled + r.expired };
}
function labelRow(value: string | null, marker: string | null, circuits: Record<string, Partial<Outcomes>>) {
  const all = outcomes({});
  const out: Record<string, Outcomes> = {};
  for (const [c, o] of Object.entries(circuits)) {
    out[c] = outcomes(o);
    for (const k of ['requested', 'completed', 'error', 'cancelled', 'expired', 'abandoned'] as const) all[k] += out[c][k];
  }
  return { value, marker, circuits: out, all } as never;
}
function withLabels(): StatsReport {
  const r = report([{ date: '2026-10-14', circuits: { oidc_domain_attestation: counts({ requested: 9, completed: 6 }), coinbase_attestation: counts({ requested: 3 }) } }]);
  r.dimensions.origin = {
    'v:dojangscan.com': labelRow('dojangscan.com', null, { oidc_domain_attestation: { requested: 6, completed: 4, cancelled: 1 } }),
    'v:demo.zkproofport.app': labelRow('demo.zkproofport.app', null, { oidc_domain_attestation: { requested: 3, completed: 2 }, coinbase_attestation: { requested: 3 } }),
    'm:none': labelRow(null, 'none', {}),
  };
  r.dimensions.scope = { 'm:other': labelRow(null, 'other', { oidc_domain_attestation: { requested: 1 } }) };
  r.dimensions.country = {
    'v:KR': labelRow('KR', null, { oidc_domain_attestation: { completed: 5, error: 1 } }),
    'v:US': labelRow('US', null, { oidc_domain_attestation: { completed: 1 }, coinbase_attestation: { cancelled: 1 } }),
    'm:unknown': labelRow(null, 'unknown', { oidc_domain_attestation: { error: 2 } }),
  };
  return r;
}

describe('labels (site, scope, country)', () => {
  it('rows are busiest first, a marker reads as Korean text, a value as itself', () => {
    const rows = core.dimensionRows(withLabels(), 'origin');
    // Both sites have 6 requests; the tie goes to the one with more answers (5 vs 2).
    expect(rows.map((r) => r.label)).toEqual(['dojangscan.com', 'demo.zkproofport.app', '(보내지 않음)']);
    expect(rows[0]).toMatchObject({ requested: 6, completed: 4, cancelled: 1, rate: '66.7%' });
  });

  it('a circuit filter keeps only that circuit and drops labels without it', () => {
    const rows = core.dimensionRows(withLabels(), 'origin', 'coinbase_attestation');
    expect(rows).toEqual([expect.objectContaining({ label: 'demo.zkproofport.app', requested: 3, completed: 0 })]);
  });

  it('a label filter: per-circuit rows and totals of that label only', () => {
    const r = withLabels();
    expect(core.labelCircuitRows(r, 'origin', 'v:demo.zkproofport.app').map((x) => [x.circuit, x.requested])).toEqual([
      ['coinbase_attestation', 3], ['oidc_domain_attestation', 3],
    ]);
    expect(core.labelTotals(r, 'origin', 'v:dojangscan.com')).toMatchObject({ requested: 6, completed: 4, rate: '66.7%' });
    expect(core.labelTotals(r, 'origin', 'v:dojangscan.com', 'coinbase_attestation')).toMatchObject({ requested: 0, rate: '—' });
    expect(core.labelTotals(r, 'origin', 'v:gone.example')).toMatchObject({ requested: 0, rate: '—' });
    expect(core.labelCircuitRows(r, 'origin', 'v:gone.example')).toEqual([]);
  });

  it('an unknown label kind is an error, never another kind', () => {
    expect(() => core.dimensionRows(withLabels(), 'site')).toThrow(/Unknown label kind 'site'/);
  });

  it('a relay that sent no dimensions reads as empty, not as a crash', () => {
    const r = withLabels() as unknown as Record<string, unknown>;
    delete r.dimensions;
    expect(core.dimensionRows(r as unknown as StatsReport, 'country')).toEqual([]);
  });

  it('a label is text only: markup in a value comes back as the same characters', () => {
    const r = withLabels();
    r.dimensions.scope['v:%3Cimg%3E'] = labelRow('<img src=x onerror=alert(1)>', null, { oidc_domain_attestation: { requested: 1 } });
    expect(core.dimensionRows(r, 'scope').map((x) => x.label)).toContain('<img src=x onerror=alert(1)>');
  });
});

describe('country map', () => {
  it('shades: 0 for nothing, the busiest is the darkest, one answer the lightest', () => {
    expect(core.shadeFor(0, 10)).toBe(0);
    expect(core.shadeFor(5, 0)).toBe(0);
    expect(core.shadeFor(1, 1)).toBe(core.MAP_SHADES);
    expect(core.shadeFor(10, 10)).toBe(core.MAP_SHADES);
    expect(core.shadeFor(1, 10_000)).toBe(1);
    const steps = [1, 10, 100, 1000, 10_000].map((n) => core.shadeFor(n, 10_000));
    expect([...steps].sort((a, b) => a - b)).toEqual(steps);
    expect(steps.every((s) => s >= 1 && s <= core.MAP_SHADES)).toBe(true);
  });

  it('only real country codes with answers are on the map; markers stay in the table', () => {
    const shades = core.mapShades(withLabels());
    expect(Object.keys(shades).sort()).toEqual(['KR', 'US']);
    expect(shades.KR).toEqual({ count: 6, shade: core.MAP_SHADES });
    expect(shades.US.count).toBe(2);
  });

  it('a circuit filter recolours the map for that circuit', () => {
    expect(core.mapShades(withLabels(), 'coinbase_attestation')).toEqual({ US: { count: 1, shade: core.MAP_SHADES } });
  });

  it('clicking a country: its name, totals and per-circuit answers, busiest first', () => {
    const d = core.countryDetail(withLabels(), 'US');
    expect(d.code).toBe('US');
    expect(d.name).toContain('US');
    expect(d.total).toEqual({ completed: 1, error: 0, cancelled: 1, answered: 2 });
    expect(d.circuits.map((c) => c.circuit)).toEqual(['coinbase_attestation', 'oidc_domain_attestation']);
  });

  it('a country with no answers opens empty rather than failing', () => {
    expect(core.countryDetail(withLabels(), 'FR')).toMatchObject({ code: 'FR', total: { answered: 0 }, circuits: [] });
  });

  it('country names are Korean where the runtime knows them, the bare code otherwise', () => {
    expect(core.countryName('KR')).toBe('대한민국 (KR)');
    expect(core.countryName('ZZ')).toMatch(/ZZ/);
  });
});

describe('range presets', () => {
  it('the page and the server agree on the longest range', () => {
    expect(core.MAX_RANGE_DAYS).toBe(STATS_MAX_RANGE_DAYS);
  });

  it('7 / 30 / 90 days end today (UTC) and include both ends', () => {
    expect(core.rangeForPreset(7, NOW)).toEqual({ from: '2026-10-08', to: '2026-10-14' });
    expect(core.rangeForPreset(30, NOW)).toEqual({ from: '2026-09-15', to: '2026-10-14' });
    expect(core.rangeForPreset(90, NOW)).toEqual({ from: '2026-07-17', to: '2026-10-14' });
    expect(core.PRESET_DAYS).toEqual([7, 30, 90]);
    expect(core.DEFAULT_PRESET_DAYS).toBe(7);
  });

  it('uses the UTC day, not the local one: 00:30 UTC is already the new day', () => {
    expect(core.rangeForPreset(1, Date.parse('2026-10-15T00:30:00Z'))).toEqual({ from: '2026-10-15', to: '2026-10-15' });
  });

  it('boundaries: 1 and 400 allowed; 0, 401, fractions and NaN refused', () => {
    expect(core.rangeForPreset(1, NOW)).toEqual({ from: '2026-10-14', to: '2026-10-14' });
    const r400 = core.rangeForPreset(400, NOW);
    expect(core.checkRange(r400.from, r400.to)).toEqual({ ok: true, days: 400 });
    for (const bad of [0, 401, 800, 1.5, Number.NaN, -7]) {
      expect(() => core.rangeForPreset(bad, NOW)).toThrow(/1\.\.400/);
    }
  });

  it('crosses a leap day correctly', () => {
    expect(core.rangeForPreset(3, Date.parse('2028-03-01T12:00:00Z'))).toEqual({ from: '2028-02-28', to: '2028-03-01' });
  });
});

describe('checkRange (mirrors the server)', () => {
  it('accepts one day and 400 days, refuses 401', () => {
    expect(core.checkRange('2026-10-14', '2026-10-14')).toEqual({ ok: true, days: 1 });
    expect(core.checkRange('2025-09-10', '2026-10-14')).toEqual({ ok: true, days: 400 });
    expect(core.checkRange('2025-09-09', '2026-10-14')).toMatchObject({ ok: false, error: expect.stringContaining('401') });
  });

  it('refuses from after to', () => {
    expect(core.checkRange('2026-10-15', '2026-10-14')).toMatchObject({ ok: false });
  });

  it('refuses empty, whitespace, non-dates, impossible dates and hostile strings as separate cases', () => {
    for (const v of ['', ' ', '2026-02-30', '2026-13-01', '26-10-14', '2026-10-14T00:00:00Z', "2026-10-14' OR 1=1", '<script>', '２０２６-10-14', null, undefined, 20261014]) {
      expect(core.checkRange(v, '2026-10-14').ok).toBe(false);
      expect(core.checkRange('2026-10-14', v).ok).toBe(false);
    }
  });
});

describe('successRate', () => {
  it('is an em dash when nothing was requested, never NaN or Infinity', () => {
    expect(core.successRate(0, 0)).toBe('—');
    expect(core.successRate(3, 0)).toBe('—');
  });
  it('is completed / requested with one decimal', () => {
    expect(core.successRate(1, 3)).toBe('33.3%');
    expect(core.successRate(0, 5)).toBe('0.0%');
    expect(core.successRate(5, 5)).toBe('100.0%');
    expect(core.successRate(1, 1_000_000)).toBe('0.0%');
  });
});

describe('errorLabel', () => {
  it('labels known codes with the app titles', () => {
    expect(core.errorLabel('E2005')).toBe('Attestation Not Found');
    expect(core.errorLabel('E1007')).toBe('Request Already Answered');
  });
  it('a code with no label is shown bare (empty label), and `none` is named', () => {
    expect(core.errorLabel('E7777')).toBe('');
    expect(core.errorLabel('none')).toBe('코드 없음');
  });
  it('never answers from the object prototype', () => {
    for (const k of ['__proto__', 'constructor', 'toString', 'hasOwnProperty']) expect(core.errorLabel(k)).toBe('');
  });
});

describe('tokenFormatError', () => {
  it('empty and whitespace-only are "enter a token"', () => {
    expect(core.tokenFormatError('')).toMatch(/입력/);
    expect(core.tokenFormatError(undefined)).toMatch(/입력/);
  });
  it('refuses characters an HTTP header cannot carry: Korean, emoji, inner space, tab, newline', () => {
    for (const t of ['토큰', 'ab😀cd', 'ab cd', 'ab\tcd', 'ab\ncd', 'ab\u0000cd']) expect(core.tokenFormatError(t)).not.toBe('');
  });
  it('accepts a 64-hex token and any visible ASCII', () => {
    expect(core.tokenFormatError('a'.repeat(64))).toBe('');
    expect(core.tokenFormatError('!~%_\\"<>')).toBe('');
  });
});

describe('table rows', () => {
  const r = report([
    { date: '2026-10-13', circuits: { coinbase_attestation: counts({ requested: 4, completed: 2, byCode: { E2005: 1 } }), dojang_playground: counts({ requested: 1, expired: 1 }) } },
    { date: '2026-10-14', circuits: { coinbase_attestation: counts({ requested: 2, cancelled: 1, byCode: { E2005: 1, none: 1 } }) } },
  ]);

  it('circuit rows are busiest first, with success rate', () => {
    expect(core.circuitRows(r)).toEqual([
      { circuit: 'coinbase_attestation', requested: 6, completed: 2, error: 3, cancelled: 1, expired: 0, rate: '33.3%' },
      { circuit: 'dojang_playground', requested: 1, completed: 0, error: 0, cancelled: 0, expired: 1, rate: '0.0%' },
    ]);
    expect(core.totalsRow(r)).toEqual({ requested: 7, completed: 2, error: 3, cancelled: 1, expired: 1, rate: '28.6%' });
  });

  it('error rows group by circuit and code, most frequent first, filterable by circuit', () => {
    expect(core.errorRows(r)).toEqual([
      { circuit: 'coinbase_attestation', code: 'E2005', label: 'Attestation Not Found', count: 2 },
      { circuit: 'coinbase_attestation', code: 'none', label: '코드 없음', count: 1 },
    ]);
    expect(core.errorRows(r, 'dojang_playground')).toEqual([]);
  });

  it('daily rows keep every day of the range and sum or filter circuits', () => {
    expect(core.dailyRows(r)).toEqual([
      { date: '2026-10-13', requested: 5, completed: 2, error: 1, cancelled: 0, expired: 1 },
      { date: '2026-10-14', requested: 2, completed: 0, error: 2, cancelled: 1, expired: 0 },
    ]);
    expect(core.dailyRows(r, 'dojang_playground').map((d) => d.requested)).toEqual([1, 0]);
  });

  it('a circuit name that is markup is carried as data, unchanged (the DOM side uses textContent)', () => {
    const evil = '<img src=x onerror=alert(1)>';
    const rr = report([{ date: '2026-10-14', circuits: { [evil]: counts({ requested: 1 }) } }]);
    expect(core.circuitRows(rr)[0].circuit).toBe(evil);
  });

  it('isEmpty: all zero is empty; one count or one unrecognized field is not', () => {
    expect(core.isEmpty(report([{ date: '2026-10-14', circuits: {} }]))).toBe(true);
    expect(core.isEmpty(report([{ date: '2026-10-14', circuits: { c: counts({ expired: 1 }) } }]))).toBe(false);
    expect(core.isEmpty(report([{ date: '2026-10-14', circuits: {} }], { '2026-10-14:junk': 3 }))).toBe(false);
  });
});

describe('chart geometry', () => {
  it('niceMax rounds up to 1/2/5 x 10^n, and 0 or garbage to 1', () => {
    expect([0, -3, Number.NaN, 0.4, 1, 3, 7, 10, 11, 99, 101, 5_000_001].map(core.niceMax)).toEqual([1, 1, 1, 0.5, 1, 5, 10, 10, 20, 100, 200, 10_000_000]);
  });

  it('bars stay inside the plot, the tallest touches the top, zero is zero height', () => {
    const rows = [
      { date: 'a', requested: 10, completed: 0 },
      { date: 'b', requested: 3, completed: 2 },
    ];
    const g = core.chartGeometry(rows, ['requested', 'completed'], { width: 800, height: 240 });
    expect(g.yMax).toBe(10);
    expect(g.bars).toHaveLength(4);
    for (const b of g.bars) {
      expect(b.x).toBeGreaterThanOrEqual(g.plot.left);
      expect(b.x + b.width).toBeLessThanOrEqual(g.plot.left + g.plot.width + 1e-9);
      expect(b.y + b.height).toBeCloseTo(g.plot.bottom);
    }
    expect(g.bars[0].y).toBeCloseTo(g.plot.top);
    expect(g.bars[1].height).toBe(0);
  });

  it('400 days of zeros: no NaN anywhere, bars at least half a unit wide', () => {
    const rows = Array.from({ length: 400 }, (_, i) => ({ date: String(i), requested: 0, completed: 0 }));
    const g = core.chartGeometry(rows, ['requested', 'completed']);
    expect(g.bars).toHaveLength(800);
    for (const b of g.bars) {
      for (const v of [b.x, b.y, b.width, b.height]) expect(Number.isFinite(v)).toBe(true);
      expect(b.width).toBeGreaterThanOrEqual(0.5);
    }
  });

  it('one day: bars stay thin and centred in the plot, not half the chart wide', () => {
    const g = core.chartGeometry([{ date: 'a', requested: 2, completed: 1 }], ['requested', 'completed'], { width: 800 });
    for (const b of g.bars) expect(b.width).toBeLessThanOrEqual(core.MAX_BAR_WIDTH);
    const mid = g.plot.left + g.plot.width / 2;
    const groupLeft = g.bars[0].x;
    const groupRight = g.bars[1].x + g.bars[1].width;
    expect((groupLeft + groupRight) / 2).toBeCloseTo(mid);
  });

  it('no rows at all is not an error', () => {
    expect(core.chartGeometry([], ['requested']).bars).toEqual([]);
  });
});

describe('retryAfterMinutes', () => {
  it('rounds seconds up to minutes; absent or unreadable is null', () => {
    expect(core.retryAfterMinutes('900')).toBe(15);
    expect(core.retryAfterMinutes('61')).toBe(2);
    expect(core.retryAfterMinutes('1')).toBe(1);
    for (const v of [null, '', '0', '-5', 'soon', 'Wed, 21 Oct 2026 07:28:00 GMT']) expect(core.retryAfterMinutes(v)).toBeNull();
  });
});
