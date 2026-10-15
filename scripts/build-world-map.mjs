#!/usr/bin/env node
// Builds src/admin/world.json: one SVG path per country, keyed by its
// two-letter ISO 3166-1 code, for the admin page's country map.
//
// The admin page loads nothing from another origin (its CSP is 'self' only),
// so the map ships with the relay. The output is committed; run this again
// only to change the projection or the detail level:
//
//   cd proofport-relay && npm ci && node scripts/build-world-map.mjs
//
// Source: Natural Earth 1:110m admin-0 countries (public domain), as TopoJSON
// in `world-atlas` (ISC). Numeric ISO codes become two-letter codes through
// `i18n-iso-countries` (MIT). All four packages are devDependencies pinned
// exactly; nothing here runs in the relay.
//
// The load balancer reports `{client_region}` as a CLDR region code, which is
// the two-letter ISO code for every country on this map. A shape whose numeric
// code has no two-letter code (Natural Earth's disputed areas and Kosovo, which
// has none in ISO 3166) is drawn but cannot be selected, and is listed below
// so the omission is visible rather than silent.
import { readFileSync, writeFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { feature } from 'topojson-client';
import { geoNaturalEarth1, geoPath } from 'd3-geo';
import countries from 'i18n-iso-countries';

const require = createRequire(import.meta.url);
const here = path.dirname(fileURLToPath(import.meta.url));
const out = path.join(here, '..', 'src', 'admin', 'world.json');

const WIDTH = 960;
const HEIGHT = 500;

const topology = JSON.parse(readFileSync(require.resolve('world-atlas/countries-110m.json'), 'utf8'));
const land = feature(topology, topology.objects.countries);
// Antarctica takes a fifth of the map and never sends a proof.
const shapes = land.features.filter((f) => f.properties.name !== 'Antarctica');

const projection = geoNaturalEarth1().fitSize([WIDTH, HEIGHT], { type: 'FeatureCollection', features: shapes });
const toPath = geoPath(projection);
// One decimal is below a pixel at this size and halves the file.
const round = (d) => d.replace(/-?\d+\.\d+/g, (n) => Number(n).toFixed(1));

const result = [];
const unselectable = [];
for (const f of shapes) {
  const d = toPath(f);
  if (!d) continue;
  const numeric = f.id === undefined ? undefined : String(f.id).padStart(3, '0');
  const code = numeric ? countries.numericToAlpha2(numeric) : undefined;
  if (!code) unselectable.push(f.properties.name);
  result.push({ code: code ?? null, name: f.properties.name, d: round(d) });
}
result.sort((a, b) => (a.code ?? '~').localeCompare(b.code ?? '~') || a.name.localeCompare(b.name));

const codes = result.filter((r) => r.code).map((r) => r.code);
if (new Set(codes).size !== codes.length) {
  throw new Error(`Two shapes share a country code: ${codes.filter((c, i) => codes.indexOf(c) !== i).join(', ')}`);
}
if (codes.length < 150) throw new Error(`Only ${codes.length} selectable countries; the source data looks wrong`);

writeFileSync(out, `${JSON.stringify({ width: WIDTH, height: HEIGHT, countries: result })}\n`);
console.log(`wrote ${path.relative(process.cwd(), out)}: ${result.length} shapes, ${codes.length} selectable`);
console.log(`not selectable (no two-letter code): ${unselectable.join(', ') || 'none'}`);
