/**
 * Labels that split the statistics by who asked and where the proof was made.
 *
 *   origin   the host of the page that created the request (browser `Origin`
 *            header). A browser sets it and page script cannot change it; a
 *            server or script can send anything or nothing. It is a label for
 *            counting, not an identity.
 *   scope    the dApp-chosen scope string carried in the request envelope. The
 *            relay never interprets it; it is counted as given.
 *   country  the country the app's callback came from, as the load balancer
 *            resolved it from the caller's address. Only read when the relay
 *            sits behind a front end that writes the header (edge.ts); the IP
 *            itself is never stored.
 *
 * Stored labels have two shapes, so a real value can never collide with a
 * marker: `v:<encodeURIComponent(value)>` for a value and `m:<name>` for a
 * marker. encodeURIComponent also removes `|`, the stats field separator.
 */

export const DIMENSIONS = ['origin', 'scope', 'country'] as const;
export type Dimension = (typeof DIMENSIONS)[number];

export const MARKERS = {
  /** Nothing was sent. */
  none: 'm:none',
  /** Something was sent that is not a value of this kind. */
  invalid: 'm:invalid',
  /** Longer than the dimension allows. */
  tooLong: 'm:too-long',
  /** The front end could not place the caller (empty region). */
  unknown: 'm:unknown',
  /** The day already holds the maximum number of distinct values. */
  other: 'm:other',
} as const;
export type Marker = keyof typeof MARKERS;

const MARKER_BY_LABEL: Record<string, Marker> = Object.fromEntries(
  Object.entries(MARKERS).map(([name, label]) => [label, name as Marker]),
);

/** Longest scope counted as itself, in code points. */
export const SCOPE_MAX_CHARS = 128;
/** A DNS name is at most 253 characters. */
const HOSTNAME_MAX_CHARS = 253;
const COUNTRY_RE = /^[A-Z]{2}$/;

function value(v: string): string {
  return `v:${encodeURIComponent(v)}`;
}

/** The host (with a non-default port) of an http(s) `Origin` header. */
export function originLabel(header: unknown): string {
  if (header === undefined || header === null || header === '') return MARKERS.none;
  if (typeof header !== 'string') return MARKERS.invalid;
  // Browsers send the literal "null" for opaque origins (file://, sandboxed frames).
  if (header === 'null') return MARKERS.none;
  let url: URL;
  try {
    url = new URL(header);
  } catch {
    return MARKERS.invalid;
  }
  if (url.protocol !== 'https:' && url.protocol !== 'http:') return MARKERS.invalid;
  // URL lowercases the host and turns an IDN into punycode, so one site is one label.
  const host = url.host;
  if (!host) return MARKERS.invalid;
  if (url.hostname.length > HOSTNAME_MAX_CHARS) return MARKERS.tooLong;
  return value(host);
}

export function scopeLabel(scope: unknown): string {
  if (scope === undefined || scope === null) return MARKERS.none;
  if (typeof scope !== 'string') return MARKERS.invalid;
  if (scope.trim() === '') return MARKERS.none;
  if (Array.from(scope).length > SCOPE_MAX_CHARS) return MARKERS.tooLong;
  return value(scope);
}

/**
 * `{client_region}` from the load balancer: an ISO 3166 / CLDR region code,
 * or an empty string when the address cannot be placed.
 */
export function countryLabel(header: unknown): string {
  if (header === undefined || header === null) return MARKERS.none;
  if (typeof header !== 'string') return MARKERS.invalid;
  if (header === '') return MARKERS.unknown;
  if (!COUNTRY_RE.test(header)) return MARKERS.invalid;
  return value(header);
}

export type DecodedLabel = { value: string; marker: null } | { value: null; marker: Marker };

/** Null when the label is not one this module writes. */
export function decodeLabel(label: string): DecodedLabel | null {
  if (label.startsWith('v:')) {
    try {
      return { value: decodeURIComponent(label.slice(2)), marker: null };
    } catch {
      return null;
    }
  }
  const marker = MARKER_BY_LABEL[label];
  return marker ? { value: null, marker } : null;
}
