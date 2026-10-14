/**
 * Masking for relay logs.
 *
 * The relay sees personal information it has no reason to write down: the
 * caller's IP, wallet and signer addresses, scopes and nullifiers inside proof
 * inputs and public inputs, e-mail domains in OIDC requests. Every log line
 * that could carry one of those goes through this module.
 *
 * Masking is not truncation. The project rule against shortening log values
 * still holds for everything else; this module replaces PERSONAL values with a
 * fixed-shape stand-in that keeps enough to correlate two lines of the same
 * request (first and last four hex digits, the /16 of an IPv4 address) and no
 * more.
 *
 * Rate limiting and every other piece of logic keeps reading the real values.
 * Only what reaches stdout is masked.
 */

const HEX_BODY_MIN = 16;

/** `0x` + hex of at least 16 digits: addresses, 32-byte hashes, nullifiers, proofs. */
function maskPrefixedHex(value: string): string {
  const body = value.slice(2);
  return `0x${body.slice(0, 4)}…${body.slice(-4)}`;
}

/** Bare hex of at least 32 digits (a sha256 digest such as inputsHash). */
function maskBareHex(value: string): string {
  return `${value.slice(0, 4)}…${value.slice(-4)}`;
}

/**
 * A hex value (address, hash, nullifier) masked to `0x1234…abcd`.
 * Values that are not long hex strings are returned unchanged, because they
 * are not identifiers of a person.
 */
export function maskHex(value: unknown): string {
  if (value === undefined || value === null) return String(value);
  const s = String(value);
  if (/^0x[0-9a-fA-F]+$/.test(s) && s.length - 2 >= HEX_BODY_MIN) return maskPrefixedHex(s);
  if (/^[0-9a-fA-F]{32,}$/.test(s)) return maskBareHex(s);
  return s;
}

function maskIPv4(ip: string): string {
  const parts = ip.split('.');
  return `${parts[0]}.${parts[1]}.x.x`;
}

/** Expands `::` so an IPv6 address has its eight groups. Null when it is not one. */
function ipv6Groups(ip: string): string[] | null {
  if (!/^[0-9a-fA-F:]+$/.test(ip) || !ip.includes(':')) return null;
  const halves = ip.split('::');
  if (halves.length > 2) return null;
  const head = halves[0] ? halves[0].split(':') : [];
  const tail = halves.length === 2 && halves[1] ? halves[1].split(':') : [];
  const missing = 8 - head.length - tail.length;
  if (halves.length === 2 ? missing < 1 : missing !== 0) return null;
  const groups = [...head, ...Array(Math.max(0, missing)).fill('0'), ...tail];
  if (groups.some((g) => g.length === 0 || g.length > 4)) return null;
  return groups;
}

function maskIPv6(ip: string): string | null {
  const groups = ipv6Groups(ip);
  if (!groups) return null;
  return `${groups.slice(0, 3).join(':')}:x:x:x:x:x`;
}

/**
 * An IP masked for logging: IPv4 keeps its first two octets (`203.0.x.x`),
 * IPv6 its first three groups, an IPv4-mapped IPv6 address keeps the mapping
 * prefix and masks the IPv4 part.
 */
export function maskIp(ip: string | undefined | null): string {
  if (!ip) return 'unknown';
  const mapped = /^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/i.exec(ip);
  if (mapped) return `::ffff:${maskIPv4(mapped[1])}`;
  if (/^\d{1,3}(?:\.\d{1,3}){3}$/.test(ip)) return maskIPv4(ip);
  const v6 = maskIPv6(ip);
  if (v6) return v6;
  // Not an address at all; scrub it rather than print an unknown shape raw.
  return scrubText(ip);
}

const PREFIXED_HEX_RE = new RegExp(`0x[0-9a-fA-F]{${HEX_BODY_MIN},}`, 'g');
const BARE_HEX_RE = /\b[0-9a-fA-F]{32,}\b/g;
const IPV4_MAPPED_RE = /::ffff:(\d{1,3}(?:\.\d{1,3}){3})\b/gi;
const IPV4_RE = /\b(\d{1,3})\.(\d{1,3})\.\d{1,3}\.\d{1,3}\b/g;
// Four or more groups, or any form with `::` that has at least one group next
// to it. A clock time (`13:21:03`) has three groups and no `::`, so it stays.
const IPV6_RE = /(?<![0-9A-Za-z:])(?:(?:[0-9A-Fa-f]{1,4}:){3,7}[0-9A-Fa-f]{1,4}|(?:[0-9A-Fa-f]{1,4}:){0,6}[0-9A-Fa-f]{1,4}::(?:[0-9A-Fa-f]{1,4}(?::[0-9A-Fa-f]{1,4}){0,5})?|::(?:[0-9A-Fa-f]{1,4}(?::[0-9A-Fa-f]{1,4}){0,6}))(?![0-9A-Za-z:]|\.\d)/g;
const EMAIL_RE = /\b([A-Za-z0-9._%+-])[A-Za-z0-9._%+-]*@([A-Za-z0-9.-]+\.[A-Za-z]{2,})\b/g;

/**
 * Masks personal values embedded in free text: 0x hex (addresses, hashes,
 * nullifiers), long bare hex, IPv4 and IPv6 addresses, e-mail local parts.
 * Used for error messages, which are free text written by the app or by a
 * library and may quote anything.
 */
export function scrubText(text: unknown): string {
  if (text === undefined || text === null) return String(text);
  return String(text)
    .replace(PREFIXED_HEX_RE, (m) => maskPrefixedHex(m))
    .replace(BARE_HEX_RE, (m) => maskBareHex(m))
    .replace(IPV4_MAPPED_RE, (_m, v4: string) => `::ffff:${maskIPv4(v4)}`)
    .replace(IPV4_RE, (_m, a: string, b: string) => `${a}.${b}.x.x`)
    .replace(IPV6_RE, (m) => maskIPv6(m) ?? m)
    .replace(EMAIL_RE, (_m, first: string, domain: string) => `${first}***@${domain}`);
}

/** An Error (or anything thrown) as one scrubbed string, stack included. */
export function scrubError(err: unknown): string {
  if (err instanceof Error) return scrubText(err.stack ?? `${err.name}: ${err.message}`);
  return scrubText(typeof err === 'string' ? err : safeJson(err));
}

function safeJson(value: unknown): string {
  try {
    return JSON.stringify(value);
  } catch {
    return String(value);
  }
}

/**
 * Fields of a request or callback body that describe the ENVELOPE and say
 * nothing about a person. Everything else is reported by key name only.
 */
const ENVELOPE_FIELDS = [
  'requestId',
  'circuitId',
  'circuit',
  'status',
  'errorCode',
  'dappName',
  'chainId',
  'returnScheme',
] as const;

/**
 * A body summarised for a log line: its key names, then the envelope fields.
 *
 * `verifierAddress` is a contract, not a person, and is printed when it is a
 * well-formed address; `error` is free text and goes through the scrubber.
 * Inputs, scope, proof, publicInputs, nullifier, signature and challenge are
 * never printed -- only the fact that the key was present.
 */
export function describeBody(body: unknown): string {
  if (!body || typeof body !== 'object' || Array.isArray(body)) {
    return `body=<${Array.isArray(body) ? 'array' : typeof body}>`;
  }
  const record = body as Record<string, unknown>;
  const parts = [`keys=[${Object.keys(record).join(',')}]`];
  for (const field of ENVELOPE_FIELDS) {
    const value = record[field];
    if (value === undefined) continue;
    const printable = typeof value === 'string' || typeof value === 'number' || typeof value === 'boolean'
      ? scrubText(value)
      : `<${typeof value}>`;
    parts.push(`${field}=${printable}`);
  }
  const verifier = record.verifierAddress;
  if (typeof verifier === 'string') {
    parts.push(`verifierAddress=${/^0x[0-9a-fA-F]{40}$/.test(verifier) ? verifier : scrubText(verifier)}`);
  }
  if (record.error !== undefined) {
    parts.push(`error=${scrubText(typeof record.error === 'string' ? record.error : safeJson(record.error))}`);
  }
  return parts.join(' ');
}

/**
 * A deep link with its payload removed. The payload is the whole proof request
 * -- inputs, scope, addresses -- base64url encoded, which is not masking.
 */
export function describeDeepLink(deepLink: string): string {
  const q = deepLink.indexOf('?');
  if (q === -1) return deepLink;
  const params = new URLSearchParams(deepLink.slice(q + 1));
  const data = params.get('data');
  return `${deepLink.slice(0, q)}?data=<${data === null ? 0 : data.length} chars>`;
}
