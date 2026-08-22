/**
 * Return-target validation for proof requests.
 *
 * `returnScheme` answers exactly one question: "which app should ZKProofport
 * open once it is done?" It is deliberately NOT a URL. The model is the one
 * MetaMask already uses for us — AppKit metadata carries
 * `redirect: { native: 'zkproofport://' }` and MetaMask opens that scheme when
 * it finishes. It never learns our result page, and we do not learn theirs.
 *
 * This is envelope-level data (who sent the request / where to hand control
 * back), not proof-input data, so validating it here does not violate the
 * relay's "inspect the envelope, never the contents" rule.
 *
 * Accepted forms — nothing else:
 *   1. bare custom scheme   `mydapp://`             (RFC 3986 scheme + exactly "://")
 *   2. https origin         `https://host[:port]`   (no path / query / fragment / userinfo)
 *
 * Rejecting paths and query strings is the load-bearing guard: it follows
 * straight from the requirement ("which app", not "which URL") and it means a
 * hostile requester can at most launch an app's default entry point, never
 * drive it to a specific action such as `bankapp://transfer?to=...`.
 *
 * The same rules are re-implemented in proofport-app-sdk (fail-fast DX) and in
 * proofport-app (`src/utils/deeplink.ts`, defence in depth — the app must never
 * trust a value that arrived inside a deep link). Keep all three in sync.
 */

/** Longest accepted value. Long enough for `https://` + a max-ish hostname + port. */
export const MAX_RETURN_SCHEME_LENGTH = 128;

/** RFC 3986 scheme (`ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )`) followed by exactly `://`. */
const BARE_SCHEME_RE = /^[a-z][a-z0-9+.-]*:\/\/$/;

/** `https://host[:port]` with no userinfo, path, query or fragment. */
const HTTPS_ORIGIN_RE =
  /^https:\/\/[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+(:[0-9]{1,5})?$/;

/**
 * Schemes we refuse to hand to the OS even in the bare `scheme://` shape.
 * `http` is here because cleartext is never the right return target and
 * allowing it would blur the "this field is not a URL" line.
 */
const DENIED_SCHEMES = new Set([
  'about',
  'blob',
  'content',
  'data',
  'facetime',
  'facetime-audio',
  'file',
  'ftp',
  'http',
  'intent',
  'javascript',
  'jar',
  'mailto',
  'sms',
  'tel',
  'vbscript',
]);

export interface ReturnSchemeValidation {
  valid: boolean;
  /** Present when valid: lowercased value to store on the request. */
  normalized?: string;
  /** Present when invalid. */
  error?: string;
}

/**
 * Validates a caller-supplied return target.
 *
 * Length is checked before any regex runs, so a multi-megabyte string can never
 * reach the pattern matcher.
 */
export function validateReturnScheme(value: unknown): ReturnSchemeValidation {
  if (value === undefined || value === null) {
    return { valid: false, error: 'returnScheme is not set' };
  }
  if (typeof value !== 'string') {
    return { valid: false, error: 'returnScheme must be a string' };
  }
  if (value.length === 0) {
    return { valid: false, error: 'returnScheme must not be empty' };
  }
  if (value.length > MAX_RETURN_SCHEME_LENGTH) {
    return {
      valid: false,
      error: `returnScheme must be at most ${MAX_RETURN_SCHEME_LENGTH} characters`,
    };
  }
  // No trimming: a value with surrounding whitespace is a caller bug, and
  // silently repairing it hides that. Whitespace-only fails here too.
  if (/\s/.test(value)) {
    return { valid: false, error: 'returnScheme must not contain whitespace' };
  }

  const normalized = value.toLowerCase();

  if (HTTPS_ORIGIN_RE.test(normalized)) {
    return { valid: true, normalized };
  }

  if (!BARE_SCHEME_RE.test(normalized)) {
    return {
      valid: false,
      error:
        'returnScheme must be a bare custom scheme such as "mydapp://" or an https origin such as "https://myapp.com" — paths, query strings and fragments are not accepted',
    };
  }

  const schemeName = normalized.slice(0, normalized.indexOf(':'));
  if (DENIED_SCHEMES.has(schemeName)) {
    return { valid: false, error: `returnScheme "${schemeName}" is not allowed` };
  }

  return { valid: true, normalized };
}
