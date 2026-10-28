import { createDecipheriv, createPublicKey, KeyObject, verify as cryptoVerify } from 'crypto';

/**
 * Decryption of a classic Google Play Integrity token.
 *
 * The app asks Play Integrity for a classic token whose nonce is bound to the
 * statement being proven. Google answers with a compact JWE (alg A256KW,
 * enc A256GCM) whose plaintext is a compact JWS (ES256) over the verdict
 * JSON. Play Console holds two keys for an app that manages its own response
 * encryption: an AES-256 decryption key and an EC P-256 verification key
 * (developer.android.com/google/play/integrity/classic, "Decrypt and verify
 * locally").
 *
 * The relay only opens the envelope. It returns the JWS exactly as Google
 * signed it -- header, payload and signature segments untouched -- so the app
 * can rebuild the signing input byte for byte, and the circuit verifies
 * Google's signature itself. The relay is trusted for confidentiality (it
 * holds the decryption key), never for integrity. It does not parse or read
 * the verdict.
 *
 * Built on Node's crypto only: AES key wrap (RFC 3394, `id-aes256-wrap`),
 * AES-256-GCM and ECDSA P-256 with IEEE P1363 (r||s) signatures are all
 * native, so no JOSE library is needed at run time.
 */

export const PLAY_INTEGRITY_DECRYPTION_KEY_ENV = 'PLAY_INTEGRITY_DECRYPTION_KEY';
export const PLAY_INTEGRITY_VERIFICATION_KEY_ENV = 'PLAY_INTEGRITY_VERIFICATION_KEY';

export type PlayIntegrityConfig =
  | { enabled: true; decryptionKey: Buffer; verificationKey: KeyObject }
  | { enabled: false; missing: string[] };

/**
 * Why a token was refused. Stable strings: the app branches on them. None of
 * them carries anything from the token.
 */
export type PlayIntegrityReason =
  | 'token_missing'
  | 'token_not_string'
  | 'token_malformed'
  | 'jwe_unsupported'
  | 'key_unwrap_failed'
  | 'decrypt_failed'
  | 'not_a_jws'
  | 'jws_unsupported'
  | 'signature_invalid';

const REASON_MESSAGES: Record<PlayIntegrityReason, string> = {
  token_missing: 'token is required',
  token_not_string: 'token must be a string',
  token_malformed: 'token is not a compact JWE',
  jwe_unsupported: 'token must be encrypted with alg A256KW and enc A256GCM, without compression or critical extensions',
  key_unwrap_failed: 'token was not encrypted for this app (key unwrap failed)',
  decrypt_failed: 'token content failed authenticated decryption',
  not_a_jws: 'decrypted token is not a compact JWS',
  jws_unsupported: 'decrypted token must be signed with alg ES256, without critical extensions',
  signature_invalid: 'decrypted token signature does not verify with the Play Integrity verification key',
};

export class PlayIntegrityError extends Error {
  constructor(readonly reason: PlayIntegrityReason) {
    super(REASON_MESSAGES[reason]);
    this.name = 'PlayIntegrityError';
  }
}

export function playIntegrityMessage(reason: PlayIntegrityReason): string {
  return REASON_MESSAGES[reason];
}

/** The three segments of the JWS, base64url, exactly as Google signed them. */
export interface DecryptedPlayIntegrityToken {
  protectedHeader: string;
  payload: string;
  signature: string;
}

const AES_KEY_WRAP_IV = Buffer.from('A6A6A6A6A6A6A6A6', 'hex');
const CEK_BYTES = 32;
const WRAPPED_CEK_BYTES = CEK_BYTES + 8;
const GCM_IV_BYTES = 12;
const GCM_TAG_BYTES = 16;
const ES256_SIGNATURE_BYTES = 64;

const BASE64URL_RE = /^[A-Za-z0-9_-]+$/;
const BASE64_RE = /^[A-Za-z0-9+/]+={0,2}$/;

/** Canonical unpadded base64url only; null for anything else. */
function decodeBase64Url(segment: string): Buffer | null {
  if (!BASE64URL_RE.test(segment)) return null;
  const bytes = Buffer.from(segment, 'base64url');
  return bytes.toString('base64url') === segment ? bytes : null;
}

/** A segment that decodes to a JSON object; null otherwise. Never rethrows the parser's message (it quotes input). */
function decodeJsonObject(segment: string): Record<string, unknown> | null {
  const bytes = decodeBase64Url(segment);
  if (!bytes) return null;
  try {
    const value: unknown = JSON.parse(bytes.toString('utf8'));
    return value && typeof value === 'object' && !Array.isArray(value) ? (value as Record<string, unknown>) : null;
  } catch {
    return null;
  }
}

function decodeStandardBase64(value: string, name: string): Buffer {
  if (!BASE64_RE.test(value)) throw new Error(`${name} must be standard base64 (as Play Console shows it)`);
  const bytes = Buffer.from(value, 'base64');
  if (bytes.toString('base64') !== value) throw new Error(`${name} must be standard base64 (as Play Console shows it)`);
  return bytes;
}

/**
 * Reads both keys. Either one absent (unset or blank) disables the feature:
 * the relay still starts and the endpoint answers 503 naming what is missing.
 * A key that is present but malformed throws, so a wrong secret stops the
 * relay at startup instead of failing every request later. There is never a
 * default key. Surrounding whitespace is ignored (a secret written with
 * `echo` ends in a newline); nothing else is.
 */
export function playIntegrityConfigFromEnv(env: NodeJS.ProcessEnv): PlayIntegrityConfig {
  const decryptionRaw = env[PLAY_INTEGRITY_DECRYPTION_KEY_ENV]?.trim();
  const verificationRaw = env[PLAY_INTEGRITY_VERIFICATION_KEY_ENV]?.trim();
  const missing = [
    ...(decryptionRaw ? [] : [PLAY_INTEGRITY_DECRYPTION_KEY_ENV]),
    ...(verificationRaw ? [] : [PLAY_INTEGRITY_VERIFICATION_KEY_ENV]),
  ];
  // Validate whichever key is present even when the other is missing, so a
  // malformed secret is reported now rather than when its partner arrives.
  const decryptionKey = decryptionRaw ? parseDecryptionKey(decryptionRaw) : null;
  const verificationKey = verificationRaw ? parseVerificationKey(verificationRaw) : null;
  if (!decryptionKey || !verificationKey) return { enabled: false, missing };
  return { enabled: true, decryptionKey, verificationKey };
}

export function parseDecryptionKey(value: string): Buffer {
  const key = decodeStandardBase64(value, PLAY_INTEGRITY_DECRYPTION_KEY_ENV);
  if (key.length !== CEK_BYTES) {
    throw new Error(`${PLAY_INTEGRITY_DECRYPTION_KEY_ENV} must decode to 32 bytes (AES-256), got ${key.length}`);
  }
  return key;
}

export function parseVerificationKey(value: string): KeyObject {
  const der = decodeStandardBase64(value, PLAY_INTEGRITY_VERIFICATION_KEY_ENV);
  let key: KeyObject;
  try {
    key = createPublicKey({ key: der, format: 'der', type: 'spki' });
  } catch {
    throw new Error(`${PLAY_INTEGRITY_VERIFICATION_KEY_ENV} must be a DER-encoded X.509 SubjectPublicKeyInfo`);
  }
  const curve = key.asymmetricKeyDetails?.namedCurve;
  if (key.asymmetricKeyType !== 'ec' || curve !== 'prime256v1') {
    throw new Error(`${PLAY_INTEGRITY_VERIFICATION_KEY_ENV} must be an EC P-256 public key, got ${key.asymmetricKeyType}${curve ? `/${curve}` : ''}`);
  }
  return key;
}

function rejectsCrit(header: Record<string, unknown>): boolean {
  return Object.prototype.hasOwnProperty.call(header, 'crit');
}

/**
 * Opens a classic Play Integrity token and returns its JWS segments.
 *
 * The ES256 signature is checked here too, although the circuit checks it
 * again: a token that will never verify is refused now, so the app learns in
 * one round trip instead of after spending a proof. Passing this check is not
 * what makes the verdict trustworthy -- the in-circuit check is.
 */
export function decryptPlayIntegrityToken(
  token: string,
  keys: { decryptionKey: Buffer; verificationKey: KeyObject },
): DecryptedPlayIntegrityToken {
  const parts = token.split('.');
  if (parts.length !== 5) throw new PlayIntegrityError('token_malformed');
  const [headerSegment, wrappedKeySegment, ivSegment, ciphertextSegment, tagSegment] = parts;

  const header = decodeJsonObject(headerSegment);
  if (!header) throw new PlayIntegrityError('token_malformed');
  // The header decides how the other segments are read (`dir` has an empty
  // key segment), so a JWE of another kind is named as such before them.
  if (header.alg !== 'A256KW' || header.enc !== 'A256GCM' || header.zip !== undefined || rejectsCrit(header)) {
    throw new PlayIntegrityError('jwe_unsupported');
  }

  const wrappedKey = decodeBase64Url(wrappedKeySegment);
  const iv = decodeBase64Url(ivSegment);
  // An empty plaintext encrypts to an empty ciphertext segment; it is still a
  // JWE and is refused below as not carrying a JWS.
  const ciphertext = ciphertextSegment === '' ? Buffer.alloc(0) : decodeBase64Url(ciphertextSegment);
  const tag = decodeBase64Url(tagSegment);
  if (!wrappedKey || !iv || !ciphertext || !tag) throw new PlayIntegrityError('token_malformed');
  if (wrappedKey.length !== WRAPPED_CEK_BYTES || iv.length !== GCM_IV_BYTES || tag.length !== GCM_TAG_BYTES) {
    throw new PlayIntegrityError('token_malformed');
  }

  let cek: Buffer;
  try {
    const unwrap = createDecipheriv('id-aes256-wrap', keys.decryptionKey, AES_KEY_WRAP_IV);
    cek = Buffer.concat([unwrap.update(wrappedKey), unwrap.final()]);
  } catch {
    throw new PlayIntegrityError('key_unwrap_failed');
  }
  if (cek.length !== CEK_BYTES) throw new PlayIntegrityError('key_unwrap_failed');

  let plaintext: Buffer;
  try {
    const decipher = createDecipheriv('aes-256-gcm', cek, iv, { authTagLength: GCM_TAG_BYTES });
    // RFC 7516 5.2 step 14: the AAD is the ASCII of the encoded protected header.
    decipher.setAAD(Buffer.from(headerSegment, 'ascii'));
    decipher.setAuthTag(tag);
    plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  } catch {
    throw new PlayIntegrityError('decrypt_failed');
  }

  const jws = plaintext.toString('utf8').split('.');
  if (jws.length !== 3) throw new PlayIntegrityError('not_a_jws');
  const [protectedHeader, payload, signatureSegment] = jws;
  const jwsHeader = decodeJsonObject(protectedHeader);
  const signature = decodeBase64Url(signatureSegment);
  if (!jwsHeader || !decodeBase64Url(payload) || !signature) throw new PlayIntegrityError('not_a_jws');
  if (jwsHeader.alg !== 'ES256' || rejectsCrit(jwsHeader)) throw new PlayIntegrityError('jws_unsupported');

  if (signature.length !== ES256_SIGNATURE_BYTES) throw new PlayIntegrityError('signature_invalid');
  const signingInput = Buffer.from(`${protectedHeader}.${payload}`, 'ascii');
  const verified = cryptoVerify('sha256', signingInput, { key: keys.verificationKey, dsaEncoding: 'ieee-p1363' }, signature);
  if (!verified) throw new PlayIntegrityError('signature_invalid');

  return { protectedHeader, payload, signature: signatureSegment };
}
