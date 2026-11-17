/**
 * Ephemeral key agreement and authenticated message encryption for the P2P session layer.
 *
 * The scheme is intentionally small and standard-library only:
 *
 * 1. Each peer generates a fresh ECDH P-256 key pair per session. Keys never leave memory,
 *    are never persisted, and are discarded when the session closes.
 * 2. Both peers export their public key as a JSON Web Key and exchange it over the signaling
 *    channel. The channel is untrusted; confidentiality comes from the ECDH secret.
 * 3. The raw ECDH secret is run through HKDF-SHA-256 to produce a 256-bit AES-GCM key. The HKDF
 *    salt is the SHA-256 digest of the two public keys in sorted order, so both peers derive the
 *    same salt without extra round trips, and the digest doubles as a short-authentication-string
 *    transcript that a user can compare out of band.
 * 4. Every message gets a fresh 96-bit random IV. The IV is prepended to the ciphertext in the
 *    wire frame, never reused, and authenticated by AES-GCM.
 */

/** The only curve this module accepts. */
export const CURVE = "P-256";

/** AES-GCM key length in bits. */
export const AES_KEY_BITS = 256;

/** AES-GCM initialization vector length in bytes (96 bits, as recommended for GCM). */
export const IV_BYTES = 12;

/** GCM authentication tag length in bits. */
const TAG_BITS = 128;

const HKDF_INFO = new TextEncoder().encode("p2p-ephemeral-webrtc/v1 aes-gcm-256");

const encoder = new TextEncoder();
const decoder = new TextDecoder("utf-8", { fatal: true });

/** An encrypted message as it appears on the wire. Both fields are base64. */
export interface EncryptedFrame {
  /** Base64-encoded 96-bit initialization vector. */
  readonly iv: string;
  /** Base64-encoded ciphertext with the GCM tag appended. */
  readonly ciphertext: string;
}

/** Result of the ECDH + HKDF handshake. */
export interface SessionKeys {
  /** AES-GCM-256 key, valid only for this session. */
  readonly key: CryptoKey;
  /** SHA-256 digest over both public keys in canonical order. */
  readonly transcript: Uint8Array;
}

const BASE64_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const BASE64_LOOKUP: Readonly<Record<string, number>> = (() => {
  const table: Record<string, number> = {};
  for (let index = 0; index < BASE64_ALPHABET.length; index += 1) {
    const character = BASE64_ALPHABET[index];
    if (character !== undefined) {
      table[character] = index;
    }
  }
  return table;
})();

/**
 * Encodes bytes as standard padded base64 without relying on `Buffer` or `btoa`, so the same
 * code path runs in Node, browsers, and edge isolates.
 */
export function toBase64(bytes: Uint8Array): string {
  let output = "";
  for (let index = 0; index < bytes.length; index += 3) {
    const first = bytes[index] ?? 0;
    const second = bytes[index + 1];
    const third = bytes[index + 2];
    output += BASE64_ALPHABET[first >> 2] ?? "";
    output += BASE64_ALPHABET[((first & 0b11) << 4) | ((second ?? 0) >> 4)] ?? "";
    output += second === undefined ? "=" : (BASE64_ALPHABET[((second & 0b1111) << 2) | ((third ?? 0) >> 6)] ?? "");
    output += third === undefined ? "=" : (BASE64_ALPHABET[third & 0b111111] ?? "");
  }
  return output;
}

/**
 * Decodes standard padded base64 and rejects every non-canonical input instead of silently
 * dropping characters.
 */
export function fromBase64(text: string): Uint8Array {
  if (text.length % 4 !== 0) {
    throw new Error("invalid base64: length must be a multiple of four");
  }
  let padding = 0;
  if (text.endsWith("==")) {
    padding = 2;
  } else if (text.endsWith("=")) {
    padding = 1;
  }
  const body = padding === 0 ? text : text.slice(0, -padding);
  const output = new Uint8Array((text.length / 4) * 3 - padding);
  let written = 0;
  for (let index = 0; index < body.length; index += 4) {
    const chunk = body.slice(index, index + 4);
    let accumulator = 0;
    for (const character of chunk) {
      const value = BASE64_LOOKUP[character];
      if (value === undefined) {
        throw new Error(`invalid base64 character: ${JSON.stringify(character)}`);
      }
      accumulator = (accumulator << 6) | value;
    }
    const bits = chunk.length * 6;
    const byteCount = Math.min(3, output.length - written);
    for (let offset = 0; offset < byteCount; offset += 1) {
      output[written + offset] = (accumulator >> (bits - 8 * (offset + 1))) & 0xff;
    }
    written += byteCount;
  }
  return output;
}

/** Generates a fresh ephemeral ECDH P-256 key pair. */
export async function generateEphemeralKeyPair(): Promise<CryptoKeyPair> {
  return crypto.subtle.generateKey({ name: "ECDH", namedCurve: CURVE }, false, ["deriveBits"]);
}

/** Exports the public half of a session key pair as a JSON Web Key. */
export async function exportPublicKey(key: CryptoKey): Promise<JsonWebKey> {
  return crypto.subtle.exportKey("jwk", key);
}

/**
 * Imports a peer public key. The key is validated by the Web Crypto implementation: wrong curve,
 * wrong key type, or a private key component all throw.
 */
export async function importPublicKey(jwk: JsonWebKey): Promise<CryptoKey> {
  return crypto.subtle.importKey("jwk", jwk, { name: "ECDH", namedCurve: CURVE }, true, []);
}

async function rawPublicKey(key: CryptoKey): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.exportKey("raw", key));
}

function compareBytes(left: Uint8Array, right: Uint8Array): number {
  const length = Math.min(left.length, right.length);
  for (let index = 0; index < length; index += 1) {
    const a = left[index] ?? 0;
    const b = right[index] ?? 0;
    if (a !== b) {
      return a - b;
    }
  }
  return left.length - right.length;
}

/**
 * Derives the session key from an own key pair and the peer's public key.
 *
 * The salt is symmetric by construction, so both peers compute identical key material. The
 * returned transcript is stable across peers and can be shown as a verification code.
 */
export async function deriveSessionKeys(own: CryptoKeyPair, peerPublicJwk: JsonWebKey): Promise<SessionKeys> {
  const peerPublicKey = await importPublicKey(peerPublicJwk);
  const sharedSecret = await crypto.subtle.deriveBits({ name: "ECDH", public: peerPublicKey }, own.privateKey, 256);

  const ownRaw = await rawPublicKey(own.publicKey);
  const peerRaw = await rawPublicKey(peerPublicKey);
  const [first, second] = compareBytes(ownRaw, peerRaw) <= 0 ? [ownRaw, peerRaw] : [peerRaw, ownRaw];
  const concatenated = new Uint8Array(first.length + second.length);
  concatenated.set(first, 0);
  concatenated.set(second, first.length);
  const transcript = new Uint8Array(await crypto.subtle.digest("SHA-256", concatenated));

  const hkdfKey = await crypto.subtle.importKey("raw", sharedSecret, "HKDF", false, ["deriveKey"]);
  const key = await crypto.subtle.deriveKey(
    { name: "HKDF", hash: "SHA-256", salt: transcript, info: HKDF_INFO },
    hkdfKey,
    { name: "AES-GCM", length: AES_KEY_BITS },
    false,
    ["encrypt", "decrypt"],
  );

  return { key, transcript };
}

function gcmParameters(iv: Uint8Array, additionalData?: string): AesGcmParams {
  if (additionalData === undefined) {
    return { name: "AES-GCM", iv, tagLength: TAG_BITS };
  }
  return { name: "AES-GCM", iv, tagLength: TAG_BITS, additionalData: encoder.encode(additionalData) };
}

/**
 * Encrypts a UTF-8 string with a fresh random 96-bit IV.
 *
 * `additionalData` is authenticated but not encrypted, which binds a frame to a context string
 * (for example the room token or message sequence number).
 */
export async function encryptMessage(key: CryptoKey, plaintext: string, additionalData?: string): Promise<EncryptedFrame> {
  const iv = crypto.getRandomValues(new Uint8Array(IV_BYTES));
  if (iv.length !== IV_BYTES) {
    throw new Error(`expected a ${IV_BYTES}-byte initialization vector`);
  }
  const ciphertext = await crypto.subtle.encrypt(gcmParameters(iv, additionalData), key, encoder.encode(plaintext));
  return { iv: toBase64(iv), ciphertext: toBase64(new Uint8Array(ciphertext)) };
}

/**
 * Decrypts and authenticates a frame. Throws on a malformed frame, a tampered ciphertext, a
 * mismatched IV, or a wrong key — AES-GCM does not distinguish between those cases.
 */
export async function decryptMessage(key: CryptoKey, frame: EncryptedFrame, additionalData?: string): Promise<string> {
  const iv = fromBase64(frame.iv);
  if (iv.length !== IV_BYTES) {
    throw new Error(`invalid frame: expected a ${IV_BYTES}-byte initialization vector`);
  }
  const ciphertext = fromBase64(frame.ciphertext);
  if (ciphertext.length < TAG_BITS / 8) {
    throw new Error("invalid frame: ciphertext is shorter than the authentication tag");
  }
  const plaintext = await crypto.subtle.decrypt(gcmParameters(iv, additionalData), key, ciphertext);
  return decoder.decode(plaintext);
}

/** Serializes a frame for transport over a data channel. */
export function serializeFrame(frame: EncryptedFrame): string {
  return JSON.stringify({ iv: frame.iv, ciphertext: frame.ciphertext });
}

/** Parses a frame received from a data channel, rejecting unexpected shapes. */
export function parseFrame(text: string): EncryptedFrame {
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    throw new Error("invalid frame: not JSON");
  }
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    throw new Error("invalid frame: expected an object");
  }
  const candidate = parsed as Record<string, unknown>;
  const { iv, ciphertext } = candidate;
  if (typeof iv !== "string" || typeof ciphertext !== "string") {
    throw new Error("invalid frame: iv and ciphertext must be strings");
  }
  return { iv, ciphertext };
}
