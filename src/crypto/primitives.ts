// Standards-aligned wrappers around Node's built-in crypto.
//
// All operations used by the LiteZero protocol are implemented here so the
// rest of the codebase never touches the low-level crypto API directly.
// Each primitive cites the standard it implements so that an auditor can
// trace a line of code to a published specification:
//
//   - ECDH on NIST P-256 ............... NIST SP 800-56A Rev.~3, sec.~5.7.1.2
//   - ECDSA on NIST P-256 .............. FIPS PUB 186-4, sec.~6
//   - HKDF (HMAC-SHA256) ............... RFC 5869 (Krawczyk 2010, CRYPTO)
//   - AES-256-GCM ...................... NIST SP 800-38D
//   - Key generation ................... NIST SP 800-133 Rev.~2
//   - Zeroization ...................... NIST SP 800-88 Rev.~1, sec.~2.5
//
// All MAC/tag comparisons route through Node's `crypto.timingSafeEqual`,
// which iterates the full buffer regardless of mismatch position
// (see Node docs and OpenSSL CRYPTO_memcmp).

import {
  createECDH,
  createHash,
  createHmac,
  createPublicKey,
  createSign,
  createVerify,
  generateKeyPairSync,
  hkdfSync,
  timingSafeEqual as nodeTimingSafeEqual,
  createCipheriv,
  createDecipheriv,
  KeyObject,
  ECDH,
} from "node:crypto";

import { KDF_LABEL } from "../config.ts";
import { assertUnseeded, randomBytes as seededRandomBytes } from "./rng.ts";

export type JWK = { kty: string; crv?: string; x?: string; y?: string; d?: string };

/* ------------------------------------------------------------------ */
/* Zeroizable buffer (SP 800-88 Rev.~1, sec.~2.5)                      */
/* ------------------------------------------------------------------ */

/**
 * Long-term or session-critical secrets should live in a Zeroizable wrapper
 * so that dispose() can overwrite the backing bytes before they become
 * garbage-collectable. This does not offer constant-time guarantees against
 * a local attacker, but it defensively limits the memory-residency window.
 */
export class Zeroizable {
  #bytes: Buffer;
  #disposed = false;
  constructor(bytes: Buffer) {
    // Copy: the caller may have obtained `bytes` from a Node API that
    // reuses its own buffer.
    this.#bytes = Buffer.from(bytes);
  }
  view(): Buffer {
    if (this.#disposed) throw new Error("Zeroizable: use-after-dispose");
    return this.#bytes;
  }
  /** Overwrite the backing bytes with zeros and mark the wrapper dead. */
  dispose(): void {
    if (this.#disposed) return;
    this.#bytes.fill(0);
    this.#disposed = true;
  }
  get length(): number {
    return this.#bytes.length;
  }
}

/* ------------------------------------------------------------------ */
/* ECDH P-256 ephemeral keys  (SP 800-56A Rev.~3)                      */
/* ------------------------------------------------------------------ */

export interface EphemeralKey {
  /** raw uncompressed public key (65 bytes, starts 0x04) */
  pub: Buffer;
  /** Node ECDH object that can compute a shared secret */
  ecdh: ECDH;
}

export function ephemeralEcdh(): EphemeralKey {
  // ECDH ephemerals must come from an unseeded CSPRNG in production.
  // The assertion makes misuse loud; tests that want reproducibility
  // call clearSeed() around ephemeral generation.
  assertUnseeded("ephemeralEcdh");
  const ecdh = createECDH("prime256v1");
  const pub = ecdh.generateKeys();
  return { pub, ecdh };
}

/**
 * Validate an incoming P-256 public point before it is used in any scalar
 * multiplication (SP 800-56A Rev.~3, sec.~5.6.2.3.4). Rejects bad encodings,
 * the identity, and off-curve points; importing the point as a KeyObject
 * routes through OpenSSL's EC_POINT validation, which enforces the curve
 * equation. P-256 has cofactor one, so a valid on-curve, non-identity point
 * necessarily lies in the prime-order group (no small-subgroup check needed).
 * Throws on an invalid point so callers abort the handshake.
 */
export function assertValidP256Point(pub: Buffer): void {
  if (pub.length !== 65 || pub[0] !== 0x04) {
    throw new Error("invalid EC point: expected 65-byte uncompressed encoding");
  }
  const x = pub.subarray(1, 33);
  const y = pub.subarray(33, 65);
  // createPublicKey rejects points that are not on the curve (incl. identity).
  createPublicKey({
    key: { kty: "EC", crv: "P-256", x: x.toString("base64url"), y: y.toString("base64url") },
    format: "jwk",
  });
}

export function ecdhSharedSecret(self: EphemeralKey, peerPub: Buffer): Buffer {
  assertValidP256Point(peerPub);
  return self.ecdh.computeSecret(peerPub);
}

/* ------------------------------------------------------------------ */
/* ECDSA P-256 long-term signing keys  (FIPS 186-4)                    */
/* ------------------------------------------------------------------ */

export interface SigningKeyPair {
  privateKey: KeyObject;
  publicKey: KeyObject;
}

export function generateSigningKey(): SigningKeyPair {
  assertUnseeded("generateSigningKey");
  const { privateKey, publicKey } = generateKeyPairSync("ec", {
    namedCurve: "prime256v1",
  });
  return { privateKey, publicKey };
}

/** DER-encoded signature over SHA-256 of msg. */
export function signEcdsa(priv: KeyObject, msg: Buffer): Buffer {
  const s = createSign("SHA256");
  s.update(msg);
  s.end();
  return s.sign(priv);
}

export function verifyEcdsa(pub: KeyObject, msg: Buffer, sig: Buffer): boolean {
  const v = createVerify("SHA256");
  v.update(msg);
  v.end();
  try {
    return v.verify(pub, sig);
  } catch {
    return false;
  }
}

export function exportPublicJwk(pub: KeyObject): JWK {
  return pub.export({ format: "jwk" }) as JWK;
}

export function importPublicJwk(jwk: JWK): KeyObject {
  return createPublicKey({ key: jwk, format: "jwk" });
}

/* ------------------------------------------------------------------ */
/* Hash / HMAC / HKDF  (FIPS 180-4, RFC 2104, RFC 5869)                */
/* ------------------------------------------------------------------ */

export function sha256(buf: Buffer): Buffer {
  return createHash("sha256").update(buf).digest();
}

export function hmacSha256(key: Buffer, msg: Buffer): Buffer {
  return createHmac("sha256", key).update(msg).digest();
}

export function hkdf(
  ikm: Buffer,
  salt: Buffer,
  info: string,
  length = 32,
): Buffer {
  // Node's hkdfSync returns an ArrayBuffer — convert to Buffer.
  const ab = hkdfSync("sha256", ikm, salt, Buffer.from(info, "utf8"), length);
  return Buffer.from(ab);
}

/** Derive a labeled subkey from an already-uniform key. */
export function deriveSubkey(masterKey: Buffer, label: string, length = 32): Buffer {
  return hkdf(masterKey, Buffer.alloc(0), `${KDF_LABEL}/${label}`, length);
}

/* ------------------------------------------------------------------ */
/* AES-256-GCM  (NIST SP 800-38D)                                      */
/* ------------------------------------------------------------------ */

export interface GcmCiphertext {
  iv: Buffer; // 12 bytes — SP 800-38D Sec.~8.2
  ct: Buffer;
  tag: Buffer; // 16 bytes
}

export function aesGcmEncrypt(
  key: Buffer,
  plaintext: Buffer,
  aad: Buffer,
  iv: Buffer = randomBytes(12),
): GcmCiphertext {
  if (key.length !== 32) throw new Error("AES-256-GCM key must be 32 bytes");
  if (iv.length !== 12) throw new Error("GCM IV must be 12 bytes");
  const c = createCipheriv("aes-256-gcm", key, iv);
  if (aad.length > 0) c.setAAD(aad);
  const ct = Buffer.concat([c.update(plaintext), c.final()]);
  const tag = c.getAuthTag();
  return { iv, ct, tag };
}

export function aesGcmDecrypt(
  key: Buffer,
  frame: GcmCiphertext,
  aad: Buffer,
): Buffer {
  if (key.length !== 32) throw new Error("AES-256-GCM key must be 32 bytes");
  const d = createDecipheriv("aes-256-gcm", key, frame.iv);
  if (aad.length > 0) d.setAAD(aad);
  d.setAuthTag(frame.tag);
  return Buffer.concat([d.update(frame.ct), d.final()]);
}

/* ------------------------------------------------------------------ */
/* Utilities                                                           */
/* ------------------------------------------------------------------ */

/** Random bytes — routes through the seeded RNG when a seed is active. */
export function randomBytes(n: number): Buffer {
  return seededRandomBytes(n);
}

export function randBytes(n: number): Buffer {
  return randomBytes(n);
}

export function u64be(n: number | bigint): Buffer {
  const b = Buffer.alloc(8);
  b.writeBigUInt64BE(BigInt(n));
  return b;
}

export function seqToIv(seq: number | bigint): Buffer {
  // 12-byte IV = 4 zero bytes || 8-byte BE sequence (SP 800-38D Sec.~8.2.1).
  return Buffer.concat([Buffer.alloc(4), u64be(seq)]);
}

/**
 * Constant-time equality — routes through Node's `crypto.timingSafeEqual`.
 * Returns false for mismatched lengths without timing leakage because the
 * length check precedes any timing-sensitive compare.
 */
export function timingSafeEqual(a: Buffer, b: Buffer): boolean {
  if (a.length !== b.length) return false;
  return nodeTimingSafeEqual(a, b);
}
