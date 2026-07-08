// Pure helpers shared between the user and drone implementations.
//
// Keeping the protocol logic free of I/O makes it easy to unit-test and reuse
// from the attack scenarios.

import {
  hkdf,
  hmacSha256,
  sha256,
  deriveSubkey,
  timingSafeEqual as ctEqual,
} from "../crypto/primitives.ts";
import { KDF_LABEL } from "../config.ts";
import type { AuthToken } from "./messages.ts";

// Re-export so callers keep importing `timingSafeEqual` from here.
export const timingSafeEqual = ctEqual;

/** Canonical JSON encoding of an AuthToken (stable field order). */
export function canonicalToken(t: AuthToken): Buffer {
  const obj = {
    droneId: t.droneId,
    dronePubKey: t.dronePubKey,
    exp: t.exp,
    iat: t.iat,
    nonceU: t.nonceU,
    policy: t.policy,
    userId: t.userId,
    userVerifyKeyJwk: t.userVerifyKeyJwk,
  };
  return Buffer.from(JSON.stringify(obj), "utf8");
}

/**
 * Domain-separated digest the user signs to prove possession of sk_U directly
 * to the drone (not the cloud). Binds the token, the user's ephemeral public
 * key, and the nonce so a signature captured off one session cannot be
 * spliced onto another.
 */
export function helloSigDigest(
  tokenBytes: Buffer,
  userPub: Buffer,
  nonceU: Buffer,
): Buffer {
  return sha256(
    Buffer.concat([
      Buffer.from("lz/hello/v1", "utf8"),
      tokenBytes,
      userPub,
      nonceU,
    ]),
  );
}

/**
 * Digest the owner signs (offline) to certify a drone's long-term identity
 * (droneId, P_D). The user pins P_D by verifying this certificate against the
 * owner's trust-anchor key at provisioning, so a forged cloud token cannot
 * substitute a different P_D — closing the drone-substitution path under a
 * stolen sk_C. Domain-separated from helloSigDigest.
 */
export function droneIdentityDigest(droneId: string, dronePub: Buffer): Buffer {
  return sha256(
    Buffer.concat([
      Buffer.from("lz/drone-id/v1", "utf8"),
      Buffer.from(droneId, "utf8"),
      dronePub,
    ]),
  );
}

export interface TranscriptInput {
  tokenBytes: Buffer;
  cloudSig: Buffer;
  userPub: Buffer;
  nonceU: Buffer;
  userSig: Buffer;
  dronePub: Buffer;
  nonceD: Buffer;
}

/** Hash the full handshake transcript (includes user's PoP signature). */
export function transcriptHash(t: TranscriptInput): Buffer {
  return sha256(
    Buffer.concat([
      t.tokenBytes,
      t.cloudSig,
      t.userPub,
      t.nonceU,
      t.userSig,
      t.dronePub,
      t.nonceD,
    ]),
  );
}

/**
 * From the ECDH secret + nonces, derive the directional session keys and the
 * key-confirmation MAC key. The 64-byte HKDF master is split into a session
 * root (ks) and a MAC key (km); ks seeds the two directional subkeys and is
 * then discarded. The master (root ks included) is zeroized before returning,
 * and only an independent copy of km escapes — so the caller only has to wipe
 * km (and the returned subkeys) when the session ends.
 */
export function deriveSessionKeys(
  ecdhSecret: Buffer,
  nonceU: Buffer,
  nonceD: Buffer,
): { km: Buffer; kU2D: Buffer; kD2U: Buffer } {
  const salt = Buffer.concat([nonceU, nonceD]);
  const master = hkdf(ecdhSecret, salt, `${KDF_LABEL}/master`, 64);
  const ks = master.subarray(0, 32);
  // deriveSubkey runs HKDF again, so the subkeys are independent buffers and
  // ks itself never needs to leave this function.
  const kU2D = deriveSubkey(ks, "u2d");
  const kD2U = deriveSubkey(ks, "d2u");
  // Copy km out before wiping the master; the copy is the only session secret
  // that outlives this call besides the directional subkeys.
  const km = Buffer.from(master.subarray(32, 64));
  master.fill(0); // zeroizes both ks and the original km bytes
  salt.fill(0);
  return { km, kU2D, kD2U };
}

export function macWithLabel(km: Buffer, transcript: Buffer, label: string): Buffer {
  return hmacSha256(km, Buffer.concat([transcript, Buffer.from(label, "utf8")]));
}

/**
 * AAD for a session frame. Binds the drone identity, direction, key epoch,
 * sub-channel, and sequence number, so a frame cannot be replayed across
 * directions, epochs, or channels. Single source of truth for both sides.
 */
export function frameAad(
  droneId: string,
  dir: string,
  epoch: number,
  chan: string,
  seq: number,
): Buffer {
  return Buffer.from(`${droneId}|${dir}|${epoch}|${chan}|${seq}`, "utf8");
}

/**
 * Derive the directional keys for a new key epoch from a fresh
 * ephemeral-ephemeral ECDH secret. The rekey rides inside the already
 * authenticated session channel, so no MAC-confirm key is needed here; the
 * handshake transcript is folded in as the HKDF salt to bind the new epoch to
 * the session it ratchets from, and the epoch number domain-separates labels.
 */
export function deriveRekeyKeys(
  ecdhSecret: Buffer,
  baseTranscript: Buffer,
  epoch: number,
): { kU2D: Buffer; kD2U: Buffer } {
  const ks = hkdf(ecdhSecret, baseTranscript, `${KDF_LABEL}/rekey/${epoch}`, 32);
  const out = {
    kU2D: deriveSubkey(ks, `rekey/${epoch}/u2d`),
    kD2U: deriveSubkey(ks, `rekey/${epoch}/d2u`),
  };
  ks.fill(0);
  return out;
}

/** Digest the cloud signs to attest a policy update for a drone (push). */
export function policyDigest(droneId: string, scope: string[], ts: number): Buffer {
  return sha256(
    Buffer.concat([
      Buffer.from("lz/policy/v1", "utf8"),
      Buffer.from(droneId, "utf8"),
      Buffer.from(scope.join(","), "utf8"),
      Buffer.from(String(ts), "utf8"),
    ]),
  );
}

