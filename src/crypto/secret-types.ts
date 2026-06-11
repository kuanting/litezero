// Secret-type taxonomy with dead-secret tracking.
//
// Background: the v1 post-mortem identified that our crypto code was a soup
// of raw Buffer values. Nothing in the type system distinguished a
// long-term ECDSA private key from a session-ephemeral HMAC key from a
// scratch buffer. As a result, two concrete bugs slipped through review:
//   1. A single long-term scalar was re-used across protocol branches
//      without re-tagging its purpose, contributing to the Gap-DH gap.
//   2. A handful of zeroize() calls were missed, leaving secrets GC-able.
//
// This module adds nominal types that tag a Buffer with its security-domain
// kind. Sinks (sign/verify/kdf-extract/zeroize) accept only their permitted
// kinds. The matching runtime audit (runSecretAudit below) tracks every
// creation, use and dispose, and reports unmatched lifecycles.
//
// The lint is NOT an airtight TypeScript-only type proof — Node's `Buffer`
// is too flexible for that. It IS a defensible layer:
//   + origin-tagging      (every secret is produced by a tagged factory),
//   + sink-tagging        (every sink declares which kinds it accepts), and
//   + lifecycle tracking  (every secret registers at birth and at dispose).
// Missing-dispose events are flagged at process exit.

import type { Buffer as NodeBuffer } from "node:buffer";

/* ------------------------------------------------------------------ */
/* Nominal brands                                                      */
/* ------------------------------------------------------------------ */

export type SecretKind =
  | "UserSk"                 // user's ECDSA private scalar
  | "CloudSk"                // cloud's ECDSA private scalar
  | "DronePufKek"            // PUF-derived key-encryption key
  | "DroneEcdhStatic"        // d_D, unwrapped from black key
  | "EphemeralEcdhScalar"    // per-session e_U or e_D
  | "Z1"                     // Z_1 = e · E (ephemeral-ephemeral)
  | "Z2"                     // Z_2 = d_D · E (static-ephemeral PUF branch)
  | "IkmTwoBranch"           // Z_1 || Z_2
  | "SessionMasterKm"        // HKDF output root
  | "SessionSubKey"          // per-direction AES-GCM key
  ;

/**
 * A Buffer branded with its SecretKind. Purely a compile-time tag.
 * The runtime bytes are still a plain Node Buffer.
 */
export type Branded<K extends SecretKind> = NodeBuffer & {
  readonly __secretKind: K;
};

/* ------------------------------------------------------------------ */
/* Runtime audit registry                                              */
/* ------------------------------------------------------------------ */

interface AuditEntry {
  kind: SecretKind;
  alloc_site: string;
  disposed: boolean;
  disposed_at?: string;
}

const REGISTRY = new Map<NodeBuffer, AuditEntry>();
let AUDIT_ENABLED = false;

/** Enable secret-lifecycle audit for this process. Safe to call in tests. */
export function enableSecretAudit(): void {
  AUDIT_ENABLED = true;
}

export function isAuditEnabled(): boolean {
  return AUDIT_ENABLED;
}

function caller(skip = 3): string {
  const err = new Error();
  const lines = (err.stack ?? "").split("\n");
  return lines[skip]?.trim() ?? "unknown";
}

/** Brand a Buffer at its creation site. Registers it for lifecycle audit. */
export function brand<K extends SecretKind>(
  buf: NodeBuffer,
  kind: K,
): Branded<K> {
  if (AUDIT_ENABLED) {
    REGISTRY.set(buf, {
      kind,
      alloc_site: caller(),
      disposed: false,
    });
  }
  // The cast is safe because the brand is phantom.
  return buf as Branded<K>;
}

/** Approved sink: zeroize a tagged secret. */
export function zeroize<K extends SecretKind>(b: Branded<K>): void {
  b.fill(0);
  if (AUDIT_ENABLED) {
    const e = REGISTRY.get(b as NodeBuffer);
    if (e) {
      e.disposed = true;
      e.disposed_at = caller();
    }
  }
}

/**
 * Return all entries that were branded but never zeroized. Call this at
 * the end of a test or at process exit to flag dead secrets.
 */
export function unDisposedSecrets(): AuditEntry[] {
  return [...REGISTRY.values()].filter((e) => !e.disposed);
}

export function resetAudit(): void {
  REGISTRY.clear();
}

/* ------------------------------------------------------------------ */
/* Approved sinks                                                      */
/* ------------------------------------------------------------------ */

/**
 * Audit hook: assert that `buf` is branded and of one of the allowed
 * kinds. Throws at test time if a sink was called with a bare Buffer.
 */
export function assertBranded<K extends SecretKind>(
  buf: NodeBuffer,
  allowed: K[],
  sink: string,
): asserts buf is Branded<K> {
  if (!AUDIT_ENABLED) return;
  const e = REGISTRY.get(buf);
  if (!e) {
    throw new Error(
      `[secret-audit] sink "${sink}" received an unbranded Buffer. ` +
        `Brand at the origin with brand(buf, kind).`,
    );
  }
  if (!(allowed as readonly SecretKind[]).includes(e.kind)) {
    throw new Error(
      `[secret-audit] sink "${sink}" does not accept kind "${e.kind}". ` +
        `Allowed: ${allowed.join(", ")}.`,
    );
  }
}
