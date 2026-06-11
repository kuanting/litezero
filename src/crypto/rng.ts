// Centralized, optionally-seeded randomness source.
//
// Production: delegates to Node's `crypto.randomBytes`, which is a
// cryptographically-secure PRNG (Fortuna/CTR_DRBG depending on the platform,
// see Node's source and OpenSSL RAND_bytes).
// Reproducibility: when `seed` is set via `setSeed`, a ChaCha20-CTR-style
// deterministic stream is used instead. This is suitable for attack-battery
// replay and the benchmark harness, NEVER for production key generation.
//
// Standards note: SP 800-133 Rev.~2 permits key-material generation from any
// approved DRBG. Node's `crypto.randomBytes` satisfies this when unseeded;
// the seeded mode is for artifact-reproducibility only and is explicitly
// disabled by `assertUnseeded()` calls in the hot path (see primitives.ts).

import { createCipheriv, randomBytes as nodeRandomBytes } from "node:crypto";

let seedState: { key: Buffer; nonce: Buffer; counter: bigint } | null = null;

/** Seed the RNG for deterministic replay. */
export function setSeed(seedHex: string): void {
  const seed = Buffer.from(seedHex.padEnd(64, "0"), "hex");
  if (seed.length < 32) throw new Error("seed must encode >= 16 bytes");
  seedState = {
    key: seed.subarray(0, 32),
    nonce: Buffer.alloc(12), // ChaCha20/AES-CTR 96-bit nonce
    counter: 0n,
  };
}

/** Clear the seed: future calls fall back to Node's CSPRNG. */
export function clearSeed(): void {
  seedState = null;
}

export function isSeeded(): boolean {
  return seedState !== null;
}

export function assertUnseeded(ctx: string): void {
  if (seedState !== null) {
    throw new Error(
      `[rng] ${ctx}: seeded RNG is only for reproducibility tests, ` +
        `never for live key material; clear the seed first`,
    );
  }
}

/** Primary entry point — returns n random bytes. */
export function randomBytes(n: number): Buffer {
  if (seedState === null) {
    return nodeRandomBytes(n);
  }
  // AES-256-CTR PRF keyed by the seed: indistinguishable from random
  // under the standard PRP assumption, and deterministic given the seed.
  const iv = Buffer.alloc(16);
  iv.writeBigUInt64BE(seedState.counter, 8);
  seedState.counter += 1n;
  const cipher = createCipheriv("aes-256-ctr", seedState.key, iv);
  return Buffer.concat([cipher.update(Buffer.alloc(n)), cipher.final()]);
}

/** Deterministic float in [0, 1) — used only by the PUF noise simulator. */
export function randomFloat(): number {
  const buf = randomBytes(8);
  // 53-bit mantissa, standard idiom from the Float64 IEEE specification.
  const hi = buf.readUInt32BE(0) & 0x001fffff;
  const lo = buf.readUInt32BE(4);
  return (hi * 0x100000000 + lo) / 0x20000000000000;
}
