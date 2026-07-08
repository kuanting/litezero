// Shared configuration for the LiteZero simulation.

export const CLOUD_PORT = 4000;
export const DRONE_PORT = 4100;

export const CLOUD_URL = `http://127.0.0.1:${CLOUD_PORT}`;
export const DRONE_URL = `ws://127.0.0.1:${DRONE_PORT}`;

// Authorization-token TTL, in milliseconds.
export const AUTH_TOKEN_TTL_MS = 30_000;

// Maximum out-of-order session frames we will accept (sliding window).
export const SESSION_REPLAY_WINDOW = 64;

// Maximum number of half-open handshakes (hello accepted, ack not yet received)
// the drone will hold at once. When the bound is reached, the oldest half-open
// handshake is evicted (its pending key material zeroized and its transport
// closed) to admit the new one. This caps memory under a half-open flood while
// never starving a legitimate initiator, which will simply evict a stale
// attacker slot. A fielded drone would pair this with a per-source rate limit.
export const MAX_PENDING_HANDSHAKES = 32;

// Domain separation label for our HKDF-based KDF.
export const KDF_LABEL = "litezero/v1";

// Simulated PUF parameters.
//
// Real RO-PUFs on FPGAs exhibit bit-error rates of ~2–8 % per read and combine
// majority voting with a BCH-style ECC to drive the false-rejection rate down
// to ~1e-6 or better. This reference simulator has no real silicon, so it
// assumes an *idealized reliable* PUF: read-noise is disabled (PUF_NOISE_PROB =
// 0), so a correct device always regenerates its KEK, while a wrong die still
// fails deterministically (its intrinsic secret differs, so the fuzzy-extractor
// tag never matches — this is what backs the captured-drone defense).
//
// The majority-vote + code-offset machinery in crypto/puf.ts is retained so a
// nonzero PUF_NOISE_PROB can be set to study reliability; characterizing the
// real RO-PUF error rate on silicon and tuning the ECC budget is future work.
export const PUF_RESPONSE_BITS = 256; // size of the raw PUF response.
export const PUF_NOISE_PROB = 0; // idealized reliable PUF (no read-noise); see above.
export const PUF_MAJORITY_READS = 15; // reads combined by majority vote.
