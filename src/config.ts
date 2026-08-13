// Shared configuration for the LiteZero simulation.

export const CLOUD_PORT = 4000;
export const DRONE_PORT = 4100;

export const CLOUD_URL = `http://127.0.0.1:${CLOUD_PORT}`;
export const DRONE_URL = `ws://127.0.0.1:${DRONE_PORT}`;

// Authorization-token TTL, in milliseconds.
export const AUTH_TOKEN_TTL_MS = 30_000;

// Maximum out-of-order session frames we will accept (sliding window).
export const SESSION_REPLAY_WINDOW = 64;

// Hard cap on the number of AES-GCM operations performed under a single
// directional key within one epoch. The session-layer AEAD bound in the paper
// (§ "Session-layer AEAD bound") is stated for q_e, q_d <= 2^30 per direction
// per epoch; this constant enforces that premise operationally. It counts
// BOTH encryption calls (send) and decryption ATTEMPTS (including rejected
// ciphertexts), each against its own counter. When a counter reaches the cap
// the session tears down (or must rekey) rather than continue under a key that
// has exceeded its analyzed budget.
//
// Overridable via LZ_MAX_FRAMES_PER_EPOCH_KEY so the boundary tests can drive a
// tiny cap without sending 2^30 frames. Read through maxFramesPerEpochKey()
// (not cached) so an in-process test can set it before opening a session.
export const MAX_FRAMES_PER_EPOCH_KEY = 2 ** 30;

export function maxFramesPerEpochKey(): number {
  const v = Number(process.env.LZ_MAX_FRAMES_PER_EPOCH_KEY);
  return Number.isSafeInteger(v) && v > 0 ? v : MAX_FRAMES_PER_EPOCH_KEY;
}

// Sequence-number VALIDITY is deliberately decoupled from the per-epoch AEAD
// budget. A wire sequence number is valid iff it is a non-negative safe integer
// representable in the 64-bit IV format (seqToIv writes a BigUInt64BE); a safe
// integer is < 2^53 < 2^64, so this always fits. The per-epoch q_e/q_d budget is
// enforced SEPARATELY by the epoch counters (epochTxCount/epochRxAttempts),
// because txSeq is monotone ACROSS epochs while the budget resets on each rekey:
// tying validity to the budget would wrongly reject fresh-epoch frames once the
// cumulative counter passed the cap (the epoch's fresh key would be unusable).
export function isValidSeq(seq: unknown): seq is number {
  return typeof seq === "number" && Number.isSafeInteger(seq) && seq >= 0;
}

// Maximum number of half-open handshakes (hello accepted, ack not yet received)
// the drone will hold at once. When the bound is reached, the oldest half-open
// handshake is evicted (its pending key material zeroized and its transport
// closed) to admit the new one. This caps memory under a half-open flood while
// never starving a legitimate initiator, which will simply evict a stale
// attacker slot. A fielded drone would pair this with a per-source rate limit.
export const MAX_PENDING_HANDSHAKES = 32;

// Maximum number of live (unexpired) hello nonces the drone remembers for
// single-use enforcement. Entries expire with their token TTL, so the cache
// only approaches this bound if the cloud issues that many tokens for this
// drone within one TTL window. If the bound is ever hit the drone FAILS
// CLOSED and rejects new hellos rather than evicting a live nonce, since
// evicting would re-open a replay window for the evicted hello; the attacker
// cannot force this state without cloud-signed tokens, so the residual DoS is
// bounded by the cloud's own issuance rate.
export const MAX_SEEN_HELLO_NONCES =
  Number(process.env.LZ_MAX_SEEN_HELLO_NONCES) || 4096;

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
