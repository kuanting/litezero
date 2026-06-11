// Shared configuration for the LiteZero simulation.

export const CLOUD_PORT = 4000;
export const DRONE_PORT = 4100;

export const CLOUD_URL = `http://127.0.0.1:${CLOUD_PORT}`;
export const DRONE_URL = `ws://127.0.0.1:${DRONE_PORT}`;

// Authorization-token TTL, in milliseconds.
export const AUTH_TOKEN_TTL_MS = 30_000;

// Maximum out-of-order session frames we will accept (sliding window).
export const SESSION_REPLAY_WINDOW = 64;

// Domain separation label for our HKDF-based KDF.
export const KDF_LABEL = "litezero/v1";

// Simulated PUF parameters.
//
// Real RO-PUFs on FPGAs typically exhibit bit-error rates of ~2–8 % per read
// and combine this with a BCH-style ECC to drive the false-rejection rate
// down to ~1e-6 or better. We model the same *behaviour* with a majority
// vote over N noisy reads: at p=0.05 and N=15, P(bit wrong) ≈ 1.7e-7, so
// for a 256-bit response P(at least one wrong) ≈ 4.5e-5, well below what
// a test suite would notice.
export const PUF_RESPONSE_BITS = 256; // size of the raw PUF response.
export const PUF_NOISE_PROB = 0.05; // probability each bit flips per read.
export const PUF_MAJORITY_READS = 15; // reads combined by majority vote.
