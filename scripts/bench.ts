// Microbenchmarks for each LiteZero primitive + the full handshake.
//
// Runs `TRIALS` iterations of each operation, records mean, stdev, p95, p99,
// and writes the result in both JSON and CSV. Meant to be run under both
// Node and Bun (`node --import tsx scripts/bench.ts` / `bun scripts/bench.ts`)
// to produce the two columns of Table III in the paper.
//
// Reproducibility: the benchmark runs under an optional seed (env BENCH_SEED).
// The seeded PRNG is used only for bench inputs, never for real key material
// (primitives.ts's assertUnseeded() protects ephemeral ECDH from seeded
// randomness).

import {
  aesGcmDecrypt,
  aesGcmEncrypt,
  ecdhSharedSecret,
  ephemeralEcdh,
  generateSigningKey,
  hkdf,
  signEcdsa,
  verifyEcdsa,
  randBytes,
} from "../src/crypto/primitives.ts";
import { bootstrap, inProcessCloudClient } from "../src/scenarios/bootstrap.ts";
import { runUserHandshake } from "../src/services/user.ts";
import { writeFileSync, mkdirSync } from "node:fs";

const TRIALS = Number(process.env.BENCH_TRIALS ?? 10000);

interface Stat {
  op: string;
  unit: "us" | "ms";
  mean: number;
  stdev: number;
  p95: number;
  p99: number;
  n: number;
}

function stats(op: string, samples: number[], unit: "us" | "ms"): Stat {
  const sorted = [...samples].sort((a, b) => a - b);
  const n = sorted.length;
  const mean = sorted.reduce((s, x) => s + x, 0) / n;
  const variance = sorted.reduce((s, x) => s + (x - mean) ** 2, 0) / n;
  const stdev = Math.sqrt(variance);
  const p95 = sorted[Math.min(n - 1, Math.floor(n * 0.95))];
  const p99 = sorted[Math.min(n - 1, Math.floor(n * 0.99))];
  return { op, unit, mean, stdev, p95, p99, n };
}

function timeUs(body: () => void): number {
  const t0 = process.hrtime.bigint();
  body();
  const t1 = process.hrtime.bigint();
  return Number(t1 - t0) / 1000;
}

async function benchSign(): Promise<Stat> {
  const { privateKey } = generateSigningKey();
  const msg = randBytes(32);
  const samples: number[] = [];
  for (let i = 0; i < TRIALS; i++) samples.push(timeUs(() => signEcdsa(privateKey, msg)));
  return stats("ecdsa_sign", samples, "us");
}

async function benchVerify(): Promise<Stat> {
  const { privateKey, publicKey } = generateSigningKey();
  const msg = randBytes(32);
  const sig = signEcdsa(privateKey, msg);
  const samples: number[] = [];
  for (let i = 0; i < TRIALS; i++) samples.push(timeUs(() => verifyEcdsa(publicKey, msg, sig)));
  return stats("ecdsa_verify", samples, "us");
}

async function benchEcdhKa(): Promise<Stat> {
  const a = ephemeralEcdh();
  const b = ephemeralEcdh();
  const samples: number[] = [];
  for (let i = 0; i < TRIALS; i++) samples.push(timeUs(() => ecdhSharedSecret(a, b.pub)));
  return stats("ecdh_ka", samples, "us");
}

async function benchHkdf(): Promise<Stat> {
  const ikm = randBytes(32);
  const salt = randBytes(32);
  const samples: number[] = [];
  for (let i = 0; i < TRIALS; i++) samples.push(timeUs(() => hkdf(ikm, salt, "bench", 64)));
  return stats("hkdf_64B", samples, "us");
}

async function benchGcmSeal(): Promise<Stat> {
  const key = randBytes(32);
  const pt = randBytes(64);
  const aad = randBytes(32);
  const samples: number[] = [];
  for (let i = 0; i < TRIALS; i++) samples.push(timeUs(() => aesGcmEncrypt(key, pt, aad)));
  return stats("aes_gcm_seal_64B", samples, "us");
}

async function benchGcmOpen(): Promise<Stat> {
  const key = randBytes(32);
  const pt = randBytes(64);
  const aad = randBytes(32);
  const ct = aesGcmEncrypt(key, pt, aad);
  const samples: number[] = [];
  for (let i = 0; i < TRIALS; i++) samples.push(timeUs(() => aesGcmDecrypt(key, ct, aad)));
  return stats("aes_gcm_open_64B", samples, "us");
}

async function benchFullHandshake(): Promise<Stat> {
  const h = await bootstrap();
  const samples: number[] = [];
  // Fewer trials for the full-handshake (heavier).
  const FH_TRIALS = Math.min(TRIALS, 1000);
  for (let i = 0; i < FH_TRIALS; i++) {
    const t0 = process.hrtime.bigint();
    const s = await runUserHandshake({
      identity: h.userIdentity,
      droneId: h.droneId,
      cloud: inProcessCloudClient(h.cloud),
      link: h.connectToDrone(),
    });
    const t1 = process.hrtime.bigint();
    samples.push(Number(t1 - t0) / 1_000_000); // ms
    s.close();
  }
  await h.shutdown();
  return stats("handshake_full", samples, "ms");
}

async function main(): Promise<void> {
  const runtime = typeof (globalThis as { Bun?: unknown }).Bun !== "undefined" ? "bun" : "node";
  const results: Stat[] = [];

  console.log(`[bench] runtime=${runtime}, trials=${TRIALS}`);
  results.push(await benchSign());
  results.push(await benchVerify());
  results.push(await benchEcdhKa());
  results.push(await benchHkdf());
  results.push(await benchGcmSeal());
  results.push(await benchGcmOpen());
  results.push(await benchFullHandshake());

  for (const r of results) {
    const u = r.unit;
    console.log(
      `  ${r.op.padEnd(22)} mean=${r.mean.toFixed(2)}${u}  ` +
        `sd=${r.stdev.toFixed(2)}${u}  p95=${r.p95.toFixed(2)}${u}  p99=${r.p99.toFixed(2)}${u}  n=${r.n}`,
    );
  }

  mkdirSync("out", { recursive: true });
  writeFileSync(
    `out/bench-${runtime}.json`,
    JSON.stringify({ runtime, trials: TRIALS, results }, null, 2),
  );
  const csv =
    "runtime,op,unit,mean,stdev,p95,p99,n\n" +
    results
      .map((r) => `${runtime},${r.op},${r.unit},${r.mean},${r.stdev},${r.p95},${r.p99},${r.n}`)
      .join("\n") +
    "\n";
  writeFileSync(`out/bench-${runtime}.csv`, csv);
  console.log(`[bench] wrote out/bench-${runtime}.json and .csv`);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
