// Captured drone without PUF seed.
//
// Attack: the attacker physically seizes a drone's non-volatile storage
// (black key + helper data) but does NOT have the PUF seed because the seed
// only lives as silicon variation. Can they unwrap the ECDH private key?
//
// Defense: without the original PUF seed, the fuzzy extractor cannot
// reconstruct the same KEK, so the AES-GCM authentication tag on the black
// key fails and the ECDH private key stays sealed.

import { aesGcmDecrypt } from "../crypto/primitives.ts";
import {
  generatePufSeed,
  pufRegenerate,
} from "../crypto/puf.ts";
import { enrollDrone, blackKeyAad } from "../services/drone.ts";
import type { AttackResult } from "./types.ts";

export async function attackCapturedDrone(): Promise<AttackResult> {
  // A genuine drone is enrolled.
  const realSeed = generatePufSeed("drone-alpha");
  const { blackKey, helper } = enrollDrone(realSeed, "drone-alpha");

  // Attacker tries to regenerate the KEK with a *different* PUF seed
  // (models a cloned FPGA or a different chip — the seed is intrinsic).
  const attackerSeed = generatePufSeed("drone-alpha");
  let unwrapped = false;
  try {
    // Two possible failure modes:
    //   - helper data tag check fails inside pufRegenerate,
    //   - or the KEK is simply wrong and AES-GCM tag fails.
    const kek = pufRegenerate(attackerSeed, helper);
    try {
      aesGcmDecrypt(kek, blackKey, blackKeyAad("drone-alpha"));
      unwrapped = true;
    } finally {
      kek.fill(0);
    }
  } catch {
    unwrapped = false;
  }

  return {
    name: "captured drone without PUF seed",
    defended: !unwrapped,
    detail: unwrapped
      ? "attacker extracted the ECDH private key — CATASTROPHIC"
      : "black key remained sealed — PUF root-of-trust held",
  };
}
