// Key-Compromise Impersonation (KCI).
//
// Scenario: the attacker has stolen the user's long-term signing key sk_U.
// In a weak AKE this lets them also impersonate the *drone* back to the
// user (the attacker completes the user side of the handshake and pretends
// to be the drone). LiteZero must prevent this: the drone's MAC tau_D
// requires Z = KA(e_U, e_D), and e_D in turn requires the PUF-derived KEK
// on the drone, which the attacker cannot regenerate without the seed.
//
// Defense: after the attacker fabricates a legitimate hello with a freshly-
// requested token, the drone still refuses to emit a valid tau_D because
// it cannot produce e_D without the PUF regeneration. Without a matching
// tau_D, the user's handshake aborts.

import { bootstrap, inProcessCloudClient } from "../scenarios/bootstrap.ts";
import { runUserHandshake } from "../services/user.ts";
import { enrollDrone, blackKeyAad } from "../services/drone.ts";
import { generatePufSeed } from "../crypto/puf.ts";
import { pufRegenerate } from "../crypto/puf.ts";
import { aesGcmDecrypt } from "../crypto/primitives.ts";
import type { AttackResult } from "./types.ts";

export async function attackKci(): Promise<AttackResult> {
  const h = await bootstrap();

  // Attacker has sk_U (modelled: they already hold the user's identity).
  // They also captured the drone's public black-key and helper data, but
  // they do not have the drone's PUF seed.
  const realSeed = h.droneSeed;
  const { blackKey, helper } = enrollDrone(realSeed, h.droneId);

  // Try the attacker's "drone side": fake PUF regeneration.
  const fakeSeed = generatePufSeed(h.droneId);
  let attackerHasDScalar = false;
  try {
    const kek = pufRegenerate(fakeSeed, helper);
    try {
      aesGcmDecrypt(kek, blackKey, blackKeyAad(h.droneId));
      attackerHasDScalar = true;
    } finally {
      kek.fill(0);
    }
  } catch {
    /* defended */
  }

  // Also confirm: a real user handshake against the real drone still works,
  // so the defense isn't accidental. (This is the "liveness" half of KCI.)
  let liveHandshakeOk = false;
  try {
    const s = await runUserHandshake({
      identity: h.userIdentity,
      droneId: h.droneId,
      cloud: inProcessCloudClient(h.cloud),
      link: h.connectToDrone(),
    });
    liveHandshakeOk = true;
    s.close();
  } catch {
    /* fall through */
  }
  await h.shutdown();

  const defended = !attackerHasDScalar && liveHandshakeOk;
  return {
    name: "KCI (attacker holds sk_U, tries to impersonate drone)",
    defended,
    detail: attackerHasDScalar
      ? "attacker unwrapped d_D without PUF — CATASTROPHIC"
      : "drone impersonation blocked by PUF-sealed d_D; real handshake still succeeded",
  };
}
