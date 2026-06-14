// Post-Compromise Security (PCS).
//
// Scenario: sk_U is leaked at time t_0. The cloud revokes the old user
// credential and re-enrolls the user (or rotates the cloud's signing key
// sk_C). After rotation, new sessions must again be secure against the
// attacker that still holds the old sk_U.
//
// Defense: every new handshake requires a fresh cloud-signed token. After
// revocation, the cloud will only issue tokens to the newly-enrolled
// credential, so the attacker with the old sk_U can no longer authorize a
// session. The drone still accepts tokens signed by the (unchanged)
// cloud, but the cloud refuses to issue any.

import { bootstrap, inProcessCloudClient } from "../scenarios/bootstrap.ts";
import { runUserHandshake } from "../services/user.ts";
import { generateSigningKey, exportPublicJwk } from "../crypto/primitives.ts";
import type { AttackResult } from "./types.ts";

export async function attackPostCompromise(): Promise<AttackResult> {
  const h = await bootstrap();

  // Attacker holds the "old" sk_U (modelled as the default userIdentity).
  // Simulate a rotation: re-register the same userId with a fresh key.
  const rotated = generateSigningKey();
  h.cloud.rotateUser({
    userId: h.userIdentity.userId,
    passwordHash: "",
    verifyKeyJwk: exportPublicJwk(rotated.publicKey),
  });
  // Under Option A the drone authenticates against a PINNED user key, so the
  // recovery flow must also re-provision the drone with the new key (the
  // in-depot re-enrollment step). This strictly strengthens PCS: even if the
  // attacker could somehow present the old key, the drone now pins the new one.
  h.reprovisionUserKey(h.userIdentity.userId, rotated.publicKey);

  // Attacker tries to authorize using the OLD signing key. Cloud must refuse.
  let attackerGotToken = true;
  try {
    const s = await runUserHandshake({
      identity: h.userIdentity, // the compromised key
      droneId: h.droneId,
      cloud: inProcessCloudClient(h.cloud),
      link: h.connectToDrone(),
    });
    s.close();
  } catch {
    attackerGotToken = false;
  }

  // Meanwhile, the legitimate user (with the new key) can still open a session.
  let legitOk = false;
  try {
    const s = await runUserHandshake({
      identity: {
        userId: h.userIdentity.userId,
        signingKey: rotated.privateKey,
        pinnedDrones: h.userIdentity.pinnedDrones,
      },
      droneId: h.droneId,
      cloud: inProcessCloudClient(h.cloud),
      link: h.connectToDrone(),
    });
    legitOk = true;
    s.close();
  } catch {
    /* unexpected */
  }
  await h.shutdown();

  const defended = !attackerGotToken && legitOk;
  return {
    name: "post-compromise (old sk_U leaked, user rotated)",
    defended,
    detail: attackerGotToken
      ? "attacker with old key still opened a session — PCS FAILED"
      : `old key refused, new key still works (legit handshake ok: ${legitOk})`,
  };
}
