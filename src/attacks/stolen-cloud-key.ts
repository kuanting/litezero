// Compromised cloud signing key (not just the DB).
//
// Threat: the attacker exfiltrated sk_C itself and can mint arbitrary
// cloud-signed AuthTokens. Under the threat model this is explicitly allowed.
// The question is whether sk_C alone lets the attacker (a) command a drone, or
// (b) lure a legitimate user onto a drone of the attacker's choosing.
//
// Defense (Option A — keys PINNED at provisioning, independent of the cloud):
//   (a) The drone verifies sigma_U against the OWNER key it was provisioned
//       with, not against authToken.userVerifyKeyJwk. A forged token that
//       advertises the attacker's own pk_U is therefore rejected: the attacker
//       lacks the real sk_U and cannot produce a sigma_U the pinned key accepts.
//   (b) The user uses the drone's P_D PINNED at provisioning (verified offline
//       against the operator trust anchor), and rejects a token whose
//       dronePubKey disagrees. A forged token that substitutes Q_D' is caught.
//
// A stolen sk_C is thus confined to the authorization layer (it changes who is
// *authorized*); it cannot command a drone or substitute a drone identity.
//
// NOTE: an earlier version of this test BUILT the rogue-substitution token and
// then discarded it with `void`, asserting only the weaker "honest rogue"
// (real pk_U, no sk_U) case. That masked the real gap. Both substitution
// directions are now exercised live and must be rejected.

import { bootstrap } from "../scenarios/bootstrap.ts";
import { runUserHandshake } from "../services/user.ts";
import {
  ephemeralEcdh,
  exportPublicJwk,
  generateSigningKey,
  randBytes,
  signEcdsa,
} from "../crypto/primitives.ts";
import { canonicalToken } from "../protocol/litezero.ts";
import type {
  AuthToken,
  SignedAuthToken,
} from "../protocol/messages.ts";
import type { CloudClient } from "../services/user.ts";
import type { AttackResult } from "./types.ts";

/** A cloud client that always returns a fixed attacker-minted token. */
function rogueCloud(signed: SignedAuthToken): CloudClient {
  return { async authorize() { return signed; } };
}

export async function attackStolenCloudKey(): Promise<AttackResult> {
  const h = await bootstrap();
  const stolen = h.cloud.cloudKey; // attacker exfiltrated sk_C
  const realDronePub = h.cloud.drones.get(h.droneId)!.pubKey;
  const realUserVk = h.cloud.users.get(h.userIdentity.userId)!.verifyKeyJwk;
  const ttl = () => ({ iat: Date.now(), exp: Date.now() + 30_000 });

  const sign = (token: AuthToken): SignedAuthToken => ({
    token,
    cloudSig: signEcdsa(stolen.privateKey, canonicalToken(token)).toString("base64"),
    cloudVerifyKeyJwk: exportPublicJwk(stolen.publicKey),
    dronePubKey: token.dronePubKey,
  });

  // ---- (a) user-key substitution: try to COMMAND the drone -----------------
  // Attacker mints a token advertising its OWN pk_U and signs the hello with
  // the matching sk_U'. A naive (Option B) drone that trusted the token's key
  // would accept. The pinned-owner-key drone must reject.
  const fakeUser = generateSigningKey();
  const tokA: AuthToken = {
    userId: h.userIdentity.userId,
    droneId: h.droneId,
    nonceU: randBytes(16).toString("base64"),
    ...ttl(),
    policy: { scope: ["control", "telemetry"] },
    userVerifyKeyJwk: exportPublicJwk(fakeUser.publicKey), // ROGUE substitution
    dronePubKey: realDronePub,
  };
  let errA: string | null = null;
  try {
    const s = await runUserHandshake({
      identity: {
        userId: h.userIdentity.userId,
        signingKey: fakeUser.privateKey, // attacker's key, matches tokA
        pinnedDrones: h.userIdentity.pinnedDrones, // so we reach the drone check
      },
      droneId: h.droneId,
      cloud: rogueCloud(sign(tokA)),
      link: h.connectToDrone(),
    });
    s.close();
  } catch (e) {
    errA = (e as Error).message;
  }
  const defendedA = errA !== null && /user signature|operator/i.test(errA);

  // ---- (b) drone-key substitution: try to LURE the user to a fake drone ----
  // Attacker mints a token (for the real user) whose dronePubKey is a Q_D' it
  // controls. The legit user signs the hello with the real sk_U, but must
  // refuse because the token's P_D disagrees with the operator-pinned P_D.
  const rogueDronePub = ephemeralEcdh().pub.toString("base64"); // attacker Q_D'
  const tokB: AuthToken = {
    userId: h.userIdentity.userId,
    droneId: h.droneId,
    nonceU: randBytes(16).toString("base64"),
    ...ttl(),
    policy: { scope: ["control", "telemetry"] },
    userVerifyKeyJwk: realUserVk,
    dronePubKey: rogueDronePub, // ROGUE substitution
  };
  let errB: string | null = null;
  try {
    const s = await runUserHandshake({
      identity: h.userIdentity, // legit user, pins the real P_D
      droneId: h.droneId,
      cloud: rogueCloud(sign(tokB)),
      link: h.connectToDrone(),
    });
    s.close();
  } catch (e) {
    errB = (e as Error).message;
  }
  const defendedB = errB !== null && /pubkey mismatch|pinned/i.test(errB);

  await h.shutdown();
  const defended = defendedA && defendedB;
  return {
    name: "stolen sk_C: forged token cannot command or substitute a drone",
    defended,
    detail: defended
      ? `drone rejected forged pk_U (${errA}); user rejected forged P_D (${errB})`
      : `Option A FAILED — pk_U-substitution: ${defendedA ? "ok" : `accepted (${errA})`}; ` +
        `P_D-substitution: ${defendedB ? "ok" : `accepted (${errB})`}`,
  };
}
