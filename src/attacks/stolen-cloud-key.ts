// Compromised cloud signing key (not just the DB).
//
// Threat: the attacker exfiltrated sk_C itself and can mint arbitrary
// cloud-signed AuthTokens. Under the threat model this is explicitly allowed.
// The question is whether sk_C alone lets the attacker (a) command a drone, or
// (b) lure a legitimate user onto a drone of the attacker's choosing.
//
// Defense (Option A — keys PINNED at provisioning, independent of the cloud):
//   (a) The drone verifies sigma_U against the USER key it was provisioned
//       with, not against authToken.userVerifyKeyJwk. A forged token that
//       advertises the attacker's own pk_U is therefore rejected: the attacker
//       lacks the real sk_U and cannot produce a sigma_U the pinned key accepts.
//   (b) The user uses the drone's P_D PINNED at provisioning (verified offline
//       against the owner trust anchor), and rejects a token whose
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
  signEcdsa,
} from "../crypto/primitives.ts";
import { canonicalToken } from "../protocol/litezero.ts";
import type { AuthToken } from "../protocol/messages.ts";
import type { CloudClient } from "../services/user.ts";
import type { AttackResult } from "./types.ts";
import type { KeyObject } from "node:crypto";

/**
 * A rogue cloud that mints a token PER REQUEST using the attacker's stolen
 * sk_C, echoing the caller's freshly generated nonceU into the token exactly as
 * an honest cloud would. This is what makes the forged input STRUCTURALLY VALID
 * all the way to the advertised defense: the hello's top-level nonceU then
 * matches authToken.nonceU, so the drone's nonce-desync guard passes and the
 * request reaches the pinned-identity checks that are the actual subject of the
 * test (rather than aborting early on a nonce mismatch, which would let an
 * unrelated rejection masquerade as the defense).
 */
function rogueCloud(build: (nonceU: string) => AuthToken, stolenSk: KeyObject, stolenPk: KeyObject): CloudClient {
  return {
    async authorize(req) {
      const token = build(req.nonceU);
      return {
        token,
        cloudSig: signEcdsa(stolenSk, canonicalToken(token)).toString("base64"),
        cloudVerifyKeyJwk: exportPublicJwk(stolenPk),
        dronePubKey: token.dronePubKey,
      };
    },
  };
}

export async function attackStolenCloudKey(): Promise<AttackResult> {
  const h = await bootstrap();
  const stolen = h.cloud.cloudKey; // attacker exfiltrated sk_C
  const realDronePub = h.cloud.drones.get(h.droneId)!.pubKey;
  const realUserVk = h.cloud.users.get(h.userIdentity.userId)!.verifyKeyJwk;
  const ttl = () => ({ iat: Date.now(), exp: Date.now() + 30_000 });

  // ---- (a) user-key substitution: try to COMMAND the drone -----------------
  // Attacker mints a token advertising its OWN pk_U and signs the hello with
  // the matching sk_U'. A naive (Option B) drone that trusted the token's key
  // would accept. The pinned-user-key drone must reject. The token echoes the
  // request's nonceU, so the hello passes cloud-sig, expiry, droneId, nonce-
  // desync and single-use checks and fails SPECIFICALLY at the pinned-user-key
  // signature check — the defense this row advertises.
  const fakeUser = generateSigningKey();
  let errA: string | null = null;
  try {
    const s = await runUserHandshake({
      identity: {
        userId: h.userIdentity.userId,
        signingKey: fakeUser.privateKey, // attacker's key, matches tokA
        pinnedDrones: h.userIdentity.pinnedDrones, // so we reach the drone check
        // Attacker drives the user role and "trusts" the very key it stole,
        // so its rogue token passes the user-side sigma_C check by design;
        // the defense under test is the drone-side pinned-key check.
        cloudVerifyKey: stolen.publicKey,
      },
      droneId: h.droneId,
      cloud: rogueCloud(
        (nonceU) => ({
          userId: h.userIdentity.userId,
          droneId: h.droneId,
          nonceU, // echo the caller's fresh nonce → passes the desync guard
          ...ttl(),
          policy: { scope: ["control", "telemetry"] },
          userVerifyKeyJwk: exportPublicJwk(fakeUser.publicKey), // ROGUE substitution
          dronePubKey: realDronePub,
        }),
        stolen.privateKey,
        stolen.publicKey,
      ),
      link: h.connectToDrone(),
    });
    s.close();
  } catch (e) {
    errA = (e as Error).message;
  }
  // The advertised defense is the drone's pinned-user-key check. Assert the
  // handshake both fails (no session) AND fails for that specific reason, so an
  // earlier unrelated rejection cannot be scored as this defense.
  const defendedA = errA !== null && /invalid user signature on hello/.test(errA);

  // ---- (b) drone-key substitution: try to LURE the user to a fake drone ----
  // Attacker mints a token (for the real user) whose dronePubKey is a Q_D' it
  // controls. The legit user signs the hello with the real sk_U, but must
  // refuse because the token's P_D disagrees with the owner-pinned P_D.
  const rogueDronePub = ephemeralEcdh().pub.toString("base64"); // attacker Q_D'
  let errB: string | null = null;
  try {
    const s = await runUserHandshake({
      identity: h.userIdentity, // legit user, pins the real P_D
      droneId: h.droneId,
      cloud: rogueCloud(
        (nonceU) => ({
          userId: h.userIdentity.userId,
          droneId: h.droneId,
          nonceU, // echo the caller's fresh nonce → token is well-formed
          ...ttl(),
          policy: { scope: ["control", "telemetry"] },
          userVerifyKeyJwk: realUserVk,
          dronePubKey: rogueDronePub, // ROGUE substitution
        }),
        stolen.privateKey,
        stolen.publicKey,
      ),
      link: h.connectToDrone(),
    });
    s.close();
  } catch (e) {
    errB = (e as Error).message;
  }
  // The advertised defense is the user-side owner-pinned P_D check. Assert the
  // specific rejection reason so an earlier unrelated abort cannot pass as it.
  const defendedB = errB !== null && /pinned P_D|drone pubkey mismatch/.test(errB);

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
