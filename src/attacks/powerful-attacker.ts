// Maximal realistic attacker: everything short of sk_U and PUF-matching silicon.
//
// Threat model:
//   + observe_transit           (always)
//   + tamper_transit            (active MITM)
//   + leak_sk_C                 (rogue cloud mints tokens at will)
//   + leak_cloud_db             (knows every registered user/drone)
//   + replay_old_token          (holds a valid captured token too)
//
// This composite exists to subsume several EXPECTED_DEFENSES entries in
// capabilities.ts under one scenario. The protocol's sigma_U check is the
// single invariant that defeats every strategy below; failing even once
// would constitute a serious finding.

import { bootstrap, inProcessCloudClient } from "../scenarios/bootstrap.ts";
import { runUserHandshake } from "../services/user.ts";
import {
  ephemeralEcdh,
  exportPublicJwk,
  generateSigningKey,
  randBytes,
  sha256,
  signEcdsa,
} from "../crypto/primitives.ts";
import { canonicalToken, helloSigDigest } from "../protocol/litezero.ts";
import type {
  AuthToken,
  HandshakeHello,
  SignedAuthToken,
} from "../protocol/messages.ts";
import { rewriteOutbound } from "./_tap.ts";
import type { AttackResult } from "./types.ts";

export async function attackPowerfulAttacker(): Promise<AttackResult> {
  const h = await bootstrap();

  // Capability: leak_cloud_db — attacker reads every public record.
  const realUser = h.cloud.users.get(h.userIdentity.userId)!;
  const realDrone = h.cloud.drones.get(h.droneId)!;

  // Capability: leak_sk_C — attacker forges cloud signatures.
  const stolenCloudKey = h.cloud.cloudKey;

  // Capability: replay_old_token — attacker captures a legitimate hello.
  let captured: HandshakeHello | null = null;
  try {
    await runUserHandshake({
      identity: h.userIdentity,
      droneId: h.droneId,
      cloud: inProcessCloudClient(h.cloud),
      link: h.connectToDrone(),
      tamperHello: (hello) => {
        captured = { ...hello };
        throw new Error("intercept");
      },
    });
  } catch {
    /* ok */
  }
  if (!captured) {
    await h.shutdown();
    return {
      name: "powerful-attacker (sk_C + cloud-db + replay + tamper)",
      defended: false,
      detail: "harness failed to capture a reference hello",
    };
  }
  // Snapshot for TypeScript: the guard above proves the capture happened.
  const heardHello = captured as HandshakeHello;

  // Capability: tamper_transit — attacker rewrites outbound messages on
  // a NEW connection while also having everything above.
  //
  // Strategy A: replay captured token verbatim but rewrite E_U / n_U.
  const evilEph = ephemeralEcdh();
  const evilNonce = randBytes(16);
  const tamperedReplay: HandshakeHello = {
    ...heardHello,
    userPub: evilEph.pub.toString("base64"),
    nonceU: evilNonce.toString("base64"),
    // sigma_U unchanged — covers old E_U / n_U.
  };

  // Strategy B: mint a fresh rogue token with stolen sk_C binding the
  // real user's pk_U, then try to sign sigma_U with a RANDOM key.
  const rogueToken: AuthToken = {
    userId: h.userIdentity.userId,
    droneId: h.droneId,
    nonceU: evilNonce.toString("base64"),
    iat: Date.now(),
    exp: Date.now() + 30_000,
    policy: { scope: ["control", "telemetry"] },
    userVerifyKeyJwk: realUser.verifyKeyJwk,
    dronePubKey: realDrone.pubKey,
  };
  const rogueCloudSig = signEcdsa(
    stolenCloudKey.privateKey,
    canonicalToken(rogueToken),
  ).toString("base64");
  const rogueSigned: SignedAuthToken = {
    token: rogueToken,
    cloudSig: rogueCloudSig,
    cloudVerifyKeyJwk: exportPublicJwk(stolenCloudKey.publicKey),
    dronePubKey: realDrone.pubKey,
  };
  // Strategy B hello: attacker can't produce a correct sigma_U (no sk_U).
  const rogueEph = ephemeralEcdh();
  const rogueHello: HandshakeHello = {
    kind: "hello",
    authToken: rogueSigned.token,
    cloudSig: rogueSigned.cloudSig,
    userPub: rogueEph.pub.toString("base64"),
    nonceU: rogueToken.nonceU,
    userSig: randBytes(64).toString("base64"), // bogus sigma_U
  };

  // Strategy C: mint a rogue token with attacker's OWN pk_U (substitute
  // userVerifyKey), sign sigma_U with matching sk_U. The drone verifies
  // sigma_U successfully, so reaches key derivation. BUT: the session
  // opens against a user identity that is NOT alice. The drone's
  // policy layer (in a real deployment) would have a paired user record
  // that would reject this at the owner-policy step. We test whether
  // the drone accepts such a hello; if yes, mutual auth G2 technically
  // "breaks" but the owner-policy layer is supposed to catch it in
  // production. This scenario records that nuance.
  const fakeUser = generateSigningKey();
  const substitutedToken: AuthToken = {
    ...rogueToken,
    userVerifyKeyJwk: exportPublicJwk(fakeUser.publicKey),
  };
  const substitutedCloudSig = signEcdsa(
    stolenCloudKey.privateKey,
    canonicalToken(substitutedToken),
  ).toString("base64");
  const subEph = ephemeralEcdh();
  const subDigest = helloSigDigest(
    canonicalToken(substitutedToken),
    subEph.pub,
    Buffer.from(substitutedToken.nonceU, "base64"),
  );
  void sha256;
  const subSig = signEcdsa(fakeUser.privateKey, subDigest).toString("base64");
  const subHello: HandshakeHello = {
    kind: "hello",
    authToken: substitutedToken,
    cloudSig: substitutedCloudSig,
    userPub: subEph.pub.toString("base64"),
    nonceU: substitutedToken.nonceU,
    userSig: subSig,
  };

  // Exercise each strategy against a fresh connection (drone does not
  // keep per-session state across these attempts in our model).
  const trySend = async (hello: HandshakeHello): Promise<string | null> => {
    const raw = h.connectToDrone();
    // tamper_transit is "on" — but in this rewrite we don't need to
    // change anything; we're sending an already-maliciously-constructed
    // hello. Wrapping in rewriteOutbound merely demonstrates we have the
    // capability.
    const link = rewriteOutbound(raw, (m) => m);
    return new Promise<string | null>((resolve) => {
      link.onMessage((s) => {
        try {
          const m = JSON.parse(s);
          if (m.kind === "error") return resolve(String(m.reason));
          if (m.kind === "finish") return resolve(null); // attack won
          resolve(`unexpected ${m.kind}`);
        } catch {
          resolve("malformed");
        }
      });
      link.onClose(() => resolve("closed"));
      link.send(JSON.stringify(hello));
    });
  };

  const rA = await trySend(tamperedReplay);
  const rB = await trySend(rogueHello);
  const rC = await trySend(subHello);

  await h.shutdown();

  // Expectations:
  //  A defended iff drone rejects at sigma_U.
  //  B defended iff drone rejects at sigma_U (random sig).
  //  C defended iff drone rejects the substituted user key: under Option A
  //    the drone verifies sigma_U against the user verify key pinned at
  //    provisioning, NOT against the token's userVerifyKeyJwk, so a rogue
  //    token carrying pk_U'=attacker fails even though sigma_U verifies
  //    under pk_U'. A stolen sk_C is an authorization-only capability.
  const defA = rA !== null && /user signature/i.test(rA);
  const defB = rB !== null && /user signature/i.test(rB);
  const defC = rC !== null && /user signature/i.test(rC);

  const defended = defA && defB && defC;
  const detail =
    `A[tampered-replay]=${rA ?? "accepted"}; ` +
    `B[rogue-token-random-sig]=${rB ?? "accepted"}; ` +
    `C[substituted-pk_U, sigma_U valid]=${rC ?? "accepted"} ` +
    `(rejected by the provisioning-pinned user verify key)`;

  return {
    name: "powerful-attacker (sk_C + cloud-db + replay + tamper)",
    defended,
    detail,
  };
}
