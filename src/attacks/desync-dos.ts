// Desynchronisation / half-open DoS.
//
// Scenario: the attacker opens many handshakes, lets the drone emit `finish`
// for each, and then never sends `ack`. Each half-open handshake makes the
// drone hold pending transcript/MAC/key state. A naive implementation keeps one
// such record per open connection, so a flood of never-acked hellos grows the
// drone's memory without bound.
//
// Defense: the drone bounds the number of half-open handshakes it will hold at
// once (config.MAX_PENDING_HANDSHAKES). When the bound is reached, the oldest
// half-open slot is evicted — its pending key material is zeroized and its
// transport closed — to admit the new one. This caps pending state under a
// flood, and because eviction targets the OLDEST (stale attacker) slot, a
// legitimate initiator is never starved: it simply displaces a stale attempt.
//
// The test fires well-formed hellos (valid token + valid sigma_U + valid E_U)
// and never acks them, keeping the connections open, then checks two properties:
//   (1) the drone's half-open count stays at or below the bound despite far
//       more attempts, and
//   (2) a legitimate handshake still completes afterwards.

import { bootstrap, inProcessCloudClient } from "../scenarios/bootstrap.ts";
import { runUserHandshake } from "../services/user.ts";
import {
  ephemeralEcdh,
  randBytes,
  sha256,
  signEcdsa,
} from "../crypto/primitives.ts";
import { canonicalToken, helloSigDigest } from "../protocol/litezero.ts";
import { MAX_PENDING_HANDSHAKES } from "../config.ts";
import type { HandshakeHello } from "../protocol/messages.ts";
import type { Transport } from "../transport/types.ts";
import type { AttackResult } from "./types.ts";

const HALF_OPEN_ATTEMPTS = MAX_PENDING_HANDSHAKES * 2 + 10; // well over the bound

export async function attackDesyncDos(): Promise<AttackResult> {
  const h = await bootstrap();
  const openLinks: Transport[] = [];

  // Fire off N well-formed handshakes: valid hello, receive finish, never ack.
  for (let i = 0; i < HALF_OPEN_ATTEMPTS; i++) {
    const link = h.connectToDrone();
    const eph = ephemeralEcdh();
    const nonceU = randBytes(16);
    const nonceUb64 = nonceU.toString("base64");
    const ts = Date.now();
    const authMsg = sha256(
      Buffer.from(`${h.userIdentity.userId}|${h.droneId}|${nonceUb64}|${ts}`, "utf8"),
    );
    const authSig = signEcdsa(h.userIdentity.signingKey, authMsg).toString("base64");
    const signed = await h.cloud.authorize({
      userId: h.userIdentity.userId,
      droneId: h.droneId,
      nonceU: nonceUb64,
      ts,
      userSig: authSig,
    });
    const helloDigest = helloSigDigest(canonicalToken(signed.token), eph.pub, nonceU);
    const userSig = signEcdsa(h.userIdentity.signingKey, helloDigest).toString("base64");
    const hello: HandshakeHello = {
      kind: "hello",
      authToken: signed.token,
      cloudSig: signed.cloudSig,
      userPub: eph.pub.toString("base64"),
      nonceU: nonceUb64,
      userSig,
    };
    // Wait for `finish` so we know the drone reached the half-open state, then
    // deliberately never ack. Keep the connection open so the pending slot is
    // only released by the drone's own bound (eviction), not by a close.
    await new Promise<void>((resolve) => {
      link.onMessage(() => resolve());
      link.onClose(() => resolve()); // evicted by the drone — also fine
      link.send(JSON.stringify(hello));
    });
    openLinks.push(link);
  }

  // The drone must be holding no more than the configured bound, even though we
  // attempted far more half-open handshakes than that.
  const pending = h.droneStats.pendingHandshakes();
  const bounded = pending <= MAX_PENDING_HANDSHAKES;

  // A legitimate handshake must still complete despite the flood.
  let legitOk = false;
  try {
    const s = await runUserHandshake({
      identity: h.userIdentity,
      droneId: h.droneId,
      cloud: inProcessCloudClient(h.cloud),
      link: h.connectToDrone(),
    });
    legitOk = true;
    s.close();
  } catch {
    /* fail */
  }

  for (const l of openLinks) l.close();
  await h.shutdown();

  const defended = bounded && legitOk;
  return {
    name: "desync / half-open DoS",
    defended,
    detail: defended
      ? `pending half-open handshakes capped at ${pending} (<= ${MAX_PENDING_HANDSHAKES}) `
        + `after ${HALF_OPEN_ATTEMPTS} never-acked hellos; legitimate handshake still completed`
      : `DoS not contained (pending=${pending}, bound=${MAX_PENDING_HANDSHAKES}, legitOk=${legitOk})`,
  };
}
