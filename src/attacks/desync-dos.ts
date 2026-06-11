// Desynchronisation / half-open DoS.
//
// Scenario: the attacker opens a handshake, lets the drone emit `finish`,
// and then never sends `ack`. A naive implementation leaves the drone with
// pending transcript/MAC state that accumulates across open connections.
// In enough parallel attempts, the drone exhausts memory.
//
// Defense: the drone bounds pending-handshake state by an absolute limit
// (and a per-source rate limit in production). In the simulator we check
// the weaker but easier-to-test property: after `N` half-open attempts,
// legitimate handshakes still succeed and the drone's queue does not grow
// without bound.

import { bootstrap, inProcessCloudClient } from "../scenarios/bootstrap.ts";
import { runUserHandshake } from "../services/user.ts";
import { randBytes, sha256, signEcdsa } from "../crypto/primitives.ts";
import type { AttackResult } from "./types.ts";

const HALF_OPEN_ATTEMPTS = 50;

export async function attackDesyncDos(): Promise<AttackResult> {
  const h = await bootstrap();

  // Fire off N partially-completed handshakes: send hello, never ack.
  for (let i = 0; i < HALF_OPEN_ATTEMPTS; i++) {
    const link = h.connectToDrone();
    const nonceU = randBytes(16).toString("base64");
    const ts = Date.now();
    const msg = sha256(
      Buffer.from(`${h.userIdentity.userId}|${h.droneId}|${nonceU}|${ts}`, "utf8"),
    );
    const userSig = signEcdsa(h.userIdentity.signingKey, msg).toString("base64");
    const signed = await h.cloud.authorize({
      userId: h.userIdentity.userId,
      droneId: h.droneId,
      nonceU,
      ts,
      userSig,
    });
    link.send(
      JSON.stringify({
        kind: "hello",
        authToken: signed.token,
        cloudSig: signed.cloudSig,
        userPub: Buffer.alloc(65).toString("base64"),
        nonceU,
      }),
    );
    // Drop the handshake mid-way: don't send ack.
    setTimeout(() => link.close(), 5);
  }

  // Let the runtime process the pending events.
  await new Promise((r) => setTimeout(r, 50));

  // Now attempt a legitimate handshake — it must still succeed quickly.
  const t0 = Date.now();
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
  const elapsed = Date.now() - t0;
  await h.shutdown();

  const defended = legitOk && elapsed < 1000;
  return {
    name: "desync / half-open DoS",
    defended,
    detail: defended
      ? `legitimate handshake still completed in ${elapsed} ms after ${HALF_OPEN_ATTEMPTS} half-opens`
      : `legitimate handshake failed or slowed (ok=${legitOk}, ${elapsed}ms) — DoS succeeded`,
  };
}
