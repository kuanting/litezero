// Spoofed drone (fake device with no valid PUF-wrapped key).
//
// We simulate a rogue server that speaks the wire protocol but cannot produce
// a valid handshake finish — its ECDH contribution does not match anything
// the user could derive to the same transcript MAC.

import { bootstrap, inProcessCloudClient } from "../scenarios/bootstrap.ts";
import { runUserHandshake } from "../services/user.ts";
import { ephemeralEcdh, randBytes } from "../crypto/primitives.ts";
import { inProcessConnect, inProcessListen } from "../transport/inprocess.ts";
import type { AttackResult } from "./types.ts";

export async function attackSpoofDrone(): Promise<AttackResult> {
  const h = await bootstrap();

  // Rogue drone — speaks the protocol shape but lacks the PUF-wrapped key,
  // so it produces a random MAC in the finish.
  const rogue = inProcessListen();
  rogue.onConnection((link) => {
    link.onMessage(() => {
      const eph = ephemeralEcdh();
      link.send(
        JSON.stringify({
          kind: "finish",
          dronePub: eph.pub.toString("base64"),
          nonceD: randBytes(16).toString("base64"),
          macD: randBytes(32).toString("base64"),
        }),
      );
    });
  });

  let error: string | null = null;
  try {
    const s = await runUserHandshake({
      identity: h.userIdentity,
      droneId: h.droneId,
      cloud: inProcessCloudClient(h.cloud),
      link: inProcessConnect(rogue.endpoint()),
    });
    s.close();
  } catch (e) {
    error = (e as Error).message;
  }

  await rogue.close();
  await h.shutdown();

  return {
    name: "spoofed drone (wrong PUF identity)",
    defended: error !== null,
    detail: error
      ? `handshake aborted: ${error}`
      : "user accepted a fake drone — BAD",
  };
}
