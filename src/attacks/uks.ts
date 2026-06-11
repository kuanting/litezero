// Unknown Key-Share (UKS) attack.
//
// Scenario: two honest sessions complete but each party believes they share
// a key with a different peer than the one they actually hold a key with.
// A common way to mount this is to splice identity fields so that the
// drone thinks it talked to user A while the user is user B.
//
// Defense: both userId and droneId are carried inside `tok`, which is
// signed by the cloud (so they can't be silently rewritten) AND included
// in the transcript hash (so a rewrite changes tau_D / tau_U). This attack
// therefore cannot split identities without aborting the handshake.

import { bootstrap, inProcessCloudClient } from "../scenarios/bootstrap.ts";
import { runUserHandshake } from "../services/user.ts";
import { rewriteOutbound } from "./_tap.ts";
import type { AttackResult } from "./types.ts";

export async function attackUks(): Promise<AttackResult> {
  const h = await bootstrap({ userId: "alice" });

  // Attacker rewrites userId inside the hello's authToken to "mallory".
  // The cloud signature no longer covers the modified bytes, so the drone
  // aborts on token verification.
  const tampered = rewriteOutbound(h.connectToDrone(), (raw) => {
    try {
      const m = JSON.parse(raw);
      if (m.kind === "hello") {
        m.authToken.userId = "mallory";
        return JSON.stringify(m);
      }
    } catch {
      /* pass through */
    }
    return raw;
  });

  let error: string | null = null;
  try {
    const s = await runUserHandshake({
      identity: h.userIdentity,
      droneId: h.droneId,
      cloud: inProcessCloudClient(h.cloud),
      link: tampered,
    });
    s.close();
  } catch (e) {
    error = (e as Error).message;
  }
  await h.shutdown();

  return {
    name: "UKS (splice userId across sessions)",
    defended: error !== null,
    detail: error
      ? `handshake aborted: ${error}`
      : "UKS succeeded — drone established session under wrong userId",
  };
}
