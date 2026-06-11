// Active MITM that swaps the user's ECDH pub for its own in the hello frame.
//
// Defense: the user's hello signature sigma_U covers E_U (it signs
// H("lz/hello/v1" || tok || E_U || n_U)), so swapping E_U makes the drone's
// sigma_U check fail and it aborts before any key derivation. (The transcript
// MAC would also catch the swap later, but the sigma_U check fires first.)

import { bootstrap, inProcessCloudClient } from "../scenarios/bootstrap.ts";
import { runUserHandshake } from "../services/user.ts";
import { rewriteOutbound } from "./_tap.ts";
import { ephemeralEcdh } from "../crypto/primitives.ts";
import type { AttackResult } from "./types.ts";

export async function attackMitm(): Promise<AttackResult> {
  const h = await bootstrap();
  const attacker = ephemeralEcdh();

  const tampered = rewriteOutbound(h.connectToDrone(), (raw) => {
    try {
      const m = JSON.parse(raw);
      if (m.kind === "hello") {
        m.userPub = attacker.pub.toString("base64");
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
    name: "active MITM swapping ECDH pub",
    defended: error !== null,
    detail: error
      ? `handshake aborted: ${error}`
      : "MITM succeeded — session established against attacker, not drone",
  };
}
