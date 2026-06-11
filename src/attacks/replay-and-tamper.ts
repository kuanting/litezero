// Replay-a-captured-token WHILE also actively tampering the transit stream.
//
// This scenario plugs a coverage hole surfaced by the capability matrix:
// `replay_old_token + tamper_transit => G4_replay_resistance`. The stock
// replay-token scenario only has observe_transit capability; this one
// gives the attacker the additional active-rewrite capability to confirm
// that the two combined are still defended.
//
// Strategy:
//   1. Snapshot a valid (tok, sigma_C) on the wire as it goes user -> drone.
//   2. Inside the SAME simulated network (same drone process), open a
//      fresh socket and replay the captured hello verbatim, but also
//      rewrite outbound fields with attacker-chosen E_U and n_U.
//
// Defense: the drone's sigma_U check binds E_U || n_U to sk_U; splicing
// in a new E_U invalidates sigma_U. Exactly the same defense that stops
// the token-bearer attack, but under the stronger capability set.

import { bootstrap, inProcessCloudClient } from "../scenarios/bootstrap.ts";
import { runUserHandshake } from "../services/user.ts";
import { ephemeralEcdh, randBytes } from "../crypto/primitives.ts";
import type { HandshakeHello } from "../protocol/messages.ts";
import type { AttackResult } from "./types.ts";

export async function attackReplayAndTamper(): Promise<AttackResult> {
  const h = await bootstrap();

  // Step 1: capture a legitimate hello.
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
    /* intercept branch */
  }
  if (!captured) {
    await h.shutdown();
    return {
      name: "replay-old-token + tamper-transit (capability matrix gap)",
      defended: false,
      detail: "harness failed to capture hello",
    };
  }
  // Snapshot for TypeScript: the guard above proves the capture happened.
  const heardHello = captured as HandshakeHello;

  // Step 2: attacker replays the captured (tok, sigma_C) PLUS actively
  // rewrites the outbound hello with its own E_U || n_U.
  const evilEph = ephemeralEcdh();
  const evilNonce = randBytes(16);
  const tamperedHello: HandshakeHello = {
    ...heardHello,
    userPub: evilEph.pub.toString("base64"),
    nonceU: evilNonce.toString("base64"),
    // userSig is UNCHANGED — still covers the captured E_U, not the new one
  };

  const link = h.connectToDrone();
  const result: string | null = await new Promise((resolve) => {
    link.onMessage((s) => {
      try {
        const m = JSON.parse(s);
        if (m.kind === "error") resolve(String(m.reason));
        else resolve(null); // finish arrived => attack succeeded
      } catch {
        resolve(null);
      }
    });
    link.onClose(() => resolve("closed"));
    link.send(JSON.stringify(tamperedHello));
  });

  await h.shutdown();
  const defended = result !== null && /user signature/i.test(result);
  return {
    name: "replay-old-token + tamper-transit (capability matrix gap)",
    defended,
    detail: defended
      ? `drone rejected tampered replay: ${result}`
      : `drone accepted tampered replay (response: ${result})`,
  };
}
