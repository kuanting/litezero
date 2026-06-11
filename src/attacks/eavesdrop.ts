// Passive network eavesdropper.
//
// Attack: capture every byte exchanged between the user and the drone and
// try to extract the plaintext command without any key material.
//
// Defense: AES-256-GCM session keys are derived from an ephemeral ECDH value
// that the eavesdropper never observes.

import { bootstrap, inProcessCloudClient } from "../scenarios/bootstrap.ts";
import { runUserHandshake } from "../services/user.ts";
import { tapTransport } from "./_tap.ts";
import type { AttackResult } from "./types.ts";

export async function attackEavesdrop(): Promise<AttackResult> {
  const h = await bootstrap();

  const captured: string[] = [];
  const tapped = tapTransport(h.connectToDrone(), (msg) => captured.push(msg));

  const session = await runUserHandshake({
    identity: h.userIdentity,
    droneId: h.droneId,
    cloud: inProcessCloudClient(h.cloud),
    link: tapped,
  });

  const secret = Buffer.from("WAYPOINT 25.034,121.565 altitude=80m");
  await new Promise<void>((resolve) => {
    session.onFrame(() => resolve());
    void session.send(secret);
  });
  session.close();
  await h.shutdown();

  const leaked = captured.some(
    (c) => c.includes("WAYPOINT") || c.includes("ACK:"),
  );
  return {
    name: "passive eavesdropping",
    defended: !leaked,
    detail: leaked
      ? "plaintext command found in captured traffic — CATASTROPHIC"
      : `captured ${captured.length} frames, none contained the plaintext`,
  };
}
