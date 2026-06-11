// Stolen cloud database.
//
// After a legitimate session, the attacker exfiltrates the entire cloud DB
// plus the cloud private key. Can they reconstruct past session keys?
//
// No — session keys come from a user↔drone ECDH that never touches the cloud.

import { bootstrap, inProcessCloudClient } from "../scenarios/bootstrap.ts";
import { runUserHandshake } from "../services/user.ts";
import type { AttackResult } from "./types.ts";

export async function attackStolenCloudDb(): Promise<AttackResult> {
  const h = await bootstrap();

  const session = await runUserHandshake({
    identity: h.userIdentity,
    droneId: h.droneId,
    cloud: inProcessCloudClient(h.cloud),
    link: h.connectToDrone(),
  });
  await new Promise<void>((resolve) => {
    session.onFrame(() => resolve());
    void session.send(Buffer.from("STATUS"));
  });
  session.close();

  const stolen = JSON.stringify({
    users: Array.from(h.cloud.users.values()),
    drones: Array.from(h.cloud.drones.values()),
    cloudKeyType: h.cloud.cloudKey.privateKey.type,
  });

  // A JWK private scalar is encoded as "d":"...". If the stolen payload
  // contains such a field in the user or drone records, zero-trust is
  // broken.
  const containsPrivateD = /("d"\s*:\s*"[^"]+")/.test(stolen.split("cloudKeyType")[0]);

  await h.shutdown();
  return {
    name: "stolen cloud database",
    defended: !containsPrivateD,
    detail: containsPrivateD
      ? "cloud DB contained private scalars — zero-trust property broken"
      : "cloud DB contains only public records; past session keys unrecoverable",
  };
}
