// WebSocket-backed demo.
//
// Spins up the cloud (HTTP :4000), the drone (WebSocket), and a user that
// connects over the network. All inside one process for illustration —
// split the three into separate Node processes in production.

import { CloudService, startCloudServer } from "../src/services/cloud.ts";
import { attachDrone, enrollDrone } from "../src/services/drone.ts";
import {
  httpCloudClient,
  runUserHandshake,
  type UserIdentity,
} from "../src/services/user.ts";
import {
  exportPublicJwk,
  generateSigningKey,
  sha256,
} from "../src/crypto/primitives.ts";
import { generatePufSeed } from "../src/crypto/puf.ts";
import { wsConnect, wsListen } from "../src/transport/websocket.ts";
import { CLOUD_PORT, DRONE_PORT } from "../src/config.ts";
import type { Transport } from "../src/transport/types.ts";

async function main() {
  // Cloud
  const cloud = new CloudService();
  const cloudHttp = startCloudServer(cloud, CLOUD_PORT);
  console.log(`[cloud] listening on :${CLOUD_PORT}`);

  // User
  const userKey = generateSigningKey();
  cloud.registerUser({
    userId: "alice",
    passwordHash: sha256(Buffer.from("hunter2", "utf8")).toString("base64"),
    verifyKeyJwk: exportPublicJwk(userKey.publicKey),
  });
  // Drone
  const seed = generatePufSeed("drone-alpha");
  const { droneEcdhPub, blackKey, helper } = enrollDrone(seed, "drone-alpha");
  cloud.registerDrone({
    droneId: "drone-alpha",
    pubKey: droneEcdhPub.toString("base64"),
    policy: { allowedUsers: ["alice"] },
  });

  // Option A provisioning: user pins the drone's P_D; drone pins the owner key.
  const identity: UserIdentity = {
    userId: "alice",
    signingKey: userKey.privateKey,
    pinnedDrones: new Map([["drone-alpha", droneEcdhPub]]),
  };

  const droneServer = await wsListen(DRONE_PORT);
  attachDrone(
    droneServer,
    {
      droneId: "drone-alpha",
      pufSeed: seed,
      cloudVerifyKey: cloud.cloudKey.publicKey,
      ownerVerifyKeys: new Map([["alice", userKey.publicKey]]),
      onCommand: (pt, reply) =>
        reply(Buffer.concat([Buffer.from("ACK:", "utf8"), pt])),
    },
    blackKey,
    helper,
  );
  console.log(`[drone] listening on :${droneServer.port}`);

  // User session over WebSocket
  const link: Transport = await wsConnect(`ws://127.0.0.1:${droneServer.port}`);
  const session = await runUserHandshake({
    identity,
    droneId: "drone-alpha",
    cloud: httpCloudClient(`http://127.0.0.1:${CLOUD_PORT}`),
    link,
    verbose: true,
  });

  let pending: ((pt: Buffer) => void) | null = null;
  session.onFrame((pt) => { const p = pending; pending = null; p?.(pt); });

  for (const cmd of ["TAKEOFF", "GOTO 25.034,121.565,80", "LAND"]) {
    await new Promise<void>((resolve) => {
      pending = (pt) => {
        console.log(`   cmd=${cmd}, telemetry=${JSON.stringify(pt.toString())}`);
        resolve();
      };
      void session.send(Buffer.from(cmd));
    });
  }

  session.close();
  await droneServer.close();
  cloudHttp.close();
  console.log("-- done");
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
