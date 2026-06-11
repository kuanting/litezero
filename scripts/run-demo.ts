// Happy-path end-to-end demo, all in a single process.
//
// For a multi-process / WebSocket demo, see scripts/run-demo-ws.ts.

import { bootstrap, inProcessCloudClient } from "../src/scenarios/bootstrap.ts";
import { runUserHandshake } from "../src/services/user.ts";

async function main() {
  console.log("-- bootstrapping cloud + drone + user (in-process) ...");
  const h = await bootstrap();

  console.log("-- user logs in, authorizes, handshakes with drone ...");
  const session = await runUserHandshake({
    identity: h.userIdentity,
    droneId: h.droneId,
    cloud: inProcessCloudClient(h.cloud),
    link: h.connectToDrone(),
    verbose: true,
  });

  // Single listener, routed to the current pending waiter.
  let pending: ((pt: Buffer) => void) | null = null;
  session.onFrame((pt) => { const p = pending; pending = null; p?.(pt); });

  const fly = (cmd: string) =>
    new Promise<void>((resolve) => {
      pending = (pt) => {
        console.log(`   cmd=${cmd}, telemetry=${JSON.stringify(pt.toString())} [epoch ${session.epoch()}]`);
        resolve();
      };
      void session.send(Buffer.from(cmd));
    });

  await fly("TAKEOFF");
  await fly("GOTO 25.034,121.565,80");

  // Continuous verification: ratchet the session keys (intra-session forward
  // secrecy) and re-present a fresh cloud token, all in-band over the
  // authenticated channel, without tearing the transport.
  console.log("-- in-band rekey to a new key epoch ...");
  await session.rekey();
  await fly("HOVER");

  console.log("-- in-band token refresh (extend authorization) ...");
  await session.refresh();
  await fly("LAND");

  session.close();
  await h.shutdown();
  console.log("-- done");
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
