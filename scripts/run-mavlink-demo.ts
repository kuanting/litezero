// End-to-end MAVLink-over-LiteZero demo.
//
// A ground station sends real MAVLink v2 COMMAND_LONG frames through the
// LiteZero-secured channel; the drone's flight stack decodes them, applies the
// command, and streams back COMMAND_ACK + HEARTBEAT + GLOBAL_POSITION_INT —
// all carried as AEAD-protected payloads inside the session. The MAVLink bytes
// never appear in cleartext on the wire.

import { bootstrap, inProcessCloudClient } from "../src/scenarios/bootstrap.ts";
import { runUserHandshake } from "../src/services/user.ts";
import { FlightStack, gcsMission, describeFrame } from "../src/mavlink/flight.ts";

async function main(): Promise<void> {
  console.log("-- bootstrapping cloud + drone (MAVLink flight stack) + user ...");
  const flight = new FlightStack();
  const h = await bootstrap({
    // The drone decodes inbound MAVLink and replies with MAVLink telemetry.
    onCommand: (payload, reply) => {
      for (const out of flight.ingest(payload)) reply(out);
    },
  });

  console.log("-- user authorizes and handshakes (LiteZero AKE) ...");
  const session = await runUserHandshake({
    identity: h.userIdentity,
    droneId: h.droneId,
    cloud: inProcessCloudClient(h.cloud),
    link: h.connectToDrone(),
  });

  // Collect telemetry frames that come back per command.
  let onTelemetry: ((b: Buffer) => void) | null = null;
  session.onFrame((b) => onTelemetry?.(b));

  for (const { label, frame } of gcsMission()) {
    const replies: string[] = [];
    await new Promise<void>((resolve) => {
      let seen = 0;
      onTelemetry = (b) => {
        replies.push(describeFrame(b));
        // each command yields ack + heartbeat + position
        if (++seen >= 3) resolve();
      };
      console.log(`\n[GCS] -> ${label}  (MAVLink COMMAND_LONG, ${frame.length} bytes, encrypted in transit)`);
      void session.send(frame);
    });
    console.log(`[drone] <- ${replies.join("  ")}`);
  }

  session.close();
  await h.shutdown();
  console.log("\n-- done: real MAVLink C2/telemetry flowed entirely inside the LiteZero tunnel");
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
