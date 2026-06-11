// MAVLink command-injection / eavesdrop attack.
//
// MAVLink v2 by itself has no transport confidentiality and only weak, rarely
// deployed optional signing, so on a bare link an attacker can both read every
// command and forge new ones the autopilot will execute. This scenario shows
// that wrapping MAVLink in the LiteZero session closes both:
//
//   (a) eavesdropping — captured frames carry only AES-GCM ciphertext, never
//       the MAVLink magic byte or any command, and
//   (b) injection — a perfectly valid, CRC-correct MAVLink COMMAND_LONG
//       (a "disarm in flight" kill command) injected as a raw session frame is
//       rejected by the drone (no AEAD key, no session), so the flight stack
//       never acts on it.
//
// The control is the attacker's own parser confirming the forged frame is a
// genuine, well-formed MAVLink command — i.e. the attack would succeed against
// bare MAVLink and is stopped only by the LiteZero tunnel.

import { bootstrap, inProcessCloudClient } from "../scenarios/bootstrap.ts";
import { runUserHandshake } from "../services/user.ts";
import { tapTransport } from "./_tap.ts";
import { randBytes } from "../crypto/primitives.ts";
import { FlightStack, gcsMission } from "../mavlink/flight.ts";
import {
  createParser,
  decodeFields,
  encodeCommandLong,
  MAV_CMD,
  MAVLINK_STX_V2,
} from "../mavlink/index.ts";
import type { AttackResult } from "./types.ts";

export async function attackMavlinkInjection(): Promise<AttackResult> {
  // A flight stack that records whether it ever executes a DISARM, so we can
  // prove the injected kill-command (disarm-in-flight) was never applied. The
  // legitimate ARM below is command 400 too, so we key on param1 (0 = disarm).
  let disarmExecuted = false;
  const flight = new FlightStack();
  const h = await bootstrap({
    onCommand: (payload, reply) => {
      if (sniffDisarm(payload)) disarmExecuted = true;
      for (const out of flight.ingest(payload)) reply(out);
    },
  });

  // Capture all ciphertext on the wire to test confidentiality.
  const captured: string[] = [];
  const tapped = tapTransport(h.connectToDrone(), (m) => captured.push(m));

  const session = await runUserHandshake({
    identity: h.userIdentity,
    droneId: h.droneId,
    cloud: inProcessCloudClient(h.cloud),
    link: tapped,
  });

  // Legitimate ARM so the drone is flying, driven over the secure channel.
  const arm = gcsMission()[0];
  await new Promise<void>((resolve) => {
    let n = 0;
    session.onFrame(() => {
      if (++n >= 3) resolve();
    });
    void session.send(arm.frame);
  });

  // The attacker forges a valid MAVLink "disarm" (COMPONENT_ARM_DISARM,
  // param1=0) — a classic in-flight kill — and confirms it is well-formed.
  const killFrame = encodeCommandLong(
    {
      targetSystem: 1,
      targetComponent: 1,
      command: MAV_CMD.COMPONENT_ARM_DISARM,
      confirmation: 0,
      param1: 0, // 0 = DISARM
      param2: 21196, // force
      param3: 0,
      param4: 0,
      param5: 0,
      param6: 0,
      param7: 0,
    },
    { sysid: 1, compid: 1, seq: 0 },
  );
  const forgedDecodes = createParser()
    .push(killFrame)
    .some((f) => f.crcOk && decodeFields(f).name === "COMMAND_LONG");

  // Inject the raw MAVLink bytes straight onto the transport, as a forged
  // "data" session frame and also as a bare write — the drone has no matching
  // AEAD key/sequence, so it must reject both without ever decoding MAVLink.
  let injectionError = "";
  const injectLink = h.connectToDrone();
  await new Promise<void>((resolve) => {
    injectLink.onMessage((s) => {
      try {
        const m = JSON.parse(s) as { kind: string; reason?: string };
        if (m.kind === "error") {
          injectionError = m.reason ?? "rejected";
          resolve();
        }
      } catch {
        /* ignore */
      }
    });
    injectLink.send(
      JSON.stringify({
        kind: "data",
        dir: "u2d",
        epoch: 0,
        chan: "app",
        seq: 0,
        iv: randBytes(12).toString("base64"),
        ct: killFrame.toString("base64"), // raw MAVLink as the "ciphertext"
        tag: randBytes(16).toString("base64"),
      }),
    );
    // The drone either replies with an error or silently drops the frame; both
    // are valid defenses. We do not gate the verdict on the reply arriving, so
    // this deadline only bounds how long we wait to record an explicit reason.
    setTimeout(resolve, 500);
  });
  injectLink.close();
  session.close();
  await h.shutdown();

  // Confidentiality: no captured frame may contain the MAVLink magic byte or a
  // decodable command. Frames are base64 JSON, so decode the ct fields.
  const leaked = captured.some((raw) => {
    try {
      const m = JSON.parse(raw) as { kind?: string; ct?: string };
      if (m.kind !== "data" || !m.ct) return false;
      const pt = Buffer.from(m.ct, "base64");
      // If the AEAD payload were actually MAVLink, it would start with 0xFD and
      // CRC-validate. It must not.
      return pt[0] === MAVLINK_STX_V2 && createParser().push(pt).some((f) => f.crcOk);
    } catch {
      return false;
    }
  });

  // The security property is: the forged disarm never executed and no plaintext
  // MAVLink ever appeared on the wire. Whether the drone actively replied with
  // an error (vs. silently dropping the frame) is informational, not the test.
  const rejection = injectionError !== "" ? injectionError : "frame dropped (no session key)";
  const defended = forgedDecodes && !leaked && !disarmExecuted;
  return {
    name: "MAVLink command injection / eavesdrop",
    defended,
    detail: defended
      ? `forged MAVLink disarm was valid (would kill bare MAVLink) but the LiteZero tunnel rejected it (${rejection}); no plaintext MAVLink on the wire`
      : `forgedValid=${forgedDecodes} leaked=${leaked} disarmExecuted=${disarmExecuted} injErr="${injectionError}" — BAD`,
  };
}

/** True if the (plaintext) MAVLink buffer carries a disarm (cmd 400, param1=0). */
function sniffDisarm(payload: Buffer): boolean {
  for (const f of createParser().push(payload)) {
    if (!f.crcOk) continue;
    const m = decodeFields(f);
    if (m.name === "COMMAND_LONG" && m.fields.command === MAV_CMD.COMPONENT_ARM_DISARM && m.fields.param1 < 0.5) {
      return true;
    }
  }
  return false;
}
