// A minimal MAVLink "flight stack" and "ground control station" pair, sharing
// the same codec. The LiteZero session carries these MAVLink frames as opaque
// AEAD-protected payloads, so the secure channel is exercised with the protocol
// a real drone actually speaks rather than toy strings.
//
// Used by the demo (run-demo.ts) and the MAVLink-injection attack scenario.

import {
  createParser,
  decodeFields,
  encodeCommandAck,
  encodeCommandLong,
  encodeGlobalPositionInt,
  encodeHeartbeat,
  MAV_AUTOPILOT_GENERIC,
  MAV_CMD,
  MAV_MODE_FLAG,
  MAV_RESULT,
  MAV_STATE,
  MAV_TYPE_QUADROTOR,
  type CommandLong,
  type MavlinkParser,
} from "./index.ts";

const GCS_SYS = 255;
const GCS_COMP = 190;
const DRONE_SYS = 1;
const DRONE_COMP = 1;

/** Encode a few realistic ground-station commands as MAVLink COMMAND_LONG frames. */
export function gcsMission(): { label: string; frame: Buffer }[] {
  let seq = 0;
  const cmd = (label: string, c: Partial<CommandLong> & { command: number }): { label: string; frame: Buffer } => ({
    label,
    frame: encodeCommandLong(
      {
        targetSystem: DRONE_SYS,
        targetComponent: DRONE_COMP,
        confirmation: 0,
        param1: 0,
        param2: 0,
        param3: 0,
        param4: 0,
        param5: 0,
        param6: 0,
        param7: 0,
        ...c,
      },
      { sysid: GCS_SYS, compid: GCS_COMP, seq: seq++ },
    ),
  });
  return [
    cmd("ARM", { command: MAV_CMD.COMPONENT_ARM_DISARM, param1: 1 }),
    cmd("TAKEOFF 80m", { command: MAV_CMD.NAV_TAKEOFF, param7: 80 }),
    cmd("GOTO 25.034,121.565", { command: MAV_CMD.DO_REPOSITION, param5: 25.034, param6: 121.565, param7: 80 }),
    cmd("LAND", { command: MAV_CMD.NAV_LAND }),
  ];
}

/**
 * Drone-side flight stack. Decodes inbound MAVLink from the user, applies the
 * command, and returns the MAVLink frames to send back (a COMMAND_ACK plus a
 * HEARTBEAT and a position telemetry frame). Returns [] for anything that is
 * not a valid, addressed command — which is exactly what an injected raw frame
 * with a bad CRC or wrong target degrades to.
 */
export class FlightStack {
  private parser: MavlinkParser = createParser();
  private bootMs = 0;
  private armed = false;
  private txSeq = 0;
  private lat = 250330000;
  private lon = 1215640000;
  private altMm = 0;

  /** Feed inbound bytes; return MAVLink response frames (possibly empty). */
  ingest(bytes: Buffer): Buffer[] {
    const out: Buffer[] = [];
    for (const frame of this.parser.push(bytes)) {
      if (!frame.crcOk) continue; // reject corrupt / non-MAVLink bytes
      const msg = decodeFields(frame);
      if (msg.name !== "COMMAND_LONG") continue;
      const c = msg.fields;
      if (c.targetSystem !== DRONE_SYS) continue; // not addressed to us
      out.push(...this.applyCommand(c));
    }
    return out;
  }

  private applyCommand(c: CommandLong): Buffer[] {
    let result: number = MAV_RESULT.ACCEPTED;
    switch (c.command) {
      case MAV_CMD.COMPONENT_ARM_DISARM:
        this.armed = c.param1 >= 0.5;
        break;
      case MAV_CMD.NAV_TAKEOFF:
        this.altMm = Math.round(c.param7 * 1000);
        break;
      case MAV_CMD.DO_REPOSITION:
        this.lat = Math.round(c.param5 * 1e7);
        this.lon = Math.round(c.param6 * 1e7);
        this.altMm = Math.round(c.param7 * 1000);
        break;
      case MAV_CMD.NAV_LAND:
        this.altMm = 0;
        break;
      default:
        result = MAV_RESULT.UNSUPPORTED;
    }
    this.bootMs += 100;
    const h = { sysid: DRONE_SYS, compid: DRONE_COMP };
    const ack = encodeCommandAck({ command: c.command, result }, { ...h, seq: this.txSeq++ });
    const beat = encodeHeartbeat(
      {
        type: MAV_TYPE_QUADROTOR,
        autopilot: MAV_AUTOPILOT_GENERIC,
        baseMode: MAV_MODE_FLAG.CUSTOM_MODE_ENABLED | (this.armed ? MAV_MODE_FLAG.SAFETY_ARMED : 0),
        customMode: 0,
        systemStatus: this.armed ? MAV_STATE.ACTIVE : MAV_STATE.STANDBY,
        mavlinkVersion: 3,
      },
      { ...h, seq: this.txSeq++ },
    );
    const pos = encodeGlobalPositionInt(
      {
        timeBootMs: this.bootMs,
        lat: this.lat,
        lon: this.lon,
        alt: this.altMm,
        relativeAlt: this.altMm,
        vx: 0,
        vy: 0,
        vz: 0,
        hdg: 0,
      },
      { ...h, seq: this.txSeq++ },
    );
    return [ack, beat, pos];
  }
}

/** Human-readable one-liner for a decoded telemetry/ack frame, for demo logs. */
export function describeFrame(bytes: Buffer): string {
  const parser = createParser();
  const parts: string[] = [];
  for (const f of parser.push(bytes)) {
    if (!f.crcOk) {
      parts.push("non-MAVLink/corrupt");
      continue;
    }
    const m = decodeFields(f);
    switch (m.name) {
      case "COMMAND_ACK":
        parts.push(`COMMAND_ACK(cmd=${m.fields.command},result=${m.fields.result})`);
        break;
      case "HEARTBEAT":
        parts.push(`HEARTBEAT(${(m.fields.baseMode & MAV_MODE_FLAG.SAFETY_ARMED) ? "ARMED" : "disarmed"})`);
        break;
      case "GLOBAL_POSITION_INT":
        parts.push(`POSITION(lat=${(m.fields.lat / 1e7).toFixed(4)},lon=${(m.fields.lon / 1e7).toFixed(4)},alt=${(m.fields.alt / 1000).toFixed(0)}m)`);
        break;
      default:
        parts.push(m.name);
    }
  }
  return parts.join(" ");
}
