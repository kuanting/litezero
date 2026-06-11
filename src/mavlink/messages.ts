// A small, spec-accurate subset of the MAVLink "common" dialect — enough to
// fly a realistic command/telemetry stream through the LiteZero tunnel.
//
// Payload field order follows the MAVLink wire rule (fields sorted by
// descending native size, ties keeping XML order), and each message carries the
// exact CRC_EXTRA from the generated common.xml headers, so frames round-trip
// with pymavlink / node-mavlink and real autopilots.

export const MAV_AUTOPILOT_GENERIC = 0;
export const MAV_TYPE_QUADROTOR = 2;

/** MAV_STATE */
export const MAV_STATE = {
  STANDBY: 3,
  ACTIVE: 4,
} as const;

/** MAV_MODE_FLAG */
export const MAV_MODE_FLAG = {
  SAFETY_ARMED: 0x80,
  CUSTOM_MODE_ENABLED: 0x01,
} as const;

/** Subset of MAV_CMD used in the demo. */
export const MAV_CMD = {
  NAV_WAYPOINT: 16,
  NAV_LAND: 21,
  NAV_TAKEOFF: 22,
  DO_REPOSITION: 192,
  COMPONENT_ARM_DISARM: 400,
} as const;

/** MAV_RESULT */
export const MAV_RESULT = {
  ACCEPTED: 0,
  TEMPORARILY_REJECTED: 1,
  DENIED: 2,
  UNSUPPORTED: 3,
  FAILED: 4,
} as const;

export interface MessageDef {
  name: string;
  msgid: number;
  crcExtra: number;
  payloadLen: number;
}

/* ------------------------------------------------------------------ */
/* HEARTBEAT (#0)                                                     */
/* ------------------------------------------------------------------ */

export interface Heartbeat {
  type: number;
  autopilot: number;
  baseMode: number;
  customMode: number;
  systemStatus: number;
  mavlinkVersion: number;
}
export const HEARTBEAT: MessageDef = { name: "HEARTBEAT", msgid: 0, crcExtra: 50, payloadLen: 9 };

export function packHeartbeat(m: Heartbeat): Buffer {
  const b = Buffer.alloc(HEARTBEAT.payloadLen);
  b.writeUInt32LE(m.customMode >>> 0, 0);
  b.writeUInt8(m.type & 0xff, 4);
  b.writeUInt8(m.autopilot & 0xff, 5);
  b.writeUInt8(m.baseMode & 0xff, 6);
  b.writeUInt8(m.systemStatus & 0xff, 7);
  b.writeUInt8(m.mavlinkVersion & 0xff, 8);
  return b;
}
export function unpackHeartbeat(b: Buffer): Heartbeat {
  return {
    customMode: b.readUInt32LE(0),
    type: b.readUInt8(4),
    autopilot: b.readUInt8(5),
    baseMode: b.readUInt8(6),
    systemStatus: b.readUInt8(7),
    mavlinkVersion: b.readUInt8(8),
  };
}

/* ------------------------------------------------------------------ */
/* COMMAND_LONG (#76)                                                 */
/* ------------------------------------------------------------------ */

export interface CommandLong {
  targetSystem: number;
  targetComponent: number;
  command: number;
  confirmation: number;
  param1: number;
  param2: number;
  param3: number;
  param4: number;
  param5: number;
  param6: number;
  param7: number;
}
export const COMMAND_LONG: MessageDef = { name: "COMMAND_LONG", msgid: 76, crcExtra: 152, payloadLen: 33 };

export function packCommandLong(m: CommandLong): Buffer {
  const b = Buffer.alloc(COMMAND_LONG.payloadLen);
  b.writeFloatLE(m.param1, 0);
  b.writeFloatLE(m.param2, 4);
  b.writeFloatLE(m.param3, 8);
  b.writeFloatLE(m.param4, 12);
  b.writeFloatLE(m.param5, 16);
  b.writeFloatLE(m.param6, 20);
  b.writeFloatLE(m.param7, 24);
  b.writeUInt16LE(m.command & 0xffff, 28);
  b.writeUInt8(m.targetSystem & 0xff, 30);
  b.writeUInt8(m.targetComponent & 0xff, 31);
  b.writeUInt8(m.confirmation & 0xff, 32);
  return b;
}
export function unpackCommandLong(b: Buffer): CommandLong {
  return {
    param1: b.readFloatLE(0),
    param2: b.readFloatLE(4),
    param3: b.readFloatLE(8),
    param4: b.readFloatLE(12),
    param5: b.readFloatLE(16),
    param6: b.readFloatLE(20),
    param7: b.readFloatLE(24),
    command: b.readUInt16LE(28),
    targetSystem: b.readUInt8(30),
    targetComponent: b.readUInt8(31),
    confirmation: b.readUInt8(32),
  };
}

/* ------------------------------------------------------------------ */
/* COMMAND_ACK (#77) — base fields only (extensions omitted)          */
/* ------------------------------------------------------------------ */

export interface CommandAck {
  command: number;
  result: number;
}
export const COMMAND_ACK: MessageDef = { name: "COMMAND_ACK", msgid: 77, crcExtra: 143, payloadLen: 3 };

export function packCommandAck(m: CommandAck): Buffer {
  const b = Buffer.alloc(COMMAND_ACK.payloadLen);
  b.writeUInt16LE(m.command & 0xffff, 0);
  b.writeUInt8(m.result & 0xff, 2);
  return b;
}
export function unpackCommandAck(b: Buffer): CommandAck {
  return { command: b.readUInt16LE(0), result: b.readUInt8(2) };
}

/* ------------------------------------------------------------------ */
/* GLOBAL_POSITION_INT (#33)                                          */
/* ------------------------------------------------------------------ */

export interface GlobalPositionInt {
  timeBootMs: number;
  lat: number; // degE7
  lon: number; // degE7
  alt: number; // mm (MSL)
  relativeAlt: number; // mm
  vx: number; // cm/s
  vy: number;
  vz: number;
  hdg: number; // cdeg
}
export const GLOBAL_POSITION_INT: MessageDef = { name: "GLOBAL_POSITION_INT", msgid: 33, crcExtra: 104, payloadLen: 28 };

export function packGlobalPositionInt(m: GlobalPositionInt): Buffer {
  const b = Buffer.alloc(GLOBAL_POSITION_INT.payloadLen);
  b.writeUInt32LE(m.timeBootMs >>> 0, 0);
  b.writeInt32LE(m.lat | 0, 4);
  b.writeInt32LE(m.lon | 0, 8);
  b.writeInt32LE(m.alt | 0, 12);
  b.writeInt32LE(m.relativeAlt | 0, 16);
  b.writeInt16LE(m.vx | 0, 20);
  b.writeInt16LE(m.vy | 0, 22);
  b.writeInt16LE(m.vz | 0, 24);
  b.writeUInt16LE(m.hdg & 0xffff, 26);
  return b;
}
export function unpackGlobalPositionInt(b: Buffer): GlobalPositionInt {
  return {
    timeBootMs: b.readUInt32LE(0),
    lat: b.readInt32LE(4),
    lon: b.readInt32LE(8),
    alt: b.readInt32LE(12),
    relativeAlt: b.readInt32LE(16),
    vx: b.readInt16LE(20),
    vy: b.readInt16LE(22),
    vz: b.readInt16LE(24),
    hdg: b.readUInt16LE(26),
  };
}

/* ------------------------------------------------------------------ */
/* ATTITUDE (#30)                                                     */
/* ------------------------------------------------------------------ */

export interface Attitude {
  timeBootMs: number;
  roll: number;
  pitch: number;
  yaw: number;
  rollspeed: number;
  pitchspeed: number;
  yawspeed: number;
}
export const ATTITUDE: MessageDef = { name: "ATTITUDE", msgid: 30, crcExtra: 39, payloadLen: 28 };

export function packAttitude(m: Attitude): Buffer {
  const b = Buffer.alloc(ATTITUDE.payloadLen);
  b.writeUInt32LE(m.timeBootMs >>> 0, 0);
  b.writeFloatLE(m.roll, 4);
  b.writeFloatLE(m.pitch, 8);
  b.writeFloatLE(m.yaw, 12);
  b.writeFloatLE(m.rollspeed, 16);
  b.writeFloatLE(m.pitchspeed, 20);
  b.writeFloatLE(m.yawspeed, 24);
  return b;
}
export function unpackAttitude(b: Buffer): Attitude {
  return {
    timeBootMs: b.readUInt32LE(0),
    roll: b.readFloatLE(4),
    pitch: b.readFloatLE(8),
    yaw: b.readFloatLE(12),
    rollspeed: b.readFloatLE(16),
    pitchspeed: b.readFloatLE(20),
    yawspeed: b.readFloatLE(24),
  };
}

/* ------------------------------------------------------------------ */
/* Registry (msgid -> def) for the parser's CRC_EXTRA lookup           */
/* ------------------------------------------------------------------ */

export const MESSAGE_DEFS: MessageDef[] = [
  HEARTBEAT,
  COMMAND_LONG,
  COMMAND_ACK,
  GLOBAL_POSITION_INT,
  ATTITUDE,
];

const BY_ID = new Map<number, MessageDef>(MESSAGE_DEFS.map((d) => [d.msgid, d]));

export function lookupDef(msgid: number): { crcExtra: number; payloadLen: number } | undefined {
  const d = BY_ID.get(msgid);
  return d ? { crcExtra: d.crcExtra, payloadLen: d.payloadLen } : undefined;
}
