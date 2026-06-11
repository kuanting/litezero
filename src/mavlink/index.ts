// Public surface of the in-repo MAVLink v2 codec.
//
// Zero-dependency and spec-accurate: frames produced here interoperate with
// pymavlink / node-mavlink and real autopilots. This keeps the LiteZero
// reference model "standard-library only" while still exercising the protocol
// the drone actually speaks. To swap in the full node-mavlink dialect set
// later, replace these helpers — the LiteZero session carries opaque bytes and
// is unaffected.

import { encodeFrame, MavlinkParser, type MavlinkFrame } from "./protocol.ts";
import {
  ATTITUDE,
  COMMAND_ACK,
  COMMAND_LONG,
  GLOBAL_POSITION_INT,
  HEARTBEAT,
  lookupDef,
  packAttitude,
  packCommandAck,
  packCommandLong,
  packGlobalPositionInt,
  packHeartbeat,
  unpackAttitude,
  unpackCommandAck,
  unpackCommandLong,
  unpackGlobalPositionInt,
  unpackHeartbeat,
  type Attitude,
  type CommandAck,
  type CommandLong,
  type GlobalPositionInt,
  type Heartbeat,
} from "./messages.ts";

export * from "./messages.ts";
export { encodeFrame, MavlinkParser, type MavlinkFrame } from "./protocol.ts";
export { MAVLINK_STX_V2, MAVLINK_IFLAG_SIGNED } from "./protocol.ts";

interface FrameHeader {
  seq?: number;
  sysid?: number;
  compid?: number;
}

export function encodeHeartbeat(m: Heartbeat, h: FrameHeader = {}): Buffer {
  return encodeFrame({ msgid: HEARTBEAT.msgid, payload: packHeartbeat(m), crcExtra: HEARTBEAT.crcExtra, ...h });
}
export function encodeCommandLong(m: CommandLong, h: FrameHeader = {}): Buffer {
  return encodeFrame({ msgid: COMMAND_LONG.msgid, payload: packCommandLong(m), crcExtra: COMMAND_LONG.crcExtra, ...h });
}
export function encodeCommandAck(m: CommandAck, h: FrameHeader = {}): Buffer {
  return encodeFrame({ msgid: COMMAND_ACK.msgid, payload: packCommandAck(m), crcExtra: COMMAND_ACK.crcExtra, ...h });
}
export function encodeGlobalPositionInt(m: GlobalPositionInt, h: FrameHeader = {}): Buffer {
  return encodeFrame({ msgid: GLOBAL_POSITION_INT.msgid, payload: packGlobalPositionInt(m), crcExtra: GLOBAL_POSITION_INT.crcExtra, ...h });
}
export function encodeAttitude(m: Attitude, h: FrameHeader = {}): Buffer {
  return encodeFrame({ msgid: ATTITUDE.msgid, payload: packAttitude(m), crcExtra: ATTITUDE.crcExtra, ...h });
}

/** A decoded message with its fields parsed into a typed object. */
export type DecodedMessage =
  | { name: "HEARTBEAT"; frame: MavlinkFrame; fields: Heartbeat }
  | { name: "COMMAND_LONG"; frame: MavlinkFrame; fields: CommandLong }
  | { name: "COMMAND_ACK"; frame: MavlinkFrame; fields: CommandAck }
  | { name: "GLOBAL_POSITION_INT"; frame: MavlinkFrame; fields: GlobalPositionInt }
  | { name: "ATTITUDE"; frame: MavlinkFrame; fields: Attitude }
  | { name: "UNKNOWN"; frame: MavlinkFrame; fields: null };

/** Parse the fields of a (CRC-valid) frame into a typed message. */
export function decodeFields(frame: MavlinkFrame): DecodedMessage {
  switch (frame.msgid) {
    case HEARTBEAT.msgid:
      return { name: "HEARTBEAT", frame, fields: unpackHeartbeat(frame.payload) };
    case COMMAND_LONG.msgid:
      return { name: "COMMAND_LONG", frame, fields: unpackCommandLong(frame.payload) };
    case COMMAND_ACK.msgid:
      return { name: "COMMAND_ACK", frame, fields: unpackCommandAck(frame.payload) };
    case GLOBAL_POSITION_INT.msgid:
      return { name: "GLOBAL_POSITION_INT", frame, fields: unpackGlobalPositionInt(frame.payload) };
    case ATTITUDE.msgid:
      return { name: "ATTITUDE", frame, fields: unpackAttitude(frame.payload) };
    default:
      return { name: "UNKNOWN", frame, fields: null };
  }
}

/** Create a streaming parser wired to this dialect's CRC_EXTRA registry. */
export function createParser(): MavlinkParser {
  return new MavlinkParser(lookupDef);
}

/** Convenience: decode all complete, CRC-valid frames in a single buffer. */
export function decodeAll(buf: Buffer): DecodedMessage[] {
  const parser = createParser();
  return parser
    .push(buf)
    .filter((f) => f.crcOk)
    .map(decodeFields);
}
