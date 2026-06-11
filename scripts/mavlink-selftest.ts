// Zero-dependency self-test for the in-repo MAVLink v2 codec.
//
// Validates encode/decode round-trips, the streaming parser (re-sync past
// garbage, frames split across chunks), CRC tamper detection, and payload
// zero-trim + re-pad. Wire-compatibility with the reference pymavlink is
// checked separately by tools/mavlink_interop_check.py (optional, needs Python).
//
// Run: npm run mavlink:test

import {
  encodeHeartbeat,
  encodeCommandLong,
  encodeCommandAck,
  encodeGlobalPositionInt,
  encodeAttitude,
  createParser,
  decodeFields,
  decodeAll,
  MAV_CMD,
  MAV_RESULT,
  MAV_TYPE_QUADROTOR,
  MAV_AUTOPILOT_GENERIC,
  MAV_STATE,
  MAVLINK_STX_V2,
} from "../src/mavlink/index.ts";

let fail = 0;
function check(name: string, cond: boolean, extra = ""): void {
  console.log(`${cond ? "ok  " : "FAIL"} ${name} ${extra}`);
  if (!cond) fail++;
}

const hb = encodeHeartbeat({
  type: MAV_TYPE_QUADROTOR,
  autopilot: MAV_AUTOPILOT_GENERIC,
  baseMode: 0x81,
  customMode: 5,
  systemStatus: MAV_STATE.ACTIVE,
  mavlinkVersion: 3,
});
check("HEARTBEAT magic is 0xFD", hb[0] === MAVLINK_STX_V2);
const dh = decodeAll(hb);
check(
  "HEARTBEAT round-trips",
  dh.length === 1 && dh[0].name === "HEARTBEAT" && dh[0].fields?.customMode === 5,
);

const cl = encodeCommandLong(
  {
    targetSystem: 1,
    targetComponent: 1,
    command: MAV_CMD.NAV_TAKEOFF,
    confirmation: 0,
    param1: 0,
    param2: 0,
    param3: 0,
    param4: 0,
    param5: 25.034,
    param6: 121.565,
    param7: 80,
  },
  { seq: 7 },
);
const dc = decodeAll(cl);
check(
  "COMMAND_LONG round-trips (cmd, alt, seq)",
  dc.length === 1 &&
    dc[0].name === "COMMAND_LONG" &&
    dc[0].fields?.command === MAV_CMD.NAV_TAKEOFF &&
    Math.abs((dc[0].fields?.param7 ?? 0) - 80) < 1e-3 &&
    dc[0].frame.seq === 7,
);

const ackFrame = encodeCommandAck({ command: MAV_CMD.NAV_TAKEOFF, result: MAV_RESULT.ACCEPTED });
const dack = decodeAll(ackFrame);
check(
  "COMMAND_ACK round-trips",
  dack.length === 1 && dack[0].name === "COMMAND_ACK" && dack[0].fields?.result === MAV_RESULT.ACCEPTED,
);

const gp = decodeAll(
  encodeGlobalPositionInt({
    timeBootMs: 1234,
    lat: 250340000,
    lon: 1215650000,
    alt: 80000,
    relativeAlt: 79000,
    vx: -5,
    vy: 3,
    vz: -1,
    hdg: 9000,
  }),
);
check(
  "GLOBAL_POSITION_INT round-trips (signed ints)",
  gp.length === 1 && gp[0].name === "GLOBAL_POSITION_INT" && gp[0].fields?.vx === -5 && gp[0].fields?.lat === 250340000,
);

const at = decodeAll(
  encodeAttitude({ timeBootMs: 99, roll: 0.1, pitch: -0.2, yaw: 1.5, rollspeed: 0, pitchspeed: 0, yawspeed: 0 }),
);
check("ATTITUDE round-trips (floats)", at.length === 1 && at[0].name === "ATTITUDE" && Math.abs((at[0].fields?.yaw ?? 0) - 1.5) < 1e-6);

// Streaming: leading garbage + three frames + split across two pushes.
const stream = Buffer.concat([Buffer.from([0x00, 0xab]), hb, cl, ackFrame]);
const p = createParser();
const recovered = [...p.push(stream.subarray(0, 12)), ...p.push(stream.subarray(12))]
  .filter((f) => f.crcOk)
  .map(decodeFields);
check("streaming recovers 3 frames past garbage & split", recovered.length === 3, `(got ${recovered.length})`);

// CRC tamper.
const bad = Buffer.from(hb);
bad[bad.length - 1] ^= 0xff;
const tampered = createParser().push(bad);
check("CRC tamper is rejected", tampered.length === 1 && tampered[0].crcOk === false);

// Zero-trim: an all-zero customMode trims to len 1 and re-pads on decode.
const hb0 = encodeHeartbeat({ type: 0, autopilot: 0, baseMode: 0, customMode: 0, systemStatus: 0, mavlinkVersion: 0 });
check("payload zero-trim keeps len>=1", hb0[1] === 1, `(len=${hb0[1]})`);
check("zero-trimmed frame decodes", decodeAll(hb0).length === 1);

console.log(fail === 0 ? "\nALL MAVLINK CODEC TESTS PASSED" : `\n${fail} FAILURES`);
process.exit(fail === 0 ? 0 : 1);
