#!/usr/bin/env python3
"""Optional wire-compatibility check for the in-repo MAVLink v2 codec.

Proves the LiteZero simulation's zero-dependency TypeScript MAVLink codec is
byte-compatible with the reference implementation (pymavlink), in BOTH
directions:

  1. frames the TS codec emits decode correctly under pymavlink, and
  2. frames pymavlink emits decode correctly under the TS codec.

This is a dev/CI aid only; the LiteZero attack battery itself stays Python-free
and standard-library only. The TS codec is the source of truth used by the
simulation.

Requires: pip install pymavlink ; Node with --experimental-transform-types.
Run:      python3 tools/mavlink_interop_check.py
"""
import json
import subprocess
import sys

try:
    from pymavlink.dialects.v20 import common as mav
except ImportError:
    print("pymavlink not installed — `pip install pymavlink` to run this check.")
    sys.exit(2)

NODE = ["node", "--experimental-transform-types", "--no-warnings"]

# A tiny TS program that emits the same five messages as hex, so we compare
# against the reference without duplicating field values in two languages.
TS_EMIT = r"""
import { encodeHeartbeat, encodeCommandLong, encodeCommandAck,
  encodeGlobalPositionInt, encodeAttitude, MAV_CMD, MAV_RESULT,
  MAV_TYPE_QUADROTOR, MAV_AUTOPILOT_GENERIC } from "../src/mavlink/index.ts";
const f = {
  HEARTBEAT: encodeHeartbeat({type:MAV_TYPE_QUADROTOR,autopilot:MAV_AUTOPILOT_GENERIC,baseMode:0x81,customMode:5,systemStatus:4,mavlinkVersion:3},{sysid:1,compid:1,seq:0}),
  COMMAND_LONG: encodeCommandLong({targetSystem:1,targetComponent:1,command:MAV_CMD.NAV_TAKEOFF,confirmation:0,param1:0,param2:0,param3:0,param4:0,param5:25.034,param6:121.565,param7:80},{sysid:1,compid:1,seq:7}),
  COMMAND_ACK: encodeCommandAck({command:MAV_CMD.NAV_TAKEOFF,result:MAV_RESULT.ACCEPTED},{sysid:1,compid:1,seq:1}),
  GLOBAL_POSITION_INT: encodeGlobalPositionInt({timeBootMs:1234,lat:250340000,lon:1215650000,alt:80000,relativeAlt:79000,vx:-5,vy:3,vz:-1,hdg:9000},{sysid:1,compid:1,seq:2}),
  ATTITUDE: encodeAttitude({timeBootMs:99,roll:0.1,pitch:-0.2,yaw:1.5,rollspeed:0,pitchspeed:0,yawspeed:0},{sysid:1,compid:1,seq:3}),
};
const o = {}; for (const [k,v] of Object.entries(f)) o[k]=v.toString("hex");
console.log(JSON.stringify(o));
"""

# A TS program that decodes hex frames (supplied on argv[2]) and reports type+crc.
TS_DECODE = r"""
import { decodeAll } from "../src/mavlink/index.ts";
const frames = JSON.parse(process.argv[2]);
const out = {};
for (const [name, hex] of Object.entries(frames)) {
  const d = decodeAll(Buffer.from(hex, "hex"));
  out[name] = d.length === 1 ? { type: d[0].name, crcOk: d[0].frame.crcOk } : { type: null, crcOk: false };
}
console.log(JSON.stringify(out));
"""


def run_ts(src: str, *args: str) -> str:
    import os
    import tempfile

    here = os.path.dirname(os.path.abspath(__file__))
    scripts = os.path.join(os.path.dirname(here), "scripts")
    with tempfile.NamedTemporaryFile("w", suffix=".ts", dir=scripts, delete=False) as fh:
        fh.write(src)
        path = fh.name
    try:
        return subprocess.check_output(NODE + [path, *args], text=True).strip()
    finally:
        os.unlink(path)


def main() -> int:
    fails = 0

    # Direction 1: TS encodes -> pymavlink decodes.
    ts_frames = json.loads(run_ts(TS_EMIT))
    dec = mav.MAVLink(None)
    for name, hexstr in ts_frames.items():
        msgs = dec.parse_buffer(bytes.fromhex(hexstr)) or []
        ok = bool(msgs) and msgs[0].get_type() == name
        print(f"{'ok  ' if ok else 'FAIL'} TS->pymavlink  {name}")
        fails += 0 if ok else 1

    # Direction 2: pymavlink encodes -> TS decodes.
    enc = mav.MAVLink(None, srcSystem=1, srcComponent=1)
    py_frames = {
        "HEARTBEAT": mav.MAVLink_heartbeat_message(mav.MAV_TYPE_QUADROTOR, mav.MAV_AUTOPILOT_GENERIC, 0x81, 5, 4, 3),
        "COMMAND_LONG": mav.MAVLink_command_long_message(1, 1, mav.MAV_CMD_NAV_TAKEOFF, 0, 0, 0, 0, 0, 25.034, 121.565, 80),
        "GLOBAL_POSITION_INT": mav.MAVLink_global_position_int_message(1234, 250340000, 1215650000, 80000, 79000, -5, 3, -1, 9000),
        "ATTITUDE": mav.MAVLink_attitude_message(99, 0.1, -0.2, 1.5, 0, 0, 0),
    }
    hexed = {name: msg.pack(enc).hex() for name, msg in py_frames.items()}
    ts_dec = json.loads(run_ts(TS_DECODE, json.dumps(hexed)))
    for name in py_frames:
        r = ts_dec.get(name, {})
        ok = r.get("type") == name and r.get("crcOk") is True
        print(f"{'ok  ' if ok else 'FAIL'} pymavlink->TS  {name}")
        fails += 0 if ok else 1

    print("\nMAVLINK INTEROP:", "PASS" if fails == 0 else f"{fails} FAILURES")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
