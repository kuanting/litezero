// MAVLink v2 framing: encode a payload into a frame, and a streaming parser
// that extracts and CRC-validates frames from a byte stream.
//
// Frame layout (MAVLink 2, unsigned):
//   0      0xFD            magic / STX
//   1      len             payload length AFTER trailing-zero truncation
//   2      incompat_flags  (0; 0x01 would indicate a 13-byte signature)
//   3      compat_flags    (0)
//   4      seq             rolling sequence number
//   5      sysid           sender system id
//   6      compid          sender component id
//   7..9   msgid           24-bit little-endian message id
//   10..   payload         len bytes
//   ...    checksum        2 bytes, little-endian (CRC over [1..end-of-payload] + CRC_EXTRA)
//
// Signing (incompat_flags & 0x01) is parsed/skipped but not produced — LiteZero
// supersedes MAVLink's weak optional signing with an AEAD-authenticated tunnel.

import { mavlinkChecksum } from "./crc.ts";

export const MAVLINK_STX_V2 = 0xfd;
export const MAVLINK_IFLAG_SIGNED = 0x01;
const HEADER_LEN = 10; // magic + 9 header bytes
const CRC_LEN = 2;
const SIGNATURE_LEN = 13;

export interface MavlinkFrame {
  msgid: number;
  seq: number;
  sysid: number;
  compid: number;
  incompatFlags: number;
  compatFlags: number;
  /** Payload re-padded with zeros to `payloadLen` so field readers see the full struct. */
  payload: Buffer;
  /** True if the frame's checksum matched the supplied CRC_EXTRA. */
  crcOk: boolean;
}

export interface EncodeOptions {
  msgid: number;
  payload: Buffer; // full (untruncated) payload
  crcExtra: number;
  seq?: number;
  sysid?: number;
  compid?: number;
  incompatFlags?: number;
  compatFlags?: number;
}

/** Trim trailing zero bytes, always keeping at least one byte (reference rule). */
function trimPayload(payload: Buffer): Buffer {
  let len = payload.length;
  while (len > 1 && payload[len - 1] === 0) len--;
  return payload.subarray(0, len);
}

/** Encode a single MAVLink v2 frame. */
export function encodeFrame(opts: EncodeOptions): Buffer {
  const trimmed = trimPayload(opts.payload);
  const header = Buffer.alloc(HEADER_LEN);
  header[0] = MAVLINK_STX_V2;
  header[1] = trimmed.length;
  header[2] = opts.incompatFlags ?? 0;
  header[3] = opts.compatFlags ?? 0;
  header[4] = (opts.seq ?? 0) & 0xff;
  header[5] = (opts.sysid ?? 1) & 0xff;
  header[6] = (opts.compid ?? 1) & 0xff;
  header[7] = opts.msgid & 0xff;
  header[8] = (opts.msgid >> 8) & 0xff;
  header[9] = (opts.msgid >> 16) & 0xff;

  // Checksum is over everything from the length field through the payload.
  const crcRegion = Buffer.concat([header.subarray(1), trimmed]);
  const crc = mavlinkChecksum(crcRegion, opts.crcExtra);
  const crcBuf = Buffer.from([crc & 0xff, (crc >> 8) & 0xff]);
  return Buffer.concat([header, trimmed, crcBuf]);
}

/** Look up a message's CRC_EXTRA and full payload length by msgid. */
export type CrcExtraLookup = (msgid: number) => { crcExtra: number; payloadLen: number } | undefined;

/**
 * Streaming MAVLink v2 parser. Feed arbitrary byte chunks via `push`; it
 * returns every complete frame it can extract, re-syncing past garbage and
 * validating each checksum against the per-message CRC_EXTRA from `lookup`.
 */
export class MavlinkParser {
  private buf: Buffer = Buffer.alloc(0);
  constructor(private lookup: CrcExtraLookup) {}

  push(chunk: Buffer): MavlinkFrame[] {
    this.buf = this.buf.length ? Buffer.concat([this.buf, chunk]) : chunk;
    const out: MavlinkFrame[] = [];
    for (;;) {
      // Re-sync to the next STX.
      const stx = this.buf.indexOf(MAVLINK_STX_V2);
      if (stx < 0) {
        this.buf = Buffer.alloc(0);
        break;
      }
      if (stx > 0) this.buf = this.buf.subarray(stx);
      if (this.buf.length < HEADER_LEN) break; // need full header

      const len = this.buf[1];
      const incompat = this.buf[2];
      const signed = (incompat & MAVLINK_IFLAG_SIGNED) !== 0;
      const total = HEADER_LEN + len + CRC_LEN + (signed ? SIGNATURE_LEN : 0);
      if (this.buf.length < total) break; // need full frame

      const frame = this.buf.subarray(0, total);
      this.buf = this.buf.subarray(total);

      const msgid = frame[7] | (frame[8] << 8) | (frame[9] << 16);
      const payload = frame.subarray(HEADER_LEN, HEADER_LEN + len);
      const ck = frame[HEADER_LEN + len] | (frame[HEADER_LEN + len + 1] << 8);

      const def = this.lookup(msgid);
      let crcOk = false;
      let fullPayload = Buffer.from(payload);
      if (def) {
        const crcRegion = Buffer.concat([frame.subarray(1, HEADER_LEN + len)]);
        crcOk = mavlinkChecksum(crcRegion, def.crcExtra) === ck;
        // Re-pad the (possibly truncated) payload to the declared length.
        if (fullPayload.length < def.payloadLen) {
          fullPayload = Buffer.concat([
            fullPayload,
            Buffer.alloc(def.payloadLen - fullPayload.length),
          ]);
        }
      }
      out.push({
        msgid,
        seq: frame[4],
        sysid: frame[5],
        compid: frame[6],
        incompatFlags: incompat,
        compatFlags: frame[3],
        payload: fullPayload,
        crcOk,
      });
    }
    return out;
  }
}
