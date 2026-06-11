// MAVLink checksum — CRC-16/MCRF4XX (the "X.25" variant MAVLink uses).
//
// This is the exact `crc_accumulate` algorithm from the reference
// mavlink_helpers.h, so frames produced here are wire-compatible with
// pymavlink / node-mavlink and any real autopilot. It is deliberately tiny and
// dependency-free, in keeping with the LiteZero simulation's standard-library
// only design.

export const X25_INIT_CRC = 0xffff;

/** Fold one byte into the running CRC (reference `crc_accumulate`). */
export function crcAccumulate(data: number, crc: number): number {
  let tmp = data ^ (crc & 0xff);
  tmp = (tmp ^ (tmp << 4)) & 0xff;
  return ((crc >> 8) ^ (tmp << 8) ^ (tmp << 3) ^ (tmp >> 4)) & 0xffff;
}

/** Accumulate every byte of `buf` into `crc`. */
export function crcAccumulateBuffer(buf: Buffer, crc: number = X25_INIT_CRC): number {
  let c = crc;
  for (const b of buf) c = crcAccumulate(b, c);
  return c;
}

/**
 * MAVLink frame checksum: the CRC over the frame bytes from the length field
 * through the end of the payload, then the per-message CRC_EXTRA byte folded in
 * last. Returns the 16-bit value (stored little-endian on the wire).
 */
export function mavlinkChecksum(headerAndPayload: Buffer, crcExtra: number): number {
  let crc = crcAccumulateBuffer(headerAndPayload, X25_INIT_CRC);
  crc = crcAccumulate(crcExtra & 0xff, crc);
  return crc;
}
