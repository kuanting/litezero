// Minimal RFC 6455 WebSocket server + client implemented on top of Node's
// built-in `http` module. Supports text frames only, which is all the
// LiteZero wire protocol needs.
//
// We intentionally avoid the `ws` npm package so this simulation has zero
// runtime dependencies and runs immediately after `git clone` without
// `npm install`.

import http from "node:http";
import net from "node:net";
import { createHash, randomBytes } from "node:crypto";
import { EventEmitter } from "node:events";
import type { Transport, TransportServer } from "./types.ts";

const WS_MAGIC = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

function acceptKey(clientKey: string): string {
  return createHash("sha1").update(clientKey + WS_MAGIC).digest("base64");
}

/* ------------------------------------------------------------------ */
/* Frame encode / decode (text-only, FIN always true)                  */
/* ------------------------------------------------------------------ */

function encodeTextFrame(payload: Buffer, mask: boolean): Buffer {
  const len = payload.length;
  const header: number[] = [0x81]; // FIN + text opcode
  let extraLen: Buffer;
  if (len < 126) {
    header.push((mask ? 0x80 : 0) | len);
    extraLen = Buffer.alloc(0);
  } else if (len < 0x10000) {
    header.push((mask ? 0x80 : 0) | 126);
    extraLen = Buffer.alloc(2);
    extraLen.writeUInt16BE(len, 0);
  } else {
    header.push((mask ? 0x80 : 0) | 127);
    extraLen = Buffer.alloc(8);
    extraLen.writeBigUInt64BE(BigInt(len), 0);
  }
  const maskKey = mask ? randomBytes(4) : Buffer.alloc(0);
  const body = mask
    ? Buffer.from(payload.map((b, i) => b ^ maskKey[i % 4]))
    : payload;
  return Buffer.concat([Buffer.from(header), extraLen, maskKey, body]);
}

interface DecodedFrame {
  opcode: number;
  payload: Buffer;
  consumed: number;
}

function tryDecodeFrame(buf: Buffer): DecodedFrame | null {
  if (buf.length < 2) return null;
  const b0 = buf[0];
  const b1 = buf[1];
  const opcode = b0 & 0x0f;
  const masked = (b1 & 0x80) !== 0;
  let length = b1 & 0x7f;
  let offset = 2;
  if (length === 126) {
    if (buf.length < offset + 2) return null;
    length = buf.readUInt16BE(offset);
    offset += 2;
  } else if (length === 127) {
    if (buf.length < offset + 8) return null;
    length = Number(buf.readBigUInt64BE(offset));
    offset += 8;
  }
  const maskKey = masked ? buf.subarray(offset, offset + 4) : null;
  if (masked) offset += 4;
  if (buf.length < offset + length) return null;
  let payload = buf.subarray(offset, offset + length);
  if (maskKey) {
    const out = Buffer.alloc(length);
    for (let i = 0; i < length; i++) out[i] = payload[i] ^ maskKey[i % 4];
    payload = out;
  }
  return { opcode, payload: Buffer.from(payload), consumed: offset + length };
}

/* ------------------------------------------------------------------ */
/* WsSocket implements Transport                                       */
/* ------------------------------------------------------------------ */

class WsSocket extends EventEmitter implements Transport {
  private closed = false;
  private buf = Buffer.alloc(0);

  constructor(private sock: net.Socket, private isClient: boolean) {
    super();
    sock.on("data", (chunk) => this.onData(chunk));
    sock.on("close", () => this.emit("_close"));
    sock.on("error", () => this.emit("_close"));
  }

  private onData(chunk: Buffer): void {
    this.buf = Buffer.concat([this.buf, chunk]);
    while (true) {
      const f = tryDecodeFrame(this.buf);
      if (!f) break;
      this.buf = this.buf.subarray(f.consumed);
      if (f.opcode === 0x8) {
        this.close();
      } else if (f.opcode === 0x1 || f.opcode === 0x2) {
        this.emit("_msg", f.payload.toString("utf8"));
      }
    }
  }

  send(msg: string): void {
    if (this.closed) return;
    const payload = Buffer.from(msg, "utf8");
    this.sock.write(encodeTextFrame(payload, this.isClient));
  }
  onMessage(cb: (msg: string) => void): void {
    this.on("_msg", cb);
  }
  onClose(cb: () => void): void {
    this.on("_close", cb);
  }
  close(): void {
    if (this.closed) return;
    this.closed = true;
    try {
      this.sock.write(Buffer.from([0x88, 0x00])); // close frame
    } catch {
      /* ignore */
    }
    this.sock.end();
    this.emit("_close");
  }
}

/* ------------------------------------------------------------------ */
/* Server                                                             */
/* ------------------------------------------------------------------ */

export function wsListen(port = 0): Promise<TransportServer & { port: number }> {
  return new Promise((resolve) => {
    const listener = new EventEmitter();
    const server = http.createServer();

    server.on("upgrade", (req, sock, head) => {
      const key = req.headers["sec-websocket-key"];
      if (!key || typeof key !== "string") {
        sock.destroy();
        return;
      }
      void head; // unused
      const accept = acceptKey(key);
      sock.write(
        "HTTP/1.1 101 Switching Protocols\r\n" +
          "Upgrade: websocket\r\n" +
          "Connection: Upgrade\r\n" +
          `Sec-WebSocket-Accept: ${accept}\r\n\r\n`,
      );
      const t = new WsSocket(sock as net.Socket, false);
      listener.emit("connection", t);
    });

    server.listen(port, () => {
      const addr = server.address();
      const actualPort = typeof addr === "object" && addr ? addr.port : 0;
      const srv: TransportServer & { port: number } = {
        port: actualPort,
        endpoint: () => `ws://127.0.0.1:${actualPort}`,
        onConnection: (cb) => {
          listener.on("connection", cb);
        },
        close: () =>
          new Promise((r) => {
            server.close(() => r());
          }),
      };
      resolve(srv);
    });
  });
}

/* ------------------------------------------------------------------ */
/* Client                                                             */
/* ------------------------------------------------------------------ */

export function wsConnect(url: string): Promise<Transport> {
  const u = new URL(url);
  const key = randomBytes(16).toString("base64");

  return new Promise((resolve, reject) => {
    const req = http.request({
      host: u.hostname,
      port: Number(u.port),
      method: "GET",
      path: u.pathname + u.search,
      headers: {
        Connection: "Upgrade",
        Upgrade: "websocket",
        "Sec-WebSocket-Key": key,
        "Sec-WebSocket-Version": "13",
      },
    });
    req.on("error", reject);
    req.on("upgrade", (res, sock) => {
      const expected = acceptKey(key);
      if (res.headers["sec-websocket-accept"] !== expected) {
        sock.destroy();
        reject(new Error("bad handshake"));
        return;
      }
      resolve(new WsSocket(sock as net.Socket, true));
    });
    req.end();
  });
}
