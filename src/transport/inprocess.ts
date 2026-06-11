// In-process transport pair. Used by automated attack tests and by the
// single-process demo so everything runs inside one Node process.

import { EventEmitter } from "node:events";
import type { Transport, TransportServer } from "./types.ts";

let nextEndpointId = 1;
const registry = new Map<string, InProcessServer>();

class InProcessTransport implements Transport {
  private emitter = new EventEmitter();
  private closed = false;
  peer: InProcessTransport | null = null;

  send(msg: string): void {
    if (this.closed) return;
    // Deliver asynchronously so it behaves like a real network hop.
    // We intentionally do NOT check peer.closed at delivery time: in real
    // networks a packet that has been sent keeps flying even if the remote
    // side later tears the connection down.
    const peer = this.peer;
    if (!peer) return;
    queueMicrotask(() => {
      peer.emitter.emit("message", msg);
    });
  }
  onMessage(cb: (msg: string) => void): void {
    this.emitter.on("message", cb);
  }
  onClose(cb: () => void): void {
    this.emitter.on("close", cb);
  }
  close(): void {
    if (this.closed) return;
    this.closed = true;
    // Deliver the close event asynchronously so any in-flight messages
    // queued via `send()` (also microtasks) are processed first. This
    // mirrors TCP behaviour: a FIN only takes effect after already-sent
    // bytes have been drained to the application.
    queueMicrotask(() => this.emitter.emit("close"));
    if (this.peer && !this.peer.closed) this.peer.close();
  }
}

class InProcessServer implements TransportServer {
  private listener: ((t: Transport) => void) | null = null;
  constructor(private id: string) {}

  onConnection(cb: (t: Transport) => void): void {
    this.listener = cb;
  }

  accept(): Transport {
    const server = new InProcessTransport();
    const client = new InProcessTransport();
    server.peer = client;
    client.peer = server;
    if (this.listener) this.listener(server);
    return client;
  }

  endpoint(): string {
    return `mem://${this.id}`;
  }

  close(): Promise<void> {
    registry.delete(this.id);
    return Promise.resolve();
  }
}

export function inProcessListen(): TransportServer {
  const id = String(nextEndpointId++);
  const s = new InProcessServer(id);
  registry.set(id, s);
  return s;
}

export function inProcessConnect(endpoint: string): Transport {
  const id = endpoint.replace(/^mem:\/\//, "");
  const s = registry.get(id);
  if (!s) throw new Error(`no in-process server at ${endpoint}`);
  return s.accept();
}
