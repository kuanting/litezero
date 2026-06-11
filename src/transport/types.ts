// Transport abstraction: a duplex channel that moves JSON-encoded strings.
//
// The protocol code depends only on this interface, so we can swap in an
// in-process transport (for automated tests) or a WebSocket transport
// (for the multi-process demo) without changing any protocol logic.

export interface Transport {
  send(msg: string): void;
  onMessage(cb: (msg: string) => void): void;
  onClose(cb: () => void): void;
  close(): void;
}

export interface TransportServer {
  onConnection(cb: (t: Transport) => void): void;
  endpoint(): string;
  close(): Promise<void>;
}
