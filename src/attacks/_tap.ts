// Helpers to install taps / proxies on a Transport, used only by attack
// scenarios.

import type { Transport } from "../transport/types.ts";

/**
 * Wrap a Transport so every outgoing and incoming message is also passed to
 * a callback. The wrapped object behaves exactly like the original to the
 * protocol code above it.
 */
export function tapTransport(inner: Transport, tap: (msg: string) => void): Transport {
  const outerMessageCbs: ((m: string) => void)[] = [];
  const outerCloseCbs: (() => void)[] = [];
  inner.onMessage((m) => {
    tap(m);
    for (const cb of outerMessageCbs) cb(m);
  });
  inner.onClose(() => {
    for (const cb of outerCloseCbs) cb();
  });
  return {
    send(msg) {
      tap(msg);
      inner.send(msg);
    },
    onMessage(cb) {
      outerMessageCbs.push(cb);
    },
    onClose(cb) {
      outerCloseCbs.push(cb);
    },
    close() {
      inner.close();
    },
  };
}

/**
 * Wrap a Transport with a rewriter that can modify each outbound message
 * before it is sent upstream. Inbound messages pass through unchanged.
 */
export function rewriteOutbound(
  inner: Transport,
  rewrite: (msg: string) => string,
): Transport {
  const outerMsgCbs: ((m: string) => void)[] = [];
  const outerCloseCbs: (() => void)[] = [];
  inner.onMessage((m) => outerMsgCbs.forEach((cb) => cb(m)));
  inner.onClose(() => outerCloseCbs.forEach((cb) => cb()));
  return {
    send(msg) {
      inner.send(rewrite(msg));
    },
    onMessage(cb) {
      outerMsgCbs.push(cb);
    },
    onClose(cb) {
      outerCloseCbs.push(cb);
    },
    close() {
      inner.close();
    },
  };
}
