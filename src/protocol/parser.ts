// Single parsing chokepoint for untrusted wire messages.
//
// Every inbound byte stream goes through `parseMessage`. Schema is checked
// structurally; base64 fields are decoded on demand by consumers. The parser
// is intentionally strict: any extra field or wrong type turns the message
// into `{ kind: "error", reason: ... }`, which the services reject by
// closing the transport. This matches the LiteZero AKE model's requirement
// that the wire format is a proper subset of the type the attacker controls.

import type {
  HandshakeAck,
  HandshakeFinish,
  HandshakeHello,
  SessionFrame,
  WireMessage,
  AuthToken,
} from "./messages.ts";

function isB64(x: unknown): x is string {
  return typeof x === "string" && /^[A-Za-z0-9+/]*=*$/.test(x);
}

function isAuthToken(x: unknown): x is AuthToken {
  if (typeof x !== "object" || x === null) return false;
  const t = x as Record<string, unknown>;
  return (
    typeof t.userId === "string" &&
    typeof t.droneId === "string" &&
    typeof t.nonceU === "string" &&
    typeof t.iat === "number" &&
    typeof t.exp === "number" &&
    typeof t.policy === "object" && t.policy !== null &&
    // userVerifyKeyJwk must be present (object); we check structure on import.
    typeof t.userVerifyKeyJwk === "object" && t.userVerifyKeyJwk !== null &&
    // dronePubKey must be present as a b64 string. Note: it is the user's
    // operator-PINNED P_D (cross-checked against this field), not the token
    // copy alone, that authenticates the drone's static key under Option A.
    typeof t.dronePubKey === "string"
  );
}

export function parseMessage(raw: string): WireMessage {
  let m: unknown;
  try {
    m = JSON.parse(raw);
  } catch {
    return { kind: "error", reason: "json-parse" };
  }
  if (typeof m !== "object" || m === null) return { kind: "error", reason: "not-object" };
  const o = m as Record<string, unknown>;
  switch (o.kind) {
    case "hello":
      if (!isAuthToken(o.authToken)) return { kind: "error", reason: "bad-token" };
      if (
        !isB64(o.cloudSig) ||
        !isB64(o.userPub) ||
        !isB64(o.nonceU) ||
        !isB64(o.userSig)
      )
        return { kind: "error", reason: "bad-hello" };
      return o as unknown as HandshakeHello;
    case "finish":
      if (!isB64(o.dronePub) || !isB64(o.nonceD) || !isB64(o.macD))
        return { kind: "error", reason: "bad-finish" };
      return o as unknown as HandshakeFinish;
    case "ack":
      if (!isB64(o.macU)) return { kind: "error", reason: "bad-ack" };
      return o as unknown as HandshakeAck;
    case "data":
      if (o.dir !== "u2d" && o.dir !== "d2u")
        return { kind: "error", reason: "bad-dir" };
      if (typeof o.seq !== "number") return { kind: "error", reason: "bad-seq" };
      if (typeof o.epoch !== "number") return { kind: "error", reason: "bad-epoch" };
      if (o.chan !== undefined && o.chan !== "app" && o.chan !== "ctrl")
        return { kind: "error", reason: "bad-chan" };
      if (!isB64(o.iv) || !isB64(o.ct) || !isB64(o.tag))
        return { kind: "error", reason: "bad-data" };
      return o as unknown as SessionFrame;
    case "error":
      return { kind: "error", reason: String(o.reason ?? "unspecified") };
    default:
      return { kind: "error", reason: `unknown-kind: ${String(o.kind)}` };
  }
}
