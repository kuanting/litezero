// Replay attacks — two variants.
//
// A. replay a stale (expired) AuthToken after its TTL has passed,
// B. replay a previously-captured session frame.

import {
  bootstrap,
  inProcessCloudClient,
} from "../scenarios/bootstrap.ts";
import { runUserHandshake } from "../services/user.ts";
import { randBytes, sha256, signEcdsa } from "../crypto/primitives.ts";
import { tapTransport } from "./_tap.ts";
import type { AttackResult } from "./types.ts";

export async function attackReplayToken(): Promise<AttackResult> {
  const h = await bootstrap();

  const nonceU = randBytes(16).toString("base64");
  const ts = Date.now();
  const msg = sha256(
    Buffer.from(`${h.userIdentity.userId}|${h.droneId}|${nonceU}|${ts}`, "utf8"),
  );
  const userSig = signEcdsa(h.userIdentity.signingKey, msg).toString("base64");
  const signed = await h.cloud.authorize({
    userId: h.userIdentity.userId,
    droneId: h.droneId,
    nonceU,
    ts,
    userSig,
  });

  // Force-expire the token. The cloud signature no longer covers the new
  // field values, which the drone will catch.
  const badToken = { ...signed, token: { ...signed.token, exp: Date.now() - 1 } };

  const link = h.connectToDrone();
  let reply = "";
  const doneP = new Promise<void>((resolve) => {
    link.onMessage((s) => {
      reply = s;
      resolve();
    });
  });
  link.send(
    JSON.stringify({
      kind: "hello",
      authToken: badToken.token,
      cloudSig: badToken.cloudSig,
      userPub: randBytes(65).toString("base64"),
      nonceU,
    }),
  );
  await doneP;
  link.close();
  await h.shutdown();

  const parsed = JSON.parse(reply) as { kind: string; reason?: string };
  const defended = parsed.kind === "error";
  return {
    name: "replay of expired / tampered auth token",
    defended,
    detail: defended
      ? `drone rejected: ${parsed.reason}`
      : "drone accepted an expired token — BAD",
  };
}

export async function attackReplayFrame(): Promise<AttackResult> {
  const h = await bootstrap();

  // Tap captures the first u2d data frame the user sends.
  let capturedFrame: string | null = null;
  const tapped = tapTransport(h.connectToDrone(), (raw) => {
    try {
      const m = JSON.parse(raw);
      if (m.kind === "data" && m.dir === "u2d" && capturedFrame == null) {
        capturedFrame = raw;
      }
    } catch {
      /* ignore */
    }
  });

  const session = await runUserHandshake({
    identity: h.userIdentity,
    droneId: h.droneId,
    cloud: inProcessCloudClient(h.cloud),
    link: tapped,
  });
  await new Promise<void>((resolve) => {
    session.onFrame(() => resolve());
    void session.send(Buffer.from("ARM"));
  });

  // Now replay the captured frame on a fresh connection — the drone has no
  // session state on the new link so it must reject it.
  const replayLink = h.connectToDrone();
  let reply = "";
  const doneP = new Promise<void>((resolve) => {
    replayLink.onMessage((s) => {
      reply = s;
      resolve();
    });
  });
  replayLink.send(capturedFrame!);
  await doneP;
  replayLink.close();

  session.close();
  await h.shutdown();

  const parsed = JSON.parse(reply) as { kind: string; reason?: string };
  const defended = parsed.kind === "error";
  return {
    name: "replay of captured session frame",
    defended,
    detail: defended
      ? `drone rejected: ${parsed.reason}`
      : "drone accepted a replayed session frame — BAD",
  };
}
