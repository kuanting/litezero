// Replay attacks — two variants.
//
// A. replay a stale (expired) AuthToken after its TTL has passed,
// B. replay a previously-captured session frame.

import {
  bootstrap,
  inProcessCloudClient,
} from "../scenarios/bootstrap.ts";
import { runUserHandshake } from "../services/user.ts";
import {
  ephemeralEcdh,
  randBytes,
  sha256,
  signEcdsa,
} from "../crypto/primitives.ts";
import { canonicalToken, helloSigDigest } from "../protocol/litezero.ts";
import { tapTransport } from "./_tap.ts";
import type { AttackResult } from "./types.ts";

export async function attackReplayToken(): Promise<AttackResult> {
  const h = await bootstrap();

  // Get a genuine, cloud-signed token for the real user...
  const nonceU = randBytes(16).toString("base64");
  const ts = Date.now();
  const authMsg = sha256(
    Buffer.from(`${h.userIdentity.userId}|${h.droneId}|${nonceU}|${ts}`, "utf8"),
  );
  const authSig = signEcdsa(h.userIdentity.signingKey, authMsg).toString("base64");
  const signed = await h.cloud.authorize({
    userId: h.userIdentity.userId,
    droneId: h.droneId,
    nonceU,
    ts,
    userSig: authSig,
  });

  // ...then age it into the past and RE-SIGN it with the cloud's real key, so
  // the drone's cloud-signature check PASSES and the *expiry* check is the sole
  // thing that can reject it. (This is the branch the previous version of this
  // test never reached — it mutated exp without re-signing, so the drone bailed
  // at the signature check instead.) We build a fully valid hello around the
  // expired token so nothing but the TTL is wrong.
  const expiredToken = {
    ...signed.token,
    iat: Date.now() - 40_000,
    exp: Date.now() - 1_000,
  };
  const tokenBytes = canonicalToken(expiredToken);
  const cloudSig = signEcdsa(h.cloud.cloudKey.privateKey, tokenBytes).toString("base64");
  const eph = ephemeralEcdh();
  const nonceUBuf = Buffer.from(expiredToken.nonceU, "base64");
  const helloDigest = helloSigDigest(tokenBytes, eph.pub, nonceUBuf);
  const userSig = signEcdsa(h.userIdentity.signingKey, helloDigest).toString("base64");

  const link = h.connectToDrone();
  let reply = "";
  const doneP = new Promise<void>((resolve) => {
    link.onMessage((s) => {
      reply = s;
      resolve();
    });
    link.onClose(() => resolve());
  });
  link.send(
    JSON.stringify({
      kind: "hello",
      authToken: expiredToken,
      cloudSig,
      userPub: eph.pub.toString("base64"),
      nonceU: expiredToken.nonceU,
      userSig,
    }),
  );
  await doneP;
  link.close();
  await h.shutdown();

  const parsed = JSON.parse(reply) as { kind: string; reason?: string };
  // This leg exists specifically to exercise the token-expiry branch, so we
  // require BOTH that no session opened AND that the rejection is the expiry
  // check — otherwise the test would silently pass on some earlier check
  // without ever validating TTL enforcement.
  const defended = parsed.kind === "error" && /expired/i.test(parsed.reason ?? "");
  return {
    name: "replay of expired / tampered auth token",
    defended,
    detail: defended
      ? `drone rejected the validly-signed but expired token: ${parsed.reason}`
      : `expiry not enforced as expected (kind=${parsed.kind}, reason=${parsed.reason})`,
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
