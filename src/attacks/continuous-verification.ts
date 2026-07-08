// Attack scenarios for the v1.1 hardening and the in-band continuous
// verification layer (token refresh, epoch rekey, policy push).
//
// Each scenario actually mounts the attack against the live protocol engine —
// no rigged setup — and PASSES only when the drone/user rejects it.

import { bootstrap, inProcessCloudClient } from "../scenarios/bootstrap.ts";
import { runUserHandshake } from "../services/user.ts";
import { randBytes, sha256, signEcdsa } from "../crypto/primitives.ts";
import { tapTransport } from "./_tap.ts";
import type { AttackResult } from "./types.ts";

/**
 * A. Hello replay within TTL. A captured-but-valid hello is replayed on a fresh
 * connection before the token expires. The drone's single-use nonce cache must
 * reject it (G3) rather than spend a PUF unwrap + two scalar mults on it.
 */
export async function attackHelloReplay(): Promise<AttackResult> {
  const h = await bootstrap();

  // Capture the legitimate hello the user sends.
  let capturedHello: string | null = null;
  const tapped = tapTransport(h.connectToDrone(), (raw) => {
    try {
      const m = JSON.parse(raw);
      if (m.kind === "hello" && capturedHello == null) capturedHello = raw;
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

  // Replay the captured hello on a new link while its token is still valid.
  const replayLink = h.connectToDrone();
  let reply = "";
  const doneP = new Promise<void>((resolve) => {
    replayLink.onMessage((s) => {
      reply = s;
      resolve();
    });
  });
  replayLink.send(capturedHello!);
  await doneP;
  replayLink.close();
  session.close();
  await h.shutdown();

  const parsed = JSON.parse(reply) as { kind: string; reason?: string };
  const defended = parsed.kind === "error" && /replay|nonce/.test(parsed.reason ?? "");
  return {
    name: "hello replay within TTL (single-use nonce)",
    defended,
    detail: defended
      ? `drone rejected replayed hello: ${parsed.reason}`
      : `drone accepted a replayed hello (${parsed.reason ?? parsed.kind}) — BAD`,
  };
}

/**
 * B. Pre-ack data injection. After a hello, the drone derives keys but must NOT
 * open the session until tau_U verifies. An attacker who guesses/forges a data
 * frame before the ack must be rejected with "no session".
 */
export async function attackPreAckInjection(): Promise<AttackResult> {
  const h = await bootstrap();

  // Drive the handshake manually up to (but not including) the ack so we can
  // inject a data frame in the half-open window.
  let finishSeen = false;
  let reply = "";
  const link = h.connectToDrone();
  const doneP = new Promise<void>((resolve) => {
    link.onMessage((s) => {
      const m = JSON.parse(s) as { kind: string; reason?: string };
      if (m.kind === "finish" && !finishSeen) {
        finishSeen = true;
        // Inject a data frame BEFORE sending ack.
        link.send(
          JSON.stringify({
            kind: "data",
            dir: "u2d",
            epoch: 0,
            chan: "app",
            seq: 0,
            iv: randBytes(12).toString("base64"),
            ct: randBytes(16).toString("base64"),
            tag: randBytes(16).toString("base64"),
          }),
        );
        return;
      }
      if (m.kind === "error") {
        reply = s;
        resolve();
      }
    });
  });

  // Build a valid hello via the real user path but over a tapped link that we
  // also control; simplest is to authorize + sign like the user does.
  const nonceU = randBytes(16);
  const ts = Date.now();
  const authMsg = sha256(
    Buffer.from(
      `${h.userIdentity.userId}|${h.droneId}|${nonceU.toString("base64")}|${ts}`,
      "utf8",
    ),
  );
  const authSig = signEcdsa(h.userIdentity.signingKey, authMsg).toString("base64");
  const signed = await h.cloud.authorize({
    userId: h.userIdentity.userId,
    droneId: h.droneId,
    nonceU: nonceU.toString("base64"),
    ts,
    userSig: authSig,
  });
  // Reuse the user handshake's hello construction by importing its helpers
  // indirectly: sign the hello digest the drone expects.
  const { canonicalToken, helloSigDigest } = await import("../protocol/litezero.ts");
  const { ephemeralEcdh } = await import("../crypto/primitives.ts");
  const eph = ephemeralEcdh();
  const tokenBytes = canonicalToken(signed.token);
  const userSig = signEcdsa(
    h.userIdentity.signingKey,
    helloSigDigest(tokenBytes, eph.pub, nonceU),
  ).toString("base64");
  link.send(
    JSON.stringify({
      kind: "hello",
      authToken: signed.token,
      cloudSig: signed.cloudSig,
      userPub: eph.pub.toString("base64"),
      nonceU: nonceU.toString("base64"),
      userSig,
    }),
  );

  await doneP;
  link.close();
  await h.shutdown();

  const parsed = JSON.parse(reply) as { kind: string; reason?: string };
  const defended = parsed.kind === "error" && /no session/.test(parsed.reason ?? "");
  return {
    name: "pre-ack data injection (session not yet confirmed)",
    defended,
    detail: defended
      ? `drone rejected pre-ack frame: ${parsed.reason}`
      : `drone accepted data before ack (${parsed.reason ?? parsed.kind}) — BAD`,
  };
}

/**
 * C. Stale-epoch frame after rekey. A frame captured under epoch n is replayed
 * after the session ratchets to epoch n+1. The old key is retired, so the
 * drone must reject it on the epoch gate / AEAD check (intra-session FS).
 */
export async function attackStaleEpochAfterRekey(): Promise<AttackResult> {
  const h = await bootstrap();

  let captured: string | null = null;
  const tapped = tapTransport(h.connectToDrone(), (raw) => {
    try {
      const m = JSON.parse(raw);
      if (m.kind === "data" && m.dir === "u2d" && m.epoch === 0 && captured == null) {
        captured = raw;
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

  // Send one epoch-0 frame (captured by the tap), then rekey to epoch 1.
  await new Promise<void>((resolve) => {
    session.onFrame(() => resolve());
    void session.send(Buffer.from("ARM"));
  });
  await session.rekey();

  // Replay the captured epoch-0 frame on a fresh link. (Fresh link → "no
  // session" also defends; to test the epoch gate specifically we instead
  // replay over the SAME live session link.)
  let reply = "";
  const doneP = new Promise<void>((resolve) => {
    tapped.onMessage((s) => {
      const m = JSON.parse(s) as { kind: string; reason?: string };
      if (m.kind === "error") {
        reply = s;
        resolve();
      }
    });
  });
  tapped.send(captured!);
  const timeout = new Promise<void>((resolve) => setTimeout(resolve, 200));
  await Promise.race([doneP, timeout]);
  session.close();
  await h.shutdown();

  // Defended if the drone errored on the epoch/AEAD gate, OR silently dropped
  // it (no reply) — either way the stale frame was not actioned. We assert the
  // explicit-error path since the drone aborts on a same-session bad frame.
  const defended = reply !== "" && /epoch|aead|replay|seq/.test(
    (JSON.parse(reply) as { reason?: string }).reason ?? "",
  );
  return {
    name: "stale-epoch frame replayed after rekey",
    defended,
    detail: defended
      ? `drone rejected retired-epoch frame: ${(JSON.parse(reply) as { reason?: string }).reason}`
      : "drone actioned a retired-epoch frame — BAD",
  };
}

/**
 * D. In-band refresh and forged-policy handling. This scenario checks two
 * continuous-verification properties on a live session:
 *   1. a genuine cloud-signed refresh keeps the session usable (commands still
 *      flow after it), and
 *   2. a forged (badly-signed) policy push that tries to revoke control scope
 *      is ignored, so commands keep working.
 * Both are non-fatal control-plane operations; the session must stay open and
 * behave correctly in each case.
 */
export async function attackForgedRefresh(): Promise<AttackResult> {
  const h = await bootstrap();
  const session = await runUserHandshake({
    identity: h.userIdentity,
    droneId: h.droneId,
    cloud: inProcessCloudClient(h.cloud),
    link: h.connectToDrone(),
  });

  // A genuine refresh must keep the session usable.
  await session.refresh();
  const ok = await new Promise<boolean>((resolve) => {
    let done = false;
    session.onFrame(() => {
      if (!done) {
        done = true;
        resolve(true);
      }
    });
    void session.send(Buffer.from("STATUS"));
    setTimeout(() => {
      if (!done) resolve(false);
    }, 200);
  });

  // A forged policy push (bad signature) revoking control must be rejected, so
  // commands keep working.
  await session.applyPolicy({ scope: [], ts: Date.now(), sig: randBytes(64).toString("base64") });
  const stillWorks = await new Promise<boolean>((resolve) => {
    let done = false;
    session.onFrame(() => {
      if (!done) {
        done = true;
        resolve(true);
      }
    });
    void session.send(Buffer.from("STATUS2"));
    setTimeout(() => {
      if (!done) resolve(false);
    }, 200);
  });

  session.close();
  await h.shutdown();

  const defended = ok && stillWorks;
  return {
    name: "in-band refresh accepted; forged policy push rejected",
    defended,
    detail: defended
      ? "genuine refresh kept session live; unsigned policy revoke was ignored"
      : `refresh/policy handling wrong (refreshOk=${ok}, afterForgedPolicy=${stillWorks}) — BAD`,
  };
}
