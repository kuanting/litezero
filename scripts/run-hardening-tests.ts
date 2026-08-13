// Targeted regression tests for the v1.2 drone hardening (not part of the
// scored attack battery, so they do not shift the 19-scenario / 760-run
// counts). They pin two robustness properties:
//
//   1. Reboot replay: the single-use hello-nonce cache is in-memory, so a
//      restart empties it. A hello captured before the restart must still be
//      rejected on replay afterwards, because the drone refuses any token
//      whose iat predates its current boot time.
//   2. Cache fail-closed: when the live-nonce cache is at capacity the drone
//      rejects new hellos rather than evicting a live nonce (which would
//      re-open a replay window).
//
// Test 2 shrinks the cache bound via LZ_MAX_SEEN_HELLO_NONCES so it can be
// filled cheaply; the env var is set before any module that reads config is
// imported. In production the bound defaults to 4096.
export {}; // ensure this file is treated as a module (top-level await below)

process.env.LZ_MAX_SEEN_HELLO_NONCES ||= "8";

const { createPublicKey } = await import("node:crypto");
const { bootstrap, inProcessCloudClient } = await import(
  "../src/scenarios/bootstrap.ts"
);
const { runUserHandshake } = await import("../src/services/user.ts");
const { attachDrone } = await import("../src/services/drone.ts");
const { inProcessListen, inProcessConnect } = await import(
  "../src/transport/inprocess.ts"
);
const { MAX_SEEN_HELLO_NONCES } = await import("../src/config.ts");
const { tapTransport } = await import("../src/attacks/_tap.ts");
const { randomBytes } = await import("node:crypto");
type Transport = import("../src/transport/types.ts").Transport;

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

/**
 * Wrap a Transport so a test can also push synthetic INBOUND frames straight to
 * the protocol code's registered onMessage callbacks (as if the peer had sent
 * them), and observe local close(). Used by the AEAD-budget tests to feed
 * forged d2u frames into the user's receive path.
 */
function injectable(inner: Transport): Transport & {
  pushInbound: (m: string) => void;
  closed: () => boolean;
} {
  const msgCbs: ((m: string) => void)[] = [];
  const closeCbs: (() => void)[] = [];
  let isClosed = false;
  inner.onMessage((m) => msgCbs.forEach((cb) => cb(m)));
  inner.onClose(() => closeCbs.forEach((cb) => cb()));
  return {
    send: (m) => inner.send(m),
    onMessage: (cb) => msgCbs.push(cb),
    onClose: (cb) => closeCbs.push(cb),
    close: () => {
      isClosed = true;
      inner.close();
    },
    pushInbound: (m) => msgCbs.forEach((cb) => cb(m)),
    closed: () => isClosed,
  };
}

/** A syntactically valid but cryptographically bogus d2u app frame. */
function forgedD2uFrame(seq: number): string {
  return JSON.stringify({
    kind: "data",
    dir: "d2u",
    epoch: 0,
    chan: "app",
    seq,
    iv: randomBytes(12).toString("base64"),
    ct: randomBytes(16).toString("base64"),
    tag: randomBytes(16).toString("base64"),
  });
}

interface TestResult {
  name: string;
  passed: boolean;
  detail: string;
}

/**
 * Test 1: a captured hello replayed against a *rebooted* drone (same identity,
 * fresh boot time, empty nonce cache) is rejected because its token predates
 * the new boot time.
 */
async function testRebootReplay(): Promise<TestResult> {
  const h = await bootstrap();

  // Capture a valid hello from a real handshake against boot #1.
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
  session.close();
  await h.shutdown(); // power off boot #1

  // Ensure wall-clock advances so the rebooted drone's boot time is strictly
  // later than the captured token's iat.
  await sleep(5);

  // Boot #2: same drone identity (same PUF seal, cloud key, pinned user key),
  // new server, fresh boot time, empty nonce cache.
  const userPub = createPublicKey(h.userIdentity.signingKey);
  const droneServer2 = inProcessListen();
  attachDrone(
    droneServer2,
    {
      droneId: h.droneId,
      pufSeed: h.droneSeed,
      cloudVerifyKey: h.cloud.cloudKey.publicKey,
      authorizedUserKeys: new Map([[h.userIdentity.userId, userPub]]),
    },
    h.blackKey,
    h.helper,
  );

  const replayLink = inProcessConnect(droneServer2.endpoint());
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
  await droneServer2.close();

  const parsed = JSON.parse(reply) as { kind: string; reason?: string };
  const passed =
    parsed.kind === "error" && /predates drone boot/.test(parsed.reason ?? "");
  return {
    name: "reboot replay rejected (token predates boot)",
    passed,
    detail: passed
      ? `rebooted drone rejected the captured hello: ${parsed.reason}`
      : `rebooted drone did NOT reject on the boot-time gate (${parsed.reason ?? parsed.kind}) — BAD`,
  };
}

/**
 * Test 2: fill the live-nonce cache to its bound with valid handshakes, then
 * confirm the next hello is rejected fail-closed rather than evicting a live
 * nonce.
 */
async function testCacheFailClosed(): Promise<TestResult> {
  const h = await bootstrap();
  const bound = MAX_SEEN_HELLO_NONCES;

  // Fill the cache: each completed handshake burns one live nonce and, being
  // single-use across reconnects, keeps it until TTL expiry.
  for (let i = 0; i < bound; i++) {
    const s = await runUserHandshake({
      identity: h.userIdentity,
      droneId: h.droneId,
      cloud: inProcessCloudClient(h.cloud),
      link: h.connectToDrone(),
    });
    s.close();
  }

  // The next hello must be rejected on the capacity gate.
  let failure = "";
  try {
    const s = await runUserHandshake({
      identity: h.userIdentity,
      droneId: h.droneId,
      cloud: inProcessCloudClient(h.cloud),
      link: h.connectToDrone(),
    });
    s.close();
  } catch (e) {
    failure = (e as Error).message;
  }
  await h.shutdown();

  const passed = /cache full/.test(failure);
  return {
    name: `cache fail-closed at capacity (bound=${bound})`,
    passed,
    detail: passed
      ? `drone rejected the over-capacity hello: ${failure}`
      : `drone did NOT fail closed at capacity (${failure || "handshake succeeded"}) — BAD`,
  };
}

/**
 * Test 3 (send budget): with a tiny per-epoch-key cap, the (cap+1)-th send()
 * throws, and a rekey (fresh key ⇒ fresh budget) lets sending resume. Exercises
 * both the tx-cap enforcement and the rekey reset.
 */
async function testSendCapAndRekeyReset(): Promise<TestResult> {
  const prev = process.env.LZ_MAX_FRAMES_PER_EPOCH_KEY;
  process.env.LZ_MAX_FRAMES_PER_EPOCH_KEY = "4";
  try {
    const h = await bootstrap();

    // Part A: at the hard cap, the next send throws (teardown, not silent reuse).
    const sA = await runUserHandshake({
      identity: h.userIdentity, droneId: h.droneId,
      cloud: inProcessCloudClient(h.cloud), link: h.connectToDrone(),
    });
    for (let i = 0; i < 4; i++) await sA.send(Buffer.from(`f${i}`));
    let threw = "";
    try {
      await sA.send(Buffer.from("overflow"));
    } catch (e) {
      threw = (e as Error).message;
    }
    sA.close();

    // Part B: rekeying WITH headroom resets the budget so sending resumes under
    // the fresh key (a rekey consumes one control frame, so it is triggered
    // before the cap, as a deployment would).
    const sB = await runUserHandshake({
      identity: h.userIdentity, droneId: h.droneId,
      cloud: inProcessCloudClient(h.cloud), link: h.connectToDrone(),
    });
    await sB.send(Buffer.from("b0"));
    await sB.send(Buffer.from("b1"));
    await sB.rekey(); // fresh key ⇒ epochTxCount reset to 0
    let resumed = true;
    try {
      for (let i = 0; i < 4; i++) await sB.send(Buffer.from(`c${i}`));
    } catch {
      resumed = false;
    }
    sB.close();
    await h.shutdown();

    const passed = /frame cap reached/.test(threw) && resumed;
    return {
      name: "per-epoch send cap enforced; rekey resets budget",
      passed,
      detail: passed
        ? `5th send at cap rejected ("${threw}"); after rekey, 4 more sends accepted under the fresh key`
        : `cap/rekey behavior wrong (threw="${threw}", resumed=${resumed}) — BAD`,
    };
  } finally {
    if (prev === undefined) delete process.env.LZ_MAX_FRAMES_PER_EPOCH_KEY;
    else process.env.LZ_MAX_FRAMES_PER_EPOCH_KEY = prev;
  }
}

/**
 * Test 4 (receive budget + forged attempts): forged d2u frames that fail AEAD
 * still count against the per-epoch decryption-attempt budget q_d, and once the
 * cap is crossed the receiver tears the session down. Also covers the invalid-
 * seq receive guard.
 */
async function testRecvCapCountsForgedAttempts(): Promise<TestResult> {
  const prev = process.env.LZ_MAX_FRAMES_PER_EPOCH_KEY;
  process.env.LZ_MAX_FRAMES_PER_EPOCH_KEY = "5";
  try {
    const h = await bootstrap();
    const link = injectable(h.connectToDrone());
    const session = await runUserHandshake({
      identity: h.userIdentity,
      droneId: h.droneId,
      cloud: inProcessCloudClient(h.cloud),
      link,
    });

    // A malformed seq (negative, or not a safe integer) is dropped by the
    // receive guard before any counting. NOTE: a large but SAFE integer such as
    // Number.MAX_SAFE_INTEGER is now VALID (validity is decoupled from the
    // budget), so we use genuinely invalid values here.
    link.pushInbound(forgedD2uFrame(-1)); // negative
    link.pushInbound(forgedD2uFrame(2 ** 53)); // not a safe integer
    const closedAfterInvalidSeq = link.closed();

    // Six forged (AEAD-failing) frames, each a valid in-range seq: attempts
    // 1..5 are tolerated, the 6th crosses the cap of 5 and closes the session.
    for (let i = 0; i < 6; i++) link.pushInbound(forgedD2uFrame(0));
    const closedAfterCap = link.closed();

    session.close();
    await h.shutdown();

    const passed = !closedAfterInvalidSeq && closedAfterCap;
    return {
      name: "per-epoch recv cap counts forged attempts; invalid seq dropped",
      passed,
      detail: passed
        ? "out-of-range seq dropped without teardown; 6th forged attempt (>cap=5) tore the session down"
        : `budget accounting wrong (invalidSeqClosed=${closedAfterInvalidSeq}, capClosed=${closedAfterCap}) — BAD`,
    };
  } finally {
    if (prev === undefined) delete process.env.LZ_MAX_FRAMES_PER_EPOCH_KEY;
    else process.env.LZ_MAX_FRAMES_PER_EPOCH_KEY = prev;
  }
}

/**
 * Test 5 (cumulative multi-epoch sequence): with a tiny per-epoch cap, drive
 * several epochs so the MONOTONE txSeq climbs well past the cap, then confirm a
 * fresh-epoch frame whose seq exceeds the cap is still accepted and delivered.
 * This is the case the earlier budget-coupled seq validator wrongly rejected:
 * seq validity must be independent of the per-epoch AEAD budget.
 */
async function testCumulativeSeqAcrossEpochs(): Promise<TestResult> {
  const prev = process.env.LZ_MAX_FRAMES_PER_EPOCH_KEY;
  process.env.LZ_MAX_FRAMES_PER_EPOCH_KEY = "3";
  try {
    const h = await bootstrap();
    const session = await runUserHandshake({
      identity: h.userIdentity, droneId: h.droneId,
      cloud: inProcessCloudClient(h.cloud), link: h.connectToDrone(),
    });

    // epoch 0: two app frames (seq 0,1), then two rekeys (seq 2,3). After this
    // the monotone txSeq is 4 > cap=3, but each epoch's budget was reset.
    await session.send(Buffer.from("f0"));
    await session.send(Buffer.from("f1"));
    await session.rekey();
    await session.rekey();

    // This app frame carries seq >= 4 (> cap). Budget-coupled validation would
    // reject it as "invalid seq"; decoupled validation accepts and delivers it.
    let delivered = false;
    await new Promise<void>((resolve) => {
      const t = setTimeout(resolve, 1000); // bound the wait; failure ⇒ not delivered
      session.onFrame(() => { delivered = true; clearTimeout(t); resolve(); });
      void session.send(Buffer.from("PING"));
    });

    session.close();
    await h.shutdown();

    return {
      name: "cumulative seq past cap across rekeys still delivered",
      passed: delivered,
      detail: delivered
        ? "a fresh-epoch frame with seq > cap (cumulative monotone txSeq) was accepted and delivered"
        : "fresh-epoch frame with seq > cap was rejected — seq validity still coupled to the budget — BAD",
    };
  } finally {
    if (prev === undefined) delete process.env.LZ_MAX_FRAMES_PER_EPOCH_KEY;
    else process.env.LZ_MAX_FRAMES_PER_EPOCH_KEY = prev;
  }
}

async function main() {
  const tests = [
    testRebootReplay,
    testCacheFailClosed,
    testSendCapAndRekeyReset,
    testRecvCapCountsForgedAttempts,
    testCumulativeSeqAcrossEpochs,
  ];
  const results: TestResult[] = [];
  for (const t of tests) results.push(await t());

  console.log("LiteZero drone-hardening regression tests");
  console.log("-------------------------------------------------------------");
  let allPass = true;
  for (const r of results) {
    const tag = r.passed ? "\x1b[32mPASS\x1b[0m" : "\x1b[31mFAIL\x1b[0m";
    console.log(`${tag}  ${r.name}`);
    console.log(`      ${r.detail}`);
    allPass &&= r.passed;
  }
  console.log("-------------------------------------------------------------");
  console.log(`${results.filter((r) => r.passed).length}/${results.length} hardening tests passed`);
  console.log("=============================================================");
  if (!allPass) process.exit(1);
}

await main();
