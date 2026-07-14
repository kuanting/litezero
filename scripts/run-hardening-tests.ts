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

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

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

async function main() {
  const tests = [testRebootReplay, testCacheFailClosed];
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
