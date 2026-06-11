// Run every attack scenario and print a PASS/FAIL summary.
//
// PASS means the system *defended* against the attack.
// FAIL means the attack broke security (and the simulation flags it).
//
// The battery is the operational half of Section VII of the LiteZero paper.
// Each defended outcome ties back to a specific invariant of the security
// proof (see Section V and Table II in the paper).

import { attackEavesdrop } from "../src/attacks/eavesdrop.ts";
import { attackMitm } from "../src/attacks/mitm.ts";
import { attackReplayToken, attackReplayFrame } from "../src/attacks/replay.ts";
import { attackSpoofDrone } from "../src/attacks/spoof-drone.ts";
import { attackStolenCloudDb } from "../src/attacks/stolen-verifier.ts";
import { attackCapturedDrone } from "../src/attacks/captured-drone.ts";
import { attackKci } from "../src/attacks/kci.ts";
import { attackUks } from "../src/attacks/uks.ts";
import { attackForwardSecrecy } from "../src/attacks/forward-secrecy.ts";
import { attackPostCompromise } from "../src/attacks/post-compromise.ts";
import { attackDesyncDos } from "../src/attacks/desync-dos.ts";
import { attackStolenCloudKey } from "../src/attacks/stolen-cloud-key.ts";
import { attackTokenBearer } from "../src/attacks/token-bearer.ts";
import {
  attackHelloReplay,
  attackPreAckInjection,
  attackStaleEpochAfterRekey,
  attackForgedRefresh,
} from "../src/attacks/continuous-verification.ts";
import { attackMavlinkInjection } from "../src/attacks/mavlink-injection.ts";
import type { AttackResult } from "../src/attacks/types.ts";

const runners: Array<() => Promise<AttackResult>> = [
  attackEavesdrop,
  attackMitm,
  attackReplayToken,
  attackReplayFrame,
  attackSpoofDrone,
  attackStolenCloudDb,
  attackStolenCloudKey, // v2: stolen sk_C alone must not let attacker start a future session
  attackTokenBearer,    // v2: captured token must not be reusable with attacker-chosen E_U
  attackCapturedDrone,
  attackKci,
  attackUks,
  attackForwardSecrecy,
  attackPostCompromise,
  attackDesyncDos,
  attackHelloReplay,           // v1.1: hello replay within TTL blocked by single-use nonce
  attackPreAckInjection,       // v1.1: no data actioned before tau_U confirms the session
  attackStaleEpochAfterRekey,  // v2 cont-verify: retired-epoch frame rejected after rekey
  attackForgedRefresh,         // v2 cont-verify: only cloud-signed refresh/policy is applied
  attackMavlinkInjection,      // MAVLink: raw forged command rejected; no plaintext C2 on the wire
];

// Independent repetitions per scenario. Every repetition draws fresh
// keys/nonces, so 40 runs exercise 40 independent protocol instances.
const ATTACK_RUNS = Math.max(1, Number(process.env.ATTACK_RUNS ?? 40));

async function main() {
  process.stdout.write(`[attack-suite] starting (${ATTACK_RUNS} runs per scenario)\n`);
  const results: Array<AttackResult & { okRuns: number }> = [];
  for (const r of runners) {
    process.stdout.write(`[attack-suite] running ${r.name} ...\n`);
    let okRuns = 0;
    let last: AttackResult = { name: r.name, defended: false, detail: "did not run" };
    let firstFail: AttackResult | null = null;
    for (let i = 0; i < ATTACK_RUNS; i++) {
      try {
        last = await r();
      } catch (e) {
        last = {
          name: r.name,
          defended: false,
          detail: `scenario threw: ${(e as Error).message}`,
        };
      }
      if (last.defended) okRuns++;
      else if (!firstFail) firstFail = last;
    }
    const report = firstFail ?? last;
    results.push({ ...report, defended: okRuns === ATTACK_RUNS, okRuns });
  }

  console.log("\n================== LiteZero attack battery ==================");
  let pass = 0;
  for (const r of results) {
    const tag = r.defended ? "\u001b[32mPASS\u001b[0m" : "\u001b[31mFAIL\u001b[0m";
    console.log(`${tag}  ${r.name}  [${r.okRuns}/${ATTACK_RUNS} runs defended]`);
    console.log(`      ${r.detail}`);
    if (r.defended) pass++;
  }
  const totalOk = results.reduce((s, r) => s + r.okRuns, 0);
  console.log(`-------------------------------------------------------------`);
  console.log(`${pass}/${results.length} attacks defended`);
  console.log(`${totalOk}/${results.length * ATTACK_RUNS} individual runs defended`);
  console.log(`=============================================================\n`);

  process.exit(pass === results.length ? 0 : 1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
