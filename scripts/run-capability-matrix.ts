// Capability matrix runner.
//
// Runs every scenario in src/attacks/, maps the outcome onto the
// (capability-subset x goal) taxonomy in src/attacks/capabilities.ts, and
// prints:
//
//   1. a per-scenario PASS/FAIL table keyed by (capabilities -> goal),
//   2. a coverage table showing which (expected-defense, goal) cells are
//      exercised and which are not.
//
// A non-zero exit status means either (a) a scenario's actual outcome
// disagreed with its expected outcome, or (b) an EXPECTED_DEFENSES entry
// is not covered by any scenario. Both are signals that the battery is
// incomplete, not that the protocol is broken.

import { attackEavesdrop } from "../src/attacks/eavesdrop.ts";
import { attackMitm } from "../src/attacks/mitm.ts";
import { attackReplayToken, attackReplayFrame } from "../src/attacks/replay.ts";
import { attackSpoofDrone } from "../src/attacks/spoof-drone.ts";
import { attackStolenCloudDb } from "../src/attacks/stolen-verifier.ts";
import { attackStolenCloudKey } from "../src/attacks/stolen-cloud-key.ts";
import { attackTokenBearer } from "../src/attacks/token-bearer.ts";
import { attackCapturedDrone } from "../src/attacks/captured-drone.ts";
import { attackKci } from "../src/attacks/kci.ts";
import { attackUks } from "../src/attacks/uks.ts";
import { attackForwardSecrecy } from "../src/attacks/forward-secrecy.ts";
import { attackPostCompromise } from "../src/attacks/post-compromise.ts";
import { attackDesyncDos } from "../src/attacks/desync-dos.ts";
import { attackReplayAndTamper } from "../src/attacks/replay-and-tamper.ts";
import { attackPowerfulAttacker } from "../src/attacks/powerful-attacker.ts";
import {
  attackHelloReplay,
  attackPreAckInjection,
  attackStaleEpochAfterRekey,
  attackForgedRefresh,
} from "../src/attacks/continuous-verification.ts";
import { attackMavlinkInjection } from "../src/attacks/mavlink-injection.ts";
import type { AttackResult } from "../src/attacks/types.ts";

import {
  COVERAGE,
  EXPECTED_DEFENSES,
  CONCEDED,
  type Capability,
  type Goal,
} from "../src/attacks/capabilities.ts";

type Runner = () => Promise<AttackResult>;

// Map scenario NAME (in capabilities.ts) -> runner function.
const runners: Record<string, Runner> = {
  eavesdrop: attackEavesdrop,
  mitm: attackMitm,
  "replay-token": attackReplayToken,
  "replay-frame": attackReplayFrame,
  "spoof-drone": attackSpoofDrone,
  "stolen-cloud-db": attackStolenCloudDb,
  "stolen-cloud-key": attackStolenCloudKey,
  "token-bearer": attackTokenBearer,
  "captured-drone": attackCapturedDrone,
  kci: attackKci,
  uks: attackUks,
  "forward-secrecy": attackForwardSecrecy,
  "post-compromise": attackPostCompromise,
  "desync-dos": attackDesyncDos,
  "replay-and-tamper": attackReplayAndTamper,
  "powerful-attacker": attackPowerfulAttacker,
  "hello-replay": attackHelloReplay,
  "pre-ack-injection": attackPreAckInjection,
  "stale-epoch-rekey": attackStaleEpochAfterRekey,
  "forged-refresh": attackForgedRefresh,
  "mavlink-injection": attackMavlinkInjection,
};

const GREEN = "\u001b[32m";
const RED = "\u001b[31m";
const YELLOW = "\u001b[33m";
const DIM = "\u001b[2m";
const RESET = "\u001b[0m";

function capsSig(caps: Capability[]): string {
  return [...caps].sort().join("|");
}

async function main(): Promise<void> {
  process.stdout.write("[capability-matrix] running scenarios...\n");
  const results: Record<string, AttackResult> = {};
  for (const entry of COVERAGE) {
    const runner = runners[entry.scenario];
    if (!runner) {
      process.stdout.write(
        `${YELLOW}[skip]${RESET} no runner registered for "${entry.scenario}"\n`,
      );
      continue;
    }
    process.stdout.write(`  running ${entry.scenario}...\n`);
    try {
      results[entry.scenario] = await runner();
    } catch (e) {
      results[entry.scenario] = {
        name: entry.scenario,
        defended: false,
        detail: `runner threw: ${(e as Error).message}`,
      };
    }
  }

  /* --------------- Table 1: per-scenario outcome -------------------- */

  console.log("\n============== Capability-matrix scenario outcomes ==============");
  let allPassed = true;
  for (const entry of COVERAGE) {
    const r = results[entry.scenario];
    if (!r) continue;
    const tag = r.defended ? `${GREEN}PASS${RESET}` : `${RED}FAIL${RESET}`;
    const caps = entry.capabilities.join(", ");
    const goals = Object.keys(entry.expect).join(", ");
    console.log(`${tag}  ${entry.scenario}`);
    console.log(`      ${DIM}capabilities:${RESET} ${caps}`);
    console.log(`      ${DIM}goals probed:${RESET} ${goals}`);
    console.log(`      ${DIM}detail:${RESET} ${r.detail}`);
    if (!r.defended) allPassed = false;
  }
  console.log("================================================================\n");

  /* --------------- Table 2: coverage of EXPECTED_DEFENSES ---------- */

  console.log("============== Expected-defense coverage =======================");
  const defendedSigs = new Set<string>();
  for (const entry of COVERAGE) {
    const r = results[entry.scenario];
    if (!r || !r.defended) continue;
    for (const g of Object.keys(entry.expect) as Goal[]) {
      if (entry.expect[g] === "holds") {
        defendedSigs.add(`${capsSig(entry.capabilities)}|${g}`);
      }
    }
  }
  let allCovered = true;
  for (const ed of EXPECTED_DEFENSES) {
    const sig = `${capsSig(ed.capabilities)}|${ed.goal}`;
    // Covered if some scenario's capability set is a SUBSET of ed.capabilities
    // and covers the goal as "holds". Subset because a weaker attacker
    // defending against the stronger goal is not sufficient; we need a
    // scenario at least as strong as ed.
    let covered = defendedSigs.has(sig);
    if (!covered) {
      for (const entry of COVERAGE) {
        const r = results[entry.scenario];
        if (!r?.defended) continue;
        // Scenario attacker is at least as strong as the expected-defense
        // attacker, i.e. scenario.capabilities is a SUPERSET of ed.capabilities.
        const isSuperset = ed.capabilities.every((c) =>
          entry.capabilities.includes(c),
        );
        if (isSuperset && entry.expect[ed.goal] === "holds") {
          covered = true;
          break;
        }
      }
    }
    const tag = covered ? `${GREEN}COVERED${RESET}` : `${YELLOW}GAP${RESET}`;
    console.log(`${tag}  ${ed.capabilities.join(" + ")}  =>  ${ed.goal}`);
    console.log(`       ${DIM}${ed.rationale}${RESET}`);
    if (!covered) allCovered = false;
  }
  console.log("================================================================\n");

  /* --------------- Table 3: conceded cases (informational) --------- */

  console.log("============== Conceded cases (inherent to threat model) =======");
  for (const c of CONCEDED) {
    console.log(
      `${DIM}[CONCEDE]${RESET} ${c.capabilities.join(" + ")} => ${c.goal}`,
    );
    console.log(`          ${DIM}${c.rationale}${RESET}`);
  }
  console.log("================================================================\n");

  /* --------------- Exit code ---------------------------------------- */

  const scenariosPass = Object.values(results).filter((r) => r.defended).length;
  console.log(`${scenariosPass}/${Object.keys(results).length} scenarios defended`);
  const coveredCount = EXPECTED_DEFENSES.filter((ed) =>
    COVERAGE.some((e) => {
      const r = results[e.scenario];
      if (!r?.defended) return false;
      // Scenario subsumes ed iff scenario.capabilities is a superset of
      // ed.capabilities (ed's caps ⊆ scenario's caps).
      const subsumes = ed.capabilities.every((c) =>
        e.capabilities.includes(c),
      );
      return subsumes && e.expect[ed.goal] === "holds";
    }),
  ).length;
  console.log(
    `${coveredCount}/${EXPECTED_DEFENSES.length} expected-defense entries covered`,
  );

  if (!allPassed || !allCovered) {
    process.exit(1);
  }
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
