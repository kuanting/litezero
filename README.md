# LiteZero

[![CI](https://github.com/kuanting/litezero/actions/workflows/ci.yml/badge.svg)](https://github.com/kuanting/litezero/actions/workflows/ci.yml)

Reference implementation, attack battery, and verification artifacts for the paper

> **"LiteZero: A Provably Secure Hardware-Anchored AKE for MAVLink-Based Zero-Trust Internet of Drones"**
> Kuan-Ting Lai, *submitted to IEEE Internet of Things Journal*, 2026.

LiteZero is a lightweight three-party authenticated key exchange (AKE) for the
Internet of Drones in which:

- the **drone's** long-term ECC key is sealed under a key regenerated on demand
  from a physical unclonable function (PUF) — no long-term secret is ever stored
  in plaintext;
- the **cloud** is reduced to a zero-trust *authorization signer* — it issues
  short-lived signed tokens but is excluded from session-key derivation, so a
  breached cloud cannot recover any session key, past or future;
- the **user** and drone derive session keys directly via ephemeral ECDH, bound
  to the cloud token and the full handshake transcript;
- the secured session carries **real MAVLink v2** — the de facto drone
  command-and-control protocol of ArduPilot and PX4, which is plaintext on the
  wire by default — making LiteZero a drop-in secure channel for the traffic
  drones actually fly on.

This repository lets you verify, without an FPGA in hand, that the combined
design defeats every attacker class enumerated in the paper.

## Requirements

- **Node.js ≥ 22.7** (Node 24 LTS recommended; pinned in `.nvmrc`).
  The TypeScript sources run natively via `--experimental-transform-types` —
  there is **no build step and zero runtime dependencies** (`"dependencies": {}`;
  every cryptographic primitive is a direct call into Node's standards-validated
  `crypto` library).
- Optional: `python3` + `pip install pymavlink` for the MAVLink wire-compatibility
  check, [Bun](https://bun.sh) for the cross-runtime benchmark, and
  [Verifpal](https://verifpal.com) for the symbolic models.

## Quick start

```bash
git clone https://github.com/kuanting/litezero.git
cd litezero            # no npm install needed — zero dependencies

npm run attack         # 19-scenario seeded attack battery, 40 reps each (760/760 defended)
npm run matrix         # 21-scenario capability matrix (15 capabilities x 6 security goals)
npm run demo           # happy-path handshake + encrypted session (rekey, token refresh, policy push)
npm run demo:mavlink   # real MAVLink v2 C2/telemetry flown through the encrypted tunnel
npm run reproduce      # one command: re-runs every experiment in the paper, writes ./out/
```

## Repository layout

| Path | Contents |
| --- | --- |
| `src/protocol/` | The LiteZero AKE itself: handshake state machines (`litezero.ts`), wire messages (`messages.ts`), schema-validating parser (`parser.ts`) |
| `src/crypto/` | Primitives (ECDH/ECDSA P-256, HKDF-SHA256, AES-256-GCM), CSPRNG wrapper, zeroizable secret buffers, software PUF model with fuzzy extractor |
| `src/services/` | The three principals: `cloud.ts` (authorization signer), `drone.ts` (PUF-anchored responder), `user.ts` (initiator) |
| `src/mavlink/` | Hand-rolled, spec-accurate MAVLink v2 codec (~700 lines, zero dependencies): X.25 CRC with per-message `CRC_EXTRA`, streaming parser, common-dialect messages, flight stack + GCS mission generator |
| `src/attacks/` | 19 attack scenarios (MITM, replay, KCI, UKS, stolen cloud key, captured drone, MAVLink injection, ...) plus the capability matrix |
| `src/transport/` | In-process and WebSocket transports |
| `scripts/` | Entry points for every npm script, incl. `reproduce.sh` and the dead-secret lint |
| `models/` | Verifpal symbolic models (authentication, secrecy, intra-session forward secrecy) with field names/order matching `src/protocol/messages.ts` |
| `docs/` | `robust-verification.md` (verification methodology), `datasheet-audit.md` (20-row spec-vs-datasheet audit of every hardware claim) |
| `tools/` | `mavlink_interop_check.py` — byte-level interop check against reference pymavlink |

## All commands

| Command | What it does |
| --- | --- |
| `npm run attack` (= `npm test`) | Seeded attack battery: 19 scenarios x 40 repetitions, each must abort the handshake or fail to open a session with the intended peer |
| `npm run matrix` | Capability-based cross-check: 21 scenarios over 15 attacker capabilities and 6 security goals, with explicit concession list |
| `npm run demo` | Single-process happy path: enrollment, authorization, handshake, encrypted commands, in-band rekey/refresh/policy |
| `npm run demo:ws` | Same flow over real HTTP (cloud, `:4000`) and WebSocket (drone, `:4100`) transports |
| `npm run demo:mavlink` | A full GCS mission (ARM, TAKEOFF, GOTO, LAND) as genuine MAVLink v2 frames inside the AEAD session |
| `npm run mavlink:test` | MAVLink codec self-test (CRC vectors, round-trips, parser resync) |
| `npm run mavlink:interop` | Byte-compatibility against pymavlink, both directions (`pip install pymavlink` first) |
| `npm run bench` / `bench:bun` | Microbenchmarks (handshake latency, AEAD seal/open) under Node / Bun |
| `npm run lint:secrets` | Dead-secret static lint: every secret-producing call must be zeroized in the same function, or carry a documented `@secret-escapes` exemption |
| `npm run verifpal` | Verify the three Verifpal models (requires `verifpal` on PATH) |
| `npm run typecheck` | `tsc --noEmit` under `strict: true` |
| `npm run reproduce` | Re-runs demo + battery + benchmarks with a pinned seed; writes text artifacts and a pass/fail digest to `out/` |

## The four-layer verification stack

The paper's claim is not just "the protocol is proven secure" but "the
implementation is kept honest with the proof". Four independent layers enforce
that:

1. **Verifpal symbolic models** (`models/`) — seven queries (session-key
   secrecy, key confirmation, user and authorization authentication, and two
   intra-session forward-secrecy queries across an in-band rekey) verify under
   an active Dolev-Yao attacker. Message names and field order are identical to
   the TypeScript types, so model and code can be audited against each other by
   inspection.
2. **Seeded attack battery + capability matrix** (`src/attacks/`) — every
   scenario instantiates a full protocol run and injects active-attacker
   behavior; each defense traces to a specific game hop, freshness rule, or
   lemma of the paper's proof. The matrix cross-checks the battery against
   compound capabilities no single hand-written scenario exercises.
3. **Dead-secret static lint** (`scripts/dead-secret-lint.ts`) — a
   zero-dependency lint that pins approved secret-producing primitives to
   approved zeroization sinks. It caught three real zeroization bugs during
   rollout and is clean over all source files; it runs in CI on every push.
4. **Spec-vs-datasheet audit** (`docs/datasheet-audit.md`) — every hardware
   claim in the papers is pinned to a vendor datasheet page or a code location.

## Cryptographic realism (and the one deliberate model)

All cryptography is real and standards-aligned (NIST SP 800-56A, SP 800-108,
SP 800-38D, SP 800-133, RFC 5869/8446): ECDH and ECDSA on `prime256v1`,
HKDF-SHA256, AES-256-GCM, constant-time tag comparison, CSPRNG-only key
generation (the RNG wrapper refuses to be seeded on the live key-generation
path).

The single simulated component is the PUF: a software model of a
ring-oscillator PUF with a fuzzy extractor (majority-vote over noisy reads plus
a helper-data XOR sketch). It reproduces the *behavior* the protocol relies on
— a stable per-device key regenerated on demand, uncloneable without the seed —
but is **not** silicon. The companion systems paper covers the real
Zynq UltraScale+ hardware platform.

## MAVLink integration

The application payload inside the secure session is **real MAVLink v2**,
encoded by the in-repo zero-dependency codec in `src/mavlink/`. Frames are
byte-compatible with reference `pymavlink` in both directions
(`npm run mavlink:interop`). Because bare MAVLink has no confidentiality and
only weak, rarely-deployed optional signing, the `mavlink-injection` scenario
demonstrates the point of the tunnel: a forged-but-valid disarm command — which
would kill a bare MAVLink link — is rejected without a session key, and no
plaintext C2 ever appears on the wire.

## Reproducing the paper's results

```bash
npm run reproduce
```

re-runs every experiment from a clean tree with a pinned benchmark seed
(`BENCH_SEED` feeds only reproducible inputs; ephemeral key generation is
guarded against seeding) and writes `out/attack-log.txt`, `out/demo-log.txt`,
`out/bench-node.{json,csv}`, and a top-level `out/summary.txt`. Expected
results: 19/19 attack scenarios defended over 40 repetitions each (760/760
individual runs), 21/21 capability-matrix scenarios defended with 7/7
expected-defense entries covered.

## Development

CI (`.github/workflows/ci.yml`) runs the typecheck, the dead-secret lint, the
full attack battery, the capability matrix, the MAVLink self-test, and a
benchmark smoke pass on every push and pull request. To run the dead-secret
lint automatically before each commit, enable the versioned hook once per
clone:

```bash
git config core.hooksPath .githooks
```

## Citing

```bibtex
@article{Lai2026LiteZero,
  author  = {Kuan-Ting Lai},
  title   = {LiteZero: A Provably Secure Hardware-Anchored {AKE} for
             {MAVLink}-Based Zero-Trust Internet of Drones},
  journal = {IEEE Internet of Things Journal},
  year    = {2026},
  note    = {Under review}
}
```

See `PLAN.md` for the full design history, protocol diagram, and attack matrix.

## License

This code is released for academic and research use under the
[Creative Commons Attribution-NonCommercial 4.0 International](https://creativecommons.org/licenses/by-nc/4.0/)
license (see `LICENSE`). You may share and adapt it for non-commercial
purposes with attribution. For commercial licensing, contact the author.
