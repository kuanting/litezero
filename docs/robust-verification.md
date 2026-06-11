# Robust verification report — LiteZero v2

This document summarises the verification work that closes the post-mortem
"big miss" from v1 — where reviewers found two protocol flaws (stolen
`sk_C` sufficed; bearer-token splice with attacker-chosen `E_U`) that the
v1 battery did not enumerate.

## 1. What was insufficient in v1

The v1 verification stack had three quiet holes:

- **Prose-only formal argument.** Security goals were narrated rather than
  probed against a machine-checked model. A reviewer-typed query
  "does the drone accept a session opened by someone who has `sk_C` but
  not `sk_U`?" had no automated answer.
- **Scenario-based attack battery.** The seven v1 scenarios were chosen
  because they sounded representative (MITM, replay, spoof, ...). There
  was no enumeration of attacker *capabilities* — so compound capabilities
  that the v1 scenarios did not individually exercise (leaked `sk_C` +
  replay, captured token + attacker-chosen `E_U`) were silently outside
  coverage.
- **No spec-vs-datasheet audit.** The v1 paper asserted a P-256 ECC
  accelerator in the Zynq CSU. This is not what the silicon provides.
  The claim survived review because no one cross-checked it against
  UG1085.

## 2. What is in place now

### 2.1 Machine-checked symbolic model
A Verifpal model at [`models/litezero.vp`](../models/litezero.vp) encodes
the v2 protocol: two-branch ECDH with `ikm = (e_D · E_U) ∥ (d_D · E_U)`,
drone-verified `σ_U^hello` over `(tok ∥ E_U ∥ n_U)`, and cloud-signed
token binding `pk_U` and `P_D`.

Queries covered:

- session-key confidentiality (`Q1 km`),
- application-data confidentiality both directions (`Q2 m_u/m_d`),
- drone → user auth via `macD` (`Q3`),
- user → drone auth via `macU` and `σ_U` (`Q4 + Q7`),
- user → cloud auth via `authSig` (`Q5`),
- nonce freshness (`Q6`).

**v1.1 — continuous-verification rekey (`phase[1]`).** The model now adds an
in-band epoch rekey: the user and drone exchange fresh ephemeral points
*inside* the already-authenticated AEAD channel and derive new directional keys
from the new ephemeral–ephemeral secret. Time is then advanced and the retired
epoch-0 keys are `leaks`-ed, so the new-epoch material is tested under an
old-epoch-key compromise. Two queries are added:

- new-epoch key secrecy after old-epoch leak (`Q8 kU2_u`) — intra-session FS,
- new-epoch app-message confidentiality after old-epoch leak (`Q9 m_u2`).

Run:

```
verifpal verify models/litezero.vp
```

Expected: all queries hold under the `attacker[active]` setting. (Verifpal must
be installed separately; if it is absent the symbolic check is *pending* and
the executable battery below is the operative evidence.)

### 2.2 Capability-based attack battery
`src/attacks/capabilities.ts` declares fifteen attacker capabilities and
six security goals; `scripts/run-capability-matrix.ts` runs every
scenario and cross-checks both (a) per-scenario `defended` outcome
against the declared expectation and (b) coverage of
`EXPECTED_DEFENSES` entries via capability subsumption.

Capabilities (v1.1 adds the last three):

```
observe_transit, tamper_transit, replay_old_token, replay_old_frame,
leak_cloud_db, leak_sk_C, leak_sk_U,
capture_drone_diff_silicon, capture_drone_same_silicon,
rogue_peer, unknown_key_share, kci_drone_static,
replay_old_hello, inject_pre_session, leak_old_epoch_key
```

Goals (`G1`-`G6`): session-key confidentiality, mutual auth, forward
secrecy, replay resistance, zero-trust, post-compromise recovery.

Scenarios now in battery: 21. The v1.1 continuous-verification hardening
added four — `hello-replay` (single-use `n_U` cache), `pre-ack-injection`
(no data actioned before `τ_U` confirms the session), `stale-epoch-rekey`
(retired-epoch frame rejected after an in-band rekey), and `forged-refresh`
(only cloud-signed refresh/policy is applied) — on top of the 16 from v2; and
`mavlink-injection` carries real MAVLink v2 as the session payload and shows a
forged-but-valid command is rejected with no plaintext C2 on the wire.

Current status:

```
capability matrix : 21/21 scenarios defended, 7/7 expected-defense entries covered
attack battery     : 19/19 scenarios defended, 40/40 runs → 760/760 outcomes
```

(The capability matrix adds `replay-and-tamper` and `powerful-attacker` on top
of the 19 in `run-attacks.ts`; the 40-run stability sweep is over the battery.)

Run:

```
npm run matrix
```

### 2.3 Dead-secret static lint
`scripts/dead-secret-lint.ts` scans `src/` for any binding whose
initializer is a secret-producing primitive (`pufRegenerate`,
`aesGcmDecrypt`, `ecdhSharedSecret`, `hkdf`) and requires the same
enclosing function to zeroize it via `.fill(0)`, `zeroize()`, or
`dispose()`. An `// @secret-escapes: <reason>` comment exempts bindings
that legitimately transfer ownership to the caller.

First run of this lint surfaced three real issues:

- `src/services/user.ts`: `z1`, `z2` (two-branch DH outputs) and `ikm`
  were not zeroized after session key extraction on the user side.
  Fixed.
- `src/attacks/captured-drone.ts`: `kek` from `pufRegenerate` not
  zeroized on the failure path. Fixed.
- `src/attacks/kci.ts`: same as above. Fixed.

Post-fix:

```
[dead-secret-lint] clean (40 files scanned)
```

Run:

```
npm run lint:secrets
```

### 2.4 Spec-vs-datasheet audit table
`docs/datasheet-audit.md` cross-references every hardware claim in both
papers against the Xilinx/AMD datasheets (UG1085, UG1283, XAPP1323,
XAPP1333) and the relevant NIST SPs. Twenty rows, all marked either
**CONFIRMED** or **REVISED** with the datasheet page or code location
that supports them. The "CSU has P-256 hardware" claim from v1 is
filed as row #4 with status **REVISED**.

### 2.5 Secret-type taxonomy (foundation)
`src/crypto/secret-types.ts` defines nominal brands for each kind of
secret (`UserSk`, `CloudSk`, `DronePufKek`, `DroneEcdhStatic`,
`EphemeralEcdhScalar`, `Z1`, `Z2`, `IkmTwoBranch`, `SessionMasterKm`,
`SessionSubKey`) and a lifecycle-audit registry. This is the hook for
later work: tagging sinks that accept only allowed kinds and running
`unDisposedSecrets()` at the end of each attack to flag leaks at
runtime in addition to the static scan.

## 3. Delta from v1

| Check | v1 | v2 / v1.1 |
|---|---|---|
| Symbolic formal model | none (prose) | Verifpal, 10 queries (incl. `phase[1]` rekey FS) |
| Attack battery style | 7 named scenarios | 21 scenarios organised over 15 capabilities × 6 goals |
| Carried application protocol | toy strings | real MAVLink v2 (pymavlink wire-compatible), with a MAVLink-injection scenario |
| Attack battery catches reviewer flaws | no | yes — `stolen-cloud-key`, `token-bearer`, `powerful-attacker`, `replay-and-tamper` |
| Half-open / replay hardening | no | ack-gated session, single-use `n_U` cache, epoch gate (`hello-replay`, `pre-ack-injection`, `stale-epoch-rekey`) |
| Continuous verification | claimed, not implemented | in-band token refresh, epoch rekey, cloud-signed policy push (`forged-refresh`) |
| Hardware claims audited | no | 20-row table against UG1085/UG1283/XAPP1323/XAPP1333 |
| Secret-zeroization lint | none | zero-dep static scanner, clean over 34 files |
| Post-fix zeroization bugs found | n/a | 3 (user-side `z1`/`z2`/`ikm` + two `kek` paths) |
| Hardware ECC accelerator claim | asserted | REVISED: software P-256 in PS DRAM with mlock + XMPU-isolated aperture |

## 4. What is still out of scope

- **Side-channel analysis** on the physical board (power, timing,
  EM). The v2 threat model assumes a logical attacker; physical-access
  side channels are a separate piece of work and not part of this
  verification package.
- **Formal game-hop proof** with reductions to the Gap-DH and ECDSA-EUF
  assumptions. The LiteZero paper Section V gives a Theorem 1 statement
  in the Bellare-Rogaway multi-stage AKE model; a machine-checked proof
  in EasyCrypt or CryptoVerif is future work.
- **ProVerif / Tamarin port.** The Verifpal model is the symbolic check
  used here. A port to ProVerif or Tamarin (unbounded sessions, richer
  equational theory, injective-agreement lemmas for the rekey ratchet) is
  deferred to the companion protocol paper (`LiteZero_AKE_IoTJ`), which
  carries the full formal treatment.
- **Property-based and fuzz testing** (fast-check / Hypothesis). The
  capability matrix is the most targeted layer; compounded randomised
  inputs would add confidence against the "surprise" class of bug but
  are not yet integrated.
- **Independent red-team pass.** We rely on the reviewers' adversarial
  probing as the external check; a standing external-red-team policy
  would be an ongoing engineering investment, not a one-shot
  verification step.

## 5. Reproduce

```
cd LiteZero_sim
npm install            # no runtime deps, installs dev toolchain only
npm run attack         # 19/19 battery scenarios defended
npm run matrix         # 21/21 scenarios defended, 7/7 coverage entries
npm run mavlink:test   # in-repo MAVLink v2 codec self-test
npm run lint:secrets   # dead-secret static scanner clean
verifpal verify models/litezero.vp   # all queries hold (verifpal installed separately)
python3 tools/mavlink_interop_check.py  # optional: pymavlink wire-compat (pip install pymavlink)
```
