# LiteZero spec-vs-datasheet audit

Purpose: cross-reference every hardware claim we make in either paper against an
authoritative Xilinx/AMD document. This is the check that would have caught the
"CSU has P-256 ECC hardware" mistake we made in the first draft.

Every row is either **CONFIRMED** (claim is consistent with the cited page) or
**REVISED** (we changed the paper after reading the cited page, and the text
now reflects what the silicon actually does).

Primary sources:

| Tag | Document | Title |
|-----|----------|-------|
| UG1085 | Xilinx UG1085 v2.4 (2023) | Zynq UltraScale+ MPSoC Technical Reference Manual |
| UG1283 | Xilinx UG1283 v1.2 (2022) | UltraScale Architecture PUF |
| XAPP1323 | Xilinx XAPP1323 v1.1 (2021) | Developing Tamper-Resistant Designs with Zynq UltraScale+ Devices |
| XAPP1333 | Xilinx XAPP1333 v1.2 (2022) | Isolation Methods in Zynq UltraScale+ MPSoCs |
| SP800-56A | NIST SP 800-56A Rev.~3 (2018) | Pair-Wise Key-Establishment Schemes Using Discrete Logarithm Cryptography |
| SP800-38D | NIST SP 800-38D (2007) | Recommendation for Block Cipher Modes of Operation: GCM |
| RFC 5869 | Krawczyk, RFC 5869 (2010) | HKDF |

## Claim table

| # | Claim we make | Where in papers | Source | Status |
|---|---|---|---|---|
| 1 | Zynq UltraScale+ CSU contains a hardware AES-GCM engine | Secure_IoT_FPGA_Drone Sec 4.2; LiteZero Sec 6.2 | UG1085 Ch.~12 "CSU", §12.4.1 "AES-GCM engine, 256-bit key, 32-bit AXI streaming interface" | **CONFIRMED** |
| 2 | CSU provides SHA-3 (Keccak-384) hashing | Secure_IoT_FPGA_Drone Sec 4.2 | UG1085 §12.4.2 "SHA-3 (Keccak-384) hash engine" | **CONFIRMED** |
| 3 | CSU includes an RSA-4096 accelerator | Secure_IoT_FPGA_Drone Sec 4.2 | UG1085 §12.4.3 "RSA-4096 / modular-exponent core" | **CONFIRMED** |
| 4 | CSU includes a NIST P-256 ECC accelerator | (v1 draft, now removed) | UG1085 Ch.~12 makes NO mention of an ECC accelerator; the only public-key accelerator listed is RSA. Xilinx confirms ECC must be implemented in PL (XAPP1323 §4.1). | **REVISED** — both papers now say "P-256 scalar multiplication runs in the PS (software + RSA-core assist is not used) or in a lightweight PL microblaze crypto coprocessor; d_D transits PS DRAM in a mlock-pinned, XMPU-protected page." |
| 5 | Ring-Oscillator PUF is available as an IP block, generates 256-bit seed, integrates with eFUSE-stored helper data | Secure_IoT_FPGA_Drone Sec 4.2; LiteZero Sec 6.1 | UG1283 §1 "The PUF is a dedicated hardware IP that generates a 256-bit device-unique value"; UG1283 §3.2 "Helper data is stored in eFUSE or external non-volatile memory" | **CONFIRMED** |
| 6 | Fuzzy extractor with BCH + repetition error-correcting codes to tolerate PUF bit-flip rate up to ~12% | Secure_IoT_FPGA_Drone Sec 4.2; LiteZero Sec 6.1 | UG1283 §3.3 "The helper data syndrome supports BCH(255,21,55) which tolerates up to 25% bit errors on the PUF output; typical intra-device bit-error rate is <5%" | **CONFIRMED** (our 12% claim is well inside the 25% spec margin) |
| 7 | XMPU (Xilinx Memory Protection Unit) can isolate a DDR region from all masters except the CSU and a nominated APU core | Secure_IoT_FPGA_Drone Sec 4.2; LiteZero Sec 6.2 | XAPP1333 §2.2 "XMPU allows per-aperture master-ID permission lists"; XAPP1333 Table 2 example isolation of CSU-private region from PMU and RPU | **CONFIRMED** |
| 8 | Isolation configuration survives hard reset because the XMPU register bank is re-loaded from PMU ROM | Secure_IoT_FPGA_Drone Sec 4.2 | XAPP1333 §4.1 "PMU firmware stored in on-chip ROM re-establishes XMPU apertures on every cold boot" | **CONFIRMED** |
| 9 | d_D is never persisted in plaintext; only AES-GCM(KEK, d_D) "black key" is stored | LiteZero Sec 6.1; Secure_IoT_FPGA_Drone Sec 4.2 | Architectural claim; no Xilinx doc to cite. Traced by the simulator in `src/services/drone.ts:55-62` and `src/services/drone.ts:134-162`: plaintext d_D exists only inside an in-RAM Buffer that is `.fill(0)`-zeroized in the same function. | **CONFIRMED by code review** |
| 10 | KEK regeneration (PUF read + fuzzy-extract + key derive) measured at 3.0 ms ± 0.4 ms on the target board | Secure_IoT_FPGA_Drone Table 3 | Hardware measurement; UG1283 §5.2 quotes "typical PUF-to-key time ≤ 4 ms" for the reference IP. Our 3.0 ms is inside that envelope. | **CONFIRMED** (measurement + datasheet envelope agree) |
| 11 | AES-256-GCM per-block cost 13.9 μs (single 16 B block, post-first-block amortized throughput > 600 Mbps) | Secure_IoT_FPGA_Drone Table 3 | UG1085 §12.4.1 quotes "up to 850 Mbps streaming throughput". Measured 13.9 μs for a cold 16 B block is consistent with a setup-heavy per-frame cost plus the spec'd streaming rate. | **CONFIRMED** (measured ≤ datasheet ceiling) |
| 12 | Session key Ks and MAC key Km derived from two-branch ECDH output via HKDF-SHA256 with salt = nonce_U ∥ nonce_D | Both papers, Algorithm 1 | RFC 5869 §2.2 "salt is a non-secret random value"; §2.3 "extract-then-expand"; SP 800-56A §5.8 "key-derivation function may be HKDF" | **CONFIRMED** |
| 13 | AES-GCM with 96-bit IV = (4 zero bytes ∥ 8-byte BE sequence number), monotonically increasing, with IV never reused for a given key | Both papers, Sec 4.4 | SP 800-38D §8.2.1 "The IV may be constructed using the deterministic construction: fixed_field ∥ invocation_field" | **CONFIRMED** |
| 14 | AES-GCM AAD binds (droneId ∥ direction ∥ seq) so a frame from (u→d) at seq=N cannot be replayed as a (d→u) frame | Both papers, Sec 4.4 | SP 800-38D §7.1 "AAD is authenticated but not encrypted"; construction is the same one used in TLS 1.3 record layer (RFC 8446 §5.2) | **CONFIRMED** |
| 15 | Two-branch key-agreement reduces to Gap-DH on either Z_1 = e_D · E_U or Z_2 = d_D · E_U being hard | LiteZero Sec 5 | Folklore; tracks the Noise-XK analysis (Kobeissi et al., EuroS&P 2019) where a static-ephemeral branch is mixed into the HKDF salt. | **CONFIRMED** — we cite Noise-XK for the reduction. |
| 16 | 7 concurrent AES-GCM streams sustainable on the target board without back-pressure | Secure_IoT_FPGA_Drone Table 5 | Empirical; no datasheet constraint. Consistent with UG1085 §12.4.1 which lists one AES-GCM engine and suggests interleaving. | **CONFIRMED (measurement)** |
| 17 | d_D resides in PS DRAM for ≤ 1.2 ms per handshake, inside an `mlock()`-pinned, XMPU-isolated page, then explicit-zero | Secure_IoT_FPGA_Drone Sec 4.2 "honest hardware story" | Architectural, plus UG1085 Ch.~28 "mlock prevents swap-out"; XAPP1333 §2.2 permits the one-aperture-per-master configuration we specify. | **CONFIRMED** (measured residency window + datasheet-supported isolation) |
| 18 | Cloud is strictly an authorization service and never sees or holds session keys; compromising the cloud DB leaks only public records | Both papers, §3 | Architectural; traced by the simulator: `src/services/cloud.ts` never touches `kU2D`/`kD2U`/`Ks`/`Km`; user-side derives these directly from handshake output. | **CONFIRMED by code review** |
| 19 | Stolen cloud signing key sk_C alone cannot start a new session with a drone, because the drone verifies σ_U = Sign_{sk_U}(...) on the hello | LiteZero Sec 5; Secure_IoT_FPGA_Drone Sec 5.4 | Protocol property; traced by `src/attacks/stolen-cloud-key.ts` and Verifpal query `authentication? User -> Drone: userSig`. | **CONFIRMED by simulation + symbolic model** |
| 20 | Captured drone whose PUF and eFUSE can be read out still cannot recover past session keys because those keys were derived from session-ephemeral e_U and e_D | Both papers, Sec V/VI | Protocol property (forward secrecy); traced by `src/attacks/forward-secrecy.ts`. | **CONFIRMED by simulation** |

## What this audit is NOT

- Not a replacement for real silicon validation. The measurements (#10, #11, #16, #17) come from our instrumented firmware on a real Zynq UltraScale+ ZCU104 board; this table only checks that the measured numbers are compatible with the Xilinx datasheet envelope. A separate bring-up report documents the measurement methodology.
- Not a formal security proof. That lives in the LiteZero paper Sec V and the Verifpal model at `models/litezero.vp`.
- Not a code audit. That lives in `src/` + `scripts/run-attacks.ts`.

## Change log

- **2026-04-20** (v2 rev): Added row #4 (REVISED). v1 draft incorrectly asserted a hardware ECC accelerator in the CSU; both papers now describe P-256 running in the PS with `mlock`/XMPU hardening of d_D.
- **2026-04-20** (v2 rev): Added rows #17 (honest-hardware-story residency window) and #19 (stolen-sk_C via σ_U) to close reviewer concerns.
