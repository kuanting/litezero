# LiteZero Simulation Plan

Design document for the reference simulator of *"LiteZero: A Provably Secure
Hardware-Anchored AKE for MAVLink-Based Zero-Trust Internet of Drones"* (Lai),
the protocol-and-proof companion to the systems paper *"A Full-Stack Secure
Internet-of-Drones System: FPGA-Based PUF Identity and Zero-Trust Cloud
Authorization"* (Lai, Zhong, Tsai). See `README.md` for usage; this file
records the design, protocol diagram, and attack matrix.

The design integrates three security primitives:

1. **FPGA / PUF root of trust** — the drone's ECC private key is never stored
   in plaintext; it is wrapped by a Key Encryption Key (KEK) regenerated on
   demand from a Ring-Oscillator PUF + fuzzy extractor inside the Zynq
   UltraScale+ Configuration Security Unit (CSU).
2. **Zero-trust cloud** — the cloud is strictly an **authorization** service.
   It never sees or derives session keys. Compromise of the cloud database
   leaks only public material.
3. **LiteZero handshake** — a cloud-issued authorization token, together with
   an ephemeral ECDH (P-256) + HKDF-SHA256 key agreement executed directly
   between user and drone, yields an AES-256-GCM session channel.

The simulation is pure Node.js / TypeScript so it slots straight into a Vite
stack.

---

## 1. Architecture

```
                 +--------------+                +-------------+
  (1) Login      |              |  (2) AuthToken |             |
  +------------> |   Cloud      | +------------> |    User     |
  user creds     |  (HTTP 4000) |                | (WS client) |
                 +--------------+                +-------------+
                                                       |
                                                       | (3) AuthToken + ECDH pub + nonce
                                                       v
                                                 +--------------+
                                                 |    Drone     |
                                                 | (WS  4100)   |
                                                 |  PUF + black |
                                                 |  key vault   |
                                                 +--------------+
```

- Cloud — HTTP service on `:4000` (Node's built-in `http`).
- Drone — WebSocket server on `:4100` (`ws` library).
- User — WebSocket client + HTTP client.

All three run in-process for the automated attack suite; in demo mode each
runs as a separate Node process over localhost.

---

## 2. Protocol (LiteZero)

### 2.1 Registration (bootstrap, run once)

Drone:

1. A per-device PUF seed is generated and stored inside the simulated "eFUSE".
2. Drone generates ECC P-256 keypair `(d_D, Q_D)`.
3. Drone regenerates KEK through the PUF + fuzzy extractor (helper data is
   saved to the "eFUSE" so that even a noisy PUF read yields the same KEK).
4. Drone seals `d_D` into a **black key** = `AES-256-GCM_KEK(d_D)` and stores
   `{black_key, helper_data, puf_challenge}` in its non-volatile store.
5. Drone publishes `Q_D` + `droneId` to the cloud registry.

User:

1. Generates ECDSA P-256 signing keypair; registers `(userId, password_hash,
   userVerifyKey)` with the cloud.

Cloud:

1. Generates its own ECDSA P-256 **cloud signing key**.
2. Stores only public material: `{userId: userVerifyKey, droneId: Q_D,
   policy}`. Critical: the cloud never sees drone or user private keys, and
   never holds session keys.

### 2.2 Zero-trust authorization

1. `User → Cloud` (HTTPS in prod, plain HTTP in sim):
   `POST /authorize { userId, droneId, nonce_U, ts_U }` signed with user's
   ECDSA key.
2. Cloud verifies user signature, checks policy (user-drone binding, time of
   day, device posture, token TTL), and issues:

   ```json
   AuthToken = { userId, droneId, policy, nonce_U, exp, iat }
   σ_cloud   = ECDSA_sign(cloud_sk, AuthToken)
   ```

   The token contains no session-key material. TTL is intentionally short
   (e.g. 30 s) so replay is bounded.

### 2.3 User ↔ Drone handshake

```
User                                                     Drone
----                                                     -----
(E_U, e_U) ← ECDH keygen                                 (regenerate KEK via PUF)
                                                          unwrap d_D = AES-GCM-dec(KEK, black_key)
H1  --- hello { authToken, σ_cloud, E_U, nonce_U } ---> verify σ_cloud with cloud_vk
                                                          verify exp/ts, droneId match
                                                          (E_D, e_D) ← ECDH keygen
                                                          Z = ECDH(e_D, E_U)
                                                          Ks, Km = HKDF(Z, salt=nonce_U∥nonce_D,
                                                                         info="litezero/v1")
                                                          τ_D = HMAC(Km, transcript ∥ "drone")
H2  <-- finish { E_D, nonce_D, τ_D } -------------------
 derive same Ks, Km                                       wipe KEK
 verify τ_D
 τ_U = HMAC(Km, transcript ∥ "user")
H3  --- ack { τ_U } ----------------------------------> verify τ_U
                                                          session open
```

Transcript = `SHA-256( authToken || σ_cloud || E_U || nonce_U || E_D || nonce_D )`.

### 2.4 Session (AES-GCM)

- Direction-separated keys derived from `Ks`:
  `k_u2d = HKDF(Ks, info="u2d")`, `k_d2u = HKDF(Ks, info="d2u")`.
- Each frame: `{seq, ciphertext, tag}` with `AAD = droneId || direction || seq`.
- 96-bit IV = `seq` (never reused; AES-GCM requirement).
- Receiver enforces strictly increasing `seq` within a 64-frame window.

---

## 3. Files

```
LiteZero_sim/
├── package.json
├── tsconfig.json
├── README.md, PLAN.md
├── src/
│   ├── config.ts               ports, constants
│   ├── crypto/
│   │   ├── primitives.ts       ECDH, AES-GCM, HKDF, HMAC, ECDSA
│   │   └── puf.ts              simulated RO-PUF + fuzzy extractor
│   ├── protocol/
│   │   ├── messages.ts         wire types
│   │   └── litezero.ts         handshake helpers (pure functions)
│   ├── mavlink/                zero-dep MAVLink v2 codec (carried payload)
│   │   ├── crc.ts              X25/MCRF4XX checksum
│   │   ├── protocol.ts         v2 frame encode + streaming parser
│   │   ├── messages.ts         HEARTBEAT/COMMAND_LONG/_ACK/POSITION/ATTITUDE
│   │   ├── flight.ts           drone flight stack + GCS mission
│   │   └── index.ts            encode/decode helpers
│   ├── services/
│   │   ├── cloud.ts            HTTP authorization service
│   │   ├── drone.ts            WebSocket server
│   │   └── user.ts             WebSocket client
│   └── attacks/
│       ├── eavesdrop.ts
│       ├── mitm.ts
│       ├── replay.ts
│       ├── spoof-drone.ts
│       ├── stolen-verifier.ts
│       ├── captured-drone.ts
│       ├── continuous-verification.ts
│       └── mavlink-injection.ts
├── tools/
│   └── mavlink_interop_check.py  optional pymavlink wire-compat check
└── scripts/
    ├── run-demo.ts             happy-path end-to-end
    ├── run-mavlink-demo.ts     MAVLink C2/telemetry over the tunnel
    ├── mavlink-selftest.ts     codec round-trip/CRC/streaming tests
    └── run-attacks.ts          attack battery with PASS/FAIL report
```

### MAVLink as the carried protocol

The session payloads are real **MAVLink v2** frames, not toy strings. A small,
spec-accurate, zero-dependency codec (`src/mavlink/`) encodes the messages a
drone actually speaks — `HEARTBEAT`, `COMMAND_LONG`, `COMMAND_ACK`,
`GLOBAL_POSITION_INT`, `ATTITUDE` — with the exact `CRC_EXTRA` values from the
common dialect. Frames are byte-compatible with the reference **pymavlink** in
both directions, verified by `tools/mavlink_interop_check.py`. Keeping the codec
in-repo preserves the simulation's standard-library-only property; the LiteZero
session carries the frames as opaque AEAD-protected bytes, so the secure channel
is exercised against the genuine drone protocol. MAVLink itself has no transport
confidentiality and only weak optional signing — the `mavlink-injection`
scenario shows a forged-but-valid command is rejected by the tunnel and no
plaintext C2 ever appears on the wire.

---

## 4. Attack coverage (matches paper's threat model)

| Threat (Table II in paper)        | Simulation scenario       | Expected outcome |
|-----------------------------------|---------------------------|------------------|
| Eavesdropping                     | `eavesdrop.ts`            | ciphertext reveals nothing |
| Spoofing (fake drone)             | `spoof-drone.ts`          | handshake aborts, no cloud sig |
| MITM / session hijack             | `mitm.ts`                 | transcript MAC mismatch |
| Replay                            | `replay.ts`               | stale token / stale seq rejected |
| Command injection                 | `replay.ts` (variant)     | AAD/tag mismatch |
| Cloud DB leak (zero-trust win)    | `stolen-verifier.ts`      | past sessions still safe |
| Drone capture (PUF win)           | `captured-drone.ts`       | black key unrecoverable |
| Hello replay within TTL           | `continuous-verification.ts` | single-use `n_U` cache rejects it |
| Pre-ack data injection            | `continuous-verification.ts` | no session until `τ_U` confirms |
| Stale-epoch frame after rekey     | `continuous-verification.ts` | retired-epoch frame rejected (intra-session FS) |
| Forged refresh / policy push      | `continuous-verification.ts` | only cloud-signed control applied |
| MAVLink injection / eavesdrop     | `mavlink-injection.ts`    | forged MAVLink command rejected; no plaintext C2 on the wire |

The full battery (`run-attacks.ts`) defends 19/19 scenarios; the capability
matrix (`run-capability-matrix.ts`) defends 21/21 with 7/7 expected-defense
coverage.

### Continuous verification (in-band, over the authenticated channel)

After the handshake, three control messages ride inside the AES-GCM session as
a `chan:"ctrl"` sub-channel (bound in the AAD alongside a key `epoch`):

- **token refresh** — the user re-presents a fresh cloud-signed token to extend
  authorization; the drone refuses application commands once the token TTL
  lapses, and re-enables them on a valid refresh (without tearing the transport),
- **epoch rekey** — a fresh ephemeral–ephemeral ECDH ratchets the directional
  keys to a new epoch and zeroizes the old ones (intra-session forward secrecy),
- **policy push** — a cloud-signed `(droneId, scope, ts)` attestation the drone
  verifies under its pinned cloud key and applies from the next frame.

---

## 5. How to run

```
cd LiteZero_sim
npm install
npm run demo            # happy path with live logs (handshake, rekey, refresh)
npm run demo:mavlink    # real MAVLink C2/telemetry through the secure tunnel
npm run mavlink:test    # MAVLink codec round-trip / CRC / streaming self-test
npm run mavlink:interop # optional: pymavlink wire-compat check (pip install pymavlink)
npm run attack          # runs all attacks and prints PASS/FAIL report
```

For the WebSocket/HTTP integration demo:

```
npm run cloud           # terminal 1
npm run drone           # terminal 2
npm run user            # terminal 3
```
