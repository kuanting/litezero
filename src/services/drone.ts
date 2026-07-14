// Drone side of the LiteZero protocol, transport-agnostic.

import {
  aesGcmDecrypt,
  aesGcmEncrypt,
  assertValidP256Point,
  randBytes,
  seqToIv,
  verifyEcdsa,
} from "../crypto/primitives.ts";
import { createECDH } from "node:crypto";
import {
  pufEnroll,
  pufRegenerate,
  type PufHelperData,
  type PufSeed,
} from "../crypto/puf.ts";
import {
  canonicalToken,
  deriveRekeyKeys,
  deriveSessionKeys,
  frameAad,
  helloSigDigest,
  macWithLabel,
  policyDigest,
  timingSafeEqual,
  transcriptHash,
} from "../protocol/litezero.ts";
import type {
  HandshakeAck,
  HandshakeFinish,
  HandshakeHello,
  SessionControl,
  SessionFrame,
  WireMessage,
} from "../protocol/messages.ts";
import { parseMessage } from "../protocol/parser.ts";
import {
  MAX_PENDING_HANDSHAKES,
  MAX_SEEN_HELLO_NONCES,
  SESSION_REPLAY_WINDOW,
} from "../config.ts";
import type { KeyObject } from "node:crypto";
import type { Transport, TransportServer } from "../transport/types.ts";

export interface DroneConfig {
  droneId: string;
  pufSeed: PufSeed;
  cloudVerifyKey: KeyObject;
  /**
   * Authorized-user verify keys, PINNED on the drone by the offline owner at provisioning
   * (Option A). The drone verifies the user's hello signature sigma_U against
   * the pinned key for the token's userId — NOT against
   * authToken.userVerifyKeyJwk. This is what makes a stolen sk_C insufficient
   * to command the drone: an attacker who forges a cloud token can advertise
   * its own pk_U inside it, but the drone ignores the token's key and checks
   * the pinned one, so the attacker must also hold the real sk_U.
   *
   * Mutable so the owner can re-provision (rotate) a user key after a
   * user-key compromise; see the post-compromise scenario.
   */
  authorizedUserKeys: Map<string, KeyObject>;
  /** Called when a plaintext command arrives from the user. */
  onCommand?: (payload: Buffer, reply: (resp: Buffer) => void) => void;
}

/**
 * AAD for the black-key AES-GCM wrap. Binds a versioned domain-separation
 * label and the device identity, so a black-key record can only be unwrapped
 * in the context of the droneId it was sealed for.
 */
export function blackKeyAad(droneId: string): Buffer {
  return Buffer.from(`litezero/blackkey/v1|${droneId}`, "utf8");
}

/**
 * Enroll the drone: make an ECDH P-256 keypair, wrap the private scalar with
 * the PUF-derived KEK, and persist only the "black key" + helper data. The
 * wrap binds droneId via the AAD; a fresh random IV is drawn per wrap (and
 * stored in the record), so no (KEK, IV) pair is reused across enrollments.
 */
export function enrollDrone(seed: PufSeed, droneId: string): {
  droneEcdhPub: Buffer;
  blackKey: { iv: Buffer; ct: Buffer; tag: Buffer };
  helper: PufHelperData;
} {
  const ecdh = createECDH("prime256v1");
  const droneEcdhPub = ecdh.generateKeys();
  const dScalar = ecdh.getPrivateKey();

  const { kek, helper } = pufEnroll(seed);
  const black = aesGcmEncrypt(kek, dScalar, blackKeyAad(droneId));
  kek.fill(0);
  return { droneEcdhPub, blackKey: black, helper };
}

interface SessionState {
  kU2D: Buffer;
  kD2U: Buffer;
  droneId: string;
  rxLastSeq: number;
  rxWindow: Set<number>;
  txSeq: number;
  /** Current key epoch; bumped on each in-band rekey. */
  epoch: number;
  /** Authorization deadline (token exp); refreshed in-band. */
  authExp: number;
  /** userId this session is authenticated to (refresh must match it). */
  userId: string;
  /** Handshake transcript, folded into rekey derivations as HKDF salt. */
  baseTranscript: Buffer;
  /** Current policy scope; updated by a cloud-signed policy push. */
  scope: string[];
  /** Last applied policy timestamp (monotonic guard against stale pushes). */
  policyTs: number;
}

/** Everything carried from handleHello to handleAck, released only on tau_U. */
interface PendingSession {
  kU2D: Buffer;
  kD2U: Buffer;
  authExp: number;
  userId: string;
  baseTranscript: Buffer;
  scope: string[];
}

/**
 * Bounded registry of half-open handshakes shared across all connections to a
 * drone. `admit` registers a newly half-open session, evicting the oldest when
 * the bound is exceeded; `retire` removes one that has opened or gone away.
 */
interface HalfOpenRegistry {
  admit(sess: DroneSession): void;
  retire(sess: DroneSession): void;
}

class DroneSession {
  state: SessionState | null = null;
  private pendingTranscript: Buffer | null = null;
  private pendingKm: Buffer | null = null;
  /** Session material derived in handleHello but not released until tau_U verifies. */
  private pendingSession: PendingSession | null = null;
  /** True while this session occupies a half-open slot in the registry. */
  private slotHeld = false;

  constructor(
    private cfg: DroneConfig,
    private blackKey: { iv: Buffer; ct: Buffer; tag: Buffer },
    private helper: PufHelperData,
    private link: Transport,
    /**
     * Single-use cache of hello nonces (nonceU -> token exp), SHARED across
     * connections to this drone. A cloud-signed token binds nonceU, so each
     * accepted hello burns its nonce; replaying the same hello on a new
     * connection is rejected before the drone spends a PUF regeneration and
     * two scalar multiplications on it.
     */
    private seenHelloNonces: Map<string, number>,
    /** Bounded half-open registry shared across connections. */
    private halfOpen: HalfOpenRegistry,
    /**
     * When this drone process started. The single-use nonce cache is
     * in-memory, so a restart empties it; rejecting any token issued before
     * boot (iat < bootTimeMs) closes the replay window a restart would
     * otherwise re-open for hellos captured in the previous boot.
     */
    private bootTimeMs: number,
  ) {}

  /** Drop expired entries so the single-use cache tracks only live nonces. */
  private pruneExpiredNonces(now: number): void {
    for (const [n, exp] of this.seenHelloNonces) {
      if (now > exp) this.seenHelloNonces.delete(n);
    }
  }

  handleMessage(msg: WireMessage): void {
    switch (msg.kind) {
      case "hello":
        this.handleHello(msg);
        break;
      case "ack":
        this.handleAck(msg);
        break;
      case "data":
        this.handleData(msg);
        break;
      default:
        this.link.send(JSON.stringify({ kind: "error", reason: `unexpected ${msg.kind}` }));
    }
  }

  private handleHello(msg: HandshakeHello): void {
    // Step 1: verify the cloud's signature over the token. This confirms the
    // token was issued by the trusted cloud; it does NOT yet prove that the
    // sender of `hello` is the legitimate user.
    const tokenBytes = canonicalToken(msg.authToken);
    if (!verifyEcdsa(this.cfg.cloudVerifyKey, tokenBytes, Buffer.from(msg.cloudSig, "base64"))) {
      return this.abort("invalid cloud signature");
    }
    if (Date.now() > msg.authToken.exp) return this.abort("auth token expired");
    // The nonce cache does not survive a restart, so a token minted before
    // this boot may carry a nonce we have already accepted (and forgotten).
    // Refuse it: a legitimate user just fetches a fresh token (TTL 30 s).
    if (msg.authToken.iat < this.bootTimeMs) {
      return this.abort("auth token predates drone boot");
    }
    if (msg.authToken.droneId !== this.cfg.droneId) return this.abort("wrong drone");
    // The hello carries nonceU twice: once cloud-signed inside the token and
    // once at the top level (bound by sigma_U). They must be the same value so
    // the freshness the cloud authorized is exactly the freshness the user
    // signed over; reject any hello that tries to desync them.
    if (msg.nonceU !== msg.authToken.nonceU) {
      return this.abort("hello nonce does not match token");
    }

    // Single-use check: each cloud-signed token binds a fresh nonceU, and the
    // drone accepts a given nonceU at most once within its TTL. This stops
    // wholesale replay of a captured hello (G3) and caps the work an attacker
    // can trigger per token. Expired entries are pruned on each hello.
    this.pruneExpiredNonces(Date.now());
    if (this.seenHelloNonces.has(msg.nonceU)) {
      return this.abort("hello replay: nonce already used");
    }
    // Fail closed if the live-nonce cache is at capacity: evicting an
    // unexpired nonce would re-open a replay window for its hello, and only
    // cloud-signed tokens can fill the cache in the first place.
    if (this.seenHelloNonces.size >= MAX_SEEN_HELLO_NONCES) {
      return this.abort("hello-nonce cache full: retry after token expiry");
    }

    // Step 2: verify the user's PoP signature sigma_U over (tok || E_U || n_U)
    // against the PINNED user key for this userId (Option A). We deliberately
    // do NOT trust authToken.userVerifyKeyJwk for authentication: under a
    // stolen sk_C, an attacker can mint a cloud-signed token that advertises
    // its own pk_U. Pinning the user key at provisioning means the drone
    // checks sigma_U against the key it was provisioned with, so the attacker
    // must also hold the real sk_U — a cloud-key compromise alone cannot
    // command the drone. (The token's userVerifyKeyJwk is now only an
    // authorization-layer convenience for the cloud's own records.)
    const pinnedKey = this.cfg.authorizedUserKeys.get(msg.authToken.userId);
    if (!pinnedKey) {
      return this.abort("user not provisioned as an authorized user of this drone");
    }
    const userPub = Buffer.from(msg.userPub, "base64");
    const nonceU = Buffer.from(msg.nonceU, "base64");
    const helloDigest = helloSigDigest(tokenBytes, userPub, nonceU);
    if (!verifyEcdsa(pinnedKey, helloDigest, Buffer.from(msg.userSig, "base64"))) {
      return this.abort("invalid user signature on hello");
    }

    // Validate E_U (on-curve, non-identity) before touching any key material,
    // closing invalid-curve / small-subgroup attacks on the static branch.
    try {
      assertValidP256Point(userPub);
    } catch {
      return this.abort("invalid user ephemeral public key");
    }

    // The hello is fully validated; burn its nonce before any expensive work.
    this.seenHelloNonces.set(msg.nonceU, msg.authToken.exp);

    // Step 3: unwrap d_D using the PUF-derived KEK. d_D lives in RAM only
    // for the duration of the two ECDH multiplications immediately below.
    let dScalar: Buffer;
    try {
      const kek = pufRegenerate(this.cfg.pufSeed, this.helper);
      dScalar = aesGcmDecrypt(kek, this.blackKey, blackKeyAad(this.cfg.droneId));
      kek.fill(0);
    } catch (e) {
      return this.abort(`puf unwrap failed: ${(e as Error).message}`);
    }

    // Step 4: two-branch ECDH.
    //   Z_1 = e_D * E_U      (ephemeral-ephemeral, for FS)
    //   Z_2 = d_D * E_U      (static-ephemeral, binds PUF-anchored identity)
    // ikm = Z_1 || Z_2. Both branches must be hard (Gap-DH) for the session
    // secret to be unpredictable — see Theorem 1 in the paper.
    const staticEcdh = createECDH("prime256v1");
    staticEcdh.setPrivateKey(dScalar);
    const ephEcdh = createECDH("prime256v1");
    const dronePub = ephEcdh.generateKeys();
    let z1: Buffer, z2: Buffer;
    try {
      z1 = ephEcdh.computeSecret(userPub);
      z2 = staticEcdh.computeSecret(userPub);
    } catch {
      dScalar.fill(0);
      return this.abort("bad user pub");
    }
    // Zeroize d_D immediately after its single use.
    dScalar.fill(0);
    const ikm = Buffer.concat([z1, z2]);
    z1.fill(0);
    z2.fill(0);

    const nonceD = randBytes(16);
    const { km, kU2D, kD2U } = deriveSessionKeys(ikm, nonceU, nonceD);
    ikm.fill(0);

    const transcript = transcriptHash({
      tokenBytes,
      cloudSig: Buffer.from(msg.cloudSig, "base64"),
      userPub,
      nonceU,
      userSig: Buffer.from(msg.userSig, "base64"),
      dronePub,
      nonceD,
    });
    const macD = macWithLabel(km, transcript, "drone");

    const out: HandshakeFinish = {
      kind: "finish",
      dronePub: dronePub.toString("base64"),
      nonceD: nonceD.toString("base64"),
      macD: macD.toString("base64"),
    };
    this.link.send(JSON.stringify(out));

    // Keys stay PENDING until the user's tau_U verifies in handleAck: the
    // session opens only after explicit key confirmation (Algorithm 1 step 16),
    // so no data frame is ever decrypted on a half-open handshake.
    if (this.pendingKm) this.pendingKm.fill(0); // defensively wipe a prior half-open on this conn
    this.pendingTranscript = transcript;
    this.pendingKm = km;
    this.pendingSession = {
      kU2D,
      kD2U,
      authExp: msg.authToken.exp,
      userId: msg.authToken.userId,
      baseTranscript: transcript,
      scope: msg.authToken.policy.scope,
    };
    // Register this half-open handshake. The registry bounds how many the drone
    // holds at once, evicting the oldest under a flood, so pending state cannot
    // grow without bound while a valid ack is still awaited.
    if (!this.slotHeld) {
      this.slotHeld = true;
      this.halfOpen.admit(this);
    }
  }

  private handleAck(msg: HandshakeAck): void {
    if (!this.pendingTranscript || !this.pendingKm || !this.pendingSession) {
      return this.abort("no handshake in progress");
    }
    const expected = macWithLabel(this.pendingKm, this.pendingTranscript, "user");
    if (!timingSafeEqual(expected, Buffer.from(msg.macU, "base64"))) {
      // Confirmation failed: this handshake will never open. Zeroize the
      // pending session material before tearing down so a failed/forged ack
      // cannot leave derived keys lingering in memory.
      this.wipePending();
      return this.abort("user mac invalid");
    }
    const p = this.pendingSession;
    this.state = {
      kU2D: p.kU2D,
      kD2U: p.kD2U,
      droneId: this.cfg.droneId,
      rxLastSeq: -1,
      rxWindow: new Set(),
      txSeq: 0,
      epoch: 0,
      authExp: p.authExp,
      userId: p.userId,
      baseTranscript: p.baseTranscript,
      scope: p.scope,
      policyTs: 0,
    };
    // Keys transferred into `state`; drop the pending handles (their buffers
    // are now aliased by `state`, so do NOT zeroize them here). The handshake
    // is no longer half-open, so free its registry slot.
    this.pendingTranscript = null;
    this.pendingKm.fill(0);
    this.pendingKm = null;
    this.pendingSession = null;
    this.retireSlot();
  }

  /** Free this session's half-open registry slot, at most once. */
  private retireSlot(): void {
    if (this.slotHeld) {
      this.slotHeld = false;
      this.halfOpen.retire(this);
    }
  }

  /** Zeroize any half-open handshake material that never opened a session. */
  private wipePending(): void {
    this.pendingTranscript = null;
    if (this.pendingKm) {
      this.pendingKm.fill(0);
      this.pendingKm = null;
    }
    if (this.pendingSession) {
      this.pendingSession.kU2D.fill(0);
      this.pendingSession.kD2U.fill(0);
      this.pendingSession = null;
    }
    this.retireSlot();
  }

  /**
   * Evicted by the registry when the drone is holding too many half-open
   * handshakes: zeroize this stale pending state and close the transport.
   */
  evict(): void {
    this.wipePending();
    this.link.close();
  }

  /**
   * Release all secret material for this connection. Called when the transport
   * closes so that an abandoned handshake (hello accepted, ack never arrives)
   * or a torn-down session does not leave session keys resident in memory.
   */
  dispose(): void {
    this.wipePending();
    if (this.state) {
      this.state.kU2D.fill(0);
      this.state.kD2U.fill(0);
      this.state = null;
    }
  }

  private handleData(msg: SessionFrame): void {
    if (!this.state) return this.abort("no session");
    if (msg.dir !== "u2d") return this.abort("wrong direction");
    // Epoch gate: a frame sealed under a retired epoch (e.g. an old-key frame
    // replayed after a rekey) no longer matches the live key and is rejected.
    if (msg.epoch !== this.state.epoch) return this.abort("wrong key epoch");
    if (msg.seq <= this.state.rxLastSeq - SESSION_REPLAY_WINDOW) return this.abort("seq too old");
    if (this.state.rxWindow.has(msg.seq)) return this.abort("replay");

    const chan = msg.chan ?? "app";
    const aad = frameAad(this.state.droneId, "u2d", msg.epoch, chan, msg.seq);
    // @secret-escapes: pt is application-layer plaintext (a command/telemetry
    // payload), not a key; it is handed to the control handler or onCommand
    // callback, which owns its lifetime — mirrors the user-side handling.
    let pt: Buffer;
    try {
      pt = aesGcmDecrypt(
        this.state.kU2D,
        {
          iv: Buffer.from(msg.iv, "base64"),
          ct: Buffer.from(msg.ct, "base64"),
          tag: Buffer.from(msg.tag, "base64"),
        },
        aad,
      );
    } catch {
      return this.abort("aead verify failed");
    }
    this.state.rxWindow.add(msg.seq);
    if (msg.seq > this.state.rxLastSeq) this.state.rxLastSeq = msg.seq;
    // Entries below the window can never be accepted again; drop them so the
    // window set stays bounded over long sessions.
    for (const s of this.state.rxWindow) {
      if (s <= this.state.rxLastSeq - SESSION_REPLAY_WINDOW) this.state.rxWindow.delete(s);
    }

    if (chan === "ctrl") {
      this.handleControl(pt);
      return;
    }

    // Application command: enforce continuous-verification policy at use time.
    // A failed authorization/policy check DROPS the command but keeps the
    // (cryptographically healthy) session open, so a subsequent valid in-band
    // refresh or policy push can re-enable it — "never trust, always verify"
    // without tearing the transport.
    if (Date.now() > this.state.authExp) return; // authorization expired
    if (!this.state.scope.includes("control")) return; // not permitted by policy
    const reply = (resp: Buffer) => this.sendFrame(resp);
    this.cfg.onCommand?.(pt, reply);
  }

  /**
   * Process an in-band continuous-verification control message. Confidentiality
   * and authentication of the channel are already established, so these
   * messages inherit it; the cloud-signed payloads (refresh token, policy) are
   * additionally verified under the pinned cloud key.
   */
  // Control-frame validation failures are NON-fatal: the AEAD channel already
  // authenticated the frame to the peer, and these checks are the *authorization*
  // layer (only the cloud may extend a TTL or change policy). A relayed control
  // message that fails cloud verification is simply dropped, never applied —
  // tearing down the cryptographically healthy session would only hand a
  // misbehaving relay a denial-of-service lever.
  private handleControl(pt: Buffer): void {
    if (!this.state) return;
    let ctrl: SessionControl;
    try {
      ctrl = JSON.parse(pt.toString("utf8")) as SessionControl;
    } catch {
      return; // malformed control frame — ignore
    }
    switch (ctrl.type) {
      case "refresh": {
        const tokenBytes = canonicalToken(ctrl.token);
        if (!verifyEcdsa(this.cfg.cloudVerifyKey, tokenBytes, Buffer.from(ctrl.cloudSig, "base64"))) {
          return; // refresh not cloud-signed — ignore
        }
        if (ctrl.token.droneId !== this.cfg.droneId) return; // wrong drone
        if (ctrl.token.userId !== this.state.userId) return; // wrong user
        if (Date.now() > ctrl.token.exp) return; // already expired
        // The refresh token carries a fresh nonceU; enforce single-use too,
        // with the same prune + fail-closed capacity rule as the hello path.
        this.pruneExpiredNonces(Date.now());
        if (this.seenHelloNonces.has(ctrl.token.nonceU)) return; // replayed refresh
        if (this.seenHelloNonces.size >= MAX_SEEN_HELLO_NONCES) return; // cache full
        this.seenHelloNonces.set(ctrl.token.nonceU, ctrl.token.exp);
        this.state.authExp = ctrl.token.exp;
        this.state.scope = ctrl.token.policy.scope;
        return;
      }
      case "rekey-init":
        return this.handleRekeyInit(ctrl);
      case "policy": {
        if (ctrl.ts <= this.state.policyTs) return; // stale/replayed push — ignore
        const digest = policyDigest(this.cfg.droneId, ctrl.scope, ctrl.ts);
        if (!verifyEcdsa(this.cfg.cloudVerifyKey, digest, Buffer.from(ctrl.sig, "base64"))) {
          return; // policy not cloud-signed — ignore
        }
        this.state.scope = ctrl.scope;
        this.state.policyTs = ctrl.ts;
        return;
      }
      default:
        return; // unknown control type — ignore
    }
  }

  /**
   * Rekey responder: derive a fresh ephemeral-ephemeral secret, reply with the
   * drone ephemeral under the CURRENT epoch keys, then switch to the new epoch
   * (zeroizing the old directional keys → intra-session forward secrecy).
   */
  private handleRekeyInit(ctrl: { epoch: number; ePub: string }): void {
    if (!this.state) return;
    if (ctrl.epoch !== this.state.epoch + 1) return; // bad epoch — ignore
    const peerPub = Buffer.from(ctrl.ePub, "base64");
    try {
      assertValidP256Point(peerPub);
    } catch {
      return; // invalid rekey ephemeral — ignore
    }
    const eph = createECDH("prime256v1");
    const ePub = eph.generateKeys();
    let ikm: Buffer;
    try {
      ikm = eph.computeSecret(peerPub);
    } catch {
      return; // bad rekey ephemeral — ignore
    }
    const next = deriveRekeyKeys(ikm, this.state.baseTranscript, ctrl.epoch);
    ikm.fill(0);

    // Answer under the still-current epoch keys so the user can match it.
    this.sendControl({ type: "rekey-resp", epoch: ctrl.epoch, ePub: ePub.toString("base64") });

    // Switch to the new epoch: retire old keys, install new, keep monotonic seq.
    this.state.kU2D.fill(0);
    this.state.kD2U.fill(0);
    this.state.kU2D = next.kU2D;
    this.state.kD2U = next.kD2U;
    this.state.epoch = ctrl.epoch;
  }

  private sendControl(ctrl: SessionControl): void {
    this.sendFrame(Buffer.from(JSON.stringify(ctrl), "utf8"), "ctrl");
  }

  private sendFrame(plaintext: Buffer, chan: "app" | "ctrl" = "app"): void {
    if (!this.state) throw new Error("no session");
    const seq = this.state.txSeq++;
    const iv = seqToIv(seq);
    const aad = frameAad(this.state.droneId, "d2u", this.state.epoch, chan, seq);
    const { ct, tag } = aesGcmEncrypt(this.state.kD2U, plaintext, aad, iv);
    const frame: SessionFrame = {
      kind: "data",
      dir: "d2u",
      epoch: this.state.epoch,
      chan,
      seq,
      iv: iv.toString("base64"),
      ct: ct.toString("base64"),
      tag: tag.toString("base64"),
    };
    this.link.send(JSON.stringify(frame));
  }

  private abort(reason: string): void {
    this.link.send(JSON.stringify({ kind: "error", reason }));
    this.link.close();
  }
}

/** Handle returned by {@link attachDrone} for observing server-wide state. */
export interface DroneServerStats {
  /** Number of half-open handshakes (hello accepted, ack pending) held now. */
  pendingHandshakes(): number;
}

/**
 * Attach the drone protocol to a transport server. Every incoming connection
 * gets its own session state. Returns a small stats handle for observing
 * server-wide state (used by tests to assert the half-open bound).
 */
export function attachDrone(
  server: TransportServer,
  cfg: DroneConfig,
  blackKey: { iv: Buffer; ct: Buffer; tag: Buffer },
  helper: PufHelperData,
): DroneServerStats {
  // Hello-nonce single-use cache, shared by ALL connections to this drone so a
  // hello captured on one connection cannot be replayed on another. It is
  // in-memory only; tokens issued before bootTimeMs are rejected so a restart
  // (which empties the cache) cannot re-open a replay window.
  const seenHelloNonces = new Map<string, number>();
  const bootTimeMs = Date.now();

  // Bounded half-open registry, shared across connections. A Set preserves
  // insertion order, so the "oldest" evictable slot is simply the first entry.
  const halfOpenSet = new Set<DroneSession>();
  const halfOpen: HalfOpenRegistry = {
    admit(sess) {
      if (halfOpenSet.size >= MAX_PENDING_HANDSHAKES) {
        const oldest = halfOpenSet.values().next().value as DroneSession | undefined;
        if (oldest) {
          halfOpenSet.delete(oldest);
          oldest.evict(); // zeroize its pending material + close its transport
        }
      }
      halfOpenSet.add(sess);
    },
    retire(sess) {
      halfOpenSet.delete(sess);
    },
  };

  server.onConnection((link) => {
    const sess = new DroneSession(cfg, blackKey, helper, link, seenHelloNonces, halfOpen, bootTimeMs);
    link.onMessage((s) => {
      // Single strict parsing chokepoint: every inbound byte string is
      // schema-validated before it reaches the session state machine. A
      // structurally malformed message (bad JSON, wrong/extra field types,
      // unknown kind) is rejected here and the transport is closed, so the
      // handlers below only ever see well-typed messages.
      const msg = parseMessage(s);
      if (msg.kind === "error") {
        link.send(JSON.stringify(msg));
        link.close();
        return;
      }
      sess.handleMessage(msg);
    });
    // Zeroize this connection's key material when the transport goes away.
    link.onClose(() => sess.dispose());
  });

  return {
    pendingHandshakes: () => halfOpenSet.size,
  };
}
