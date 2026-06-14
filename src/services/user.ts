// User side of the LiteZero protocol, transport-agnostic.

import {
  aesGcmDecrypt,
  aesGcmEncrypt,
  ecdhSharedSecret,
  ephemeralEcdh,
  randBytes,
  seqToIv,
  sha256,
  signEcdsa,
} from "../crypto/primitives.ts";
import {
  canonicalToken,
  deriveRekeyKeys,
  deriveSessionKeys,
  frameAad,
  helloSigDigest,
  macWithLabel,
  timingSafeEqual,
  transcriptHash,
} from "../protocol/litezero.ts";
import type {
  AuthorizeRequest,
  HandshakeAck,
  HandshakeFinish,
  HandshakeHello,
  SessionControl,
  SessionFrame,
  SignedAuthToken,
  WireMessage,
} from "../protocol/messages.ts";
import { SESSION_REPLAY_WINDOW } from "../config.ts";
import type { KeyObject } from "node:crypto";
import type { Transport } from "../transport/types.ts";

export interface UserIdentity {
  userId: string;
  signingKey: KeyObject;
  /**
   * Drone long-term public keys (P_D) the user PINNED at provisioning, each
   * verified offline against the owner's trust-anchor signature (Option A),
   * keyed by droneId. When present for the target drone, the user uses the
   * pinned P_D for the static-ephemeral branch and rejects a cloud token whose
   * dronePubKey disagrees — closing the drone-substitution path under a stolen
   * sk_C. When absent, the user falls back to the token's P_D.
   */
  pinnedDrones?: Map<string, Buffer>;
}

export interface CloudClient {
  authorize(req: AuthorizeRequest): Promise<SignedAuthToken>;
}

export interface UserSession {
  send(cmd: Buffer): Promise<void>;
  close(): void;
  onFrame(cb: (plaintext: Buffer) => void): void;
  /** Re-present a fresh cloud token in-band to extend authorization (TTL). */
  refresh(): Promise<void>;
  /** Ratchet to a new key epoch via a fresh ephemeral-ephemeral exchange. */
  rekey(): Promise<void>;
  /** Relay a cloud-signed policy attestation to the drone (continuous verify). */
  applyPolicy(signed: { scope: string[]; ts: number; sig: string }): Promise<void>;
  /** Current key epoch (0 post-handshake; +1 per rekey). */
  epoch(): number;
}

export function httpCloudClient(url: string): CloudClient {
  return {
    async authorize(req) {
      const r = await fetch(`${url}/authorize`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(req),
      });
      if (!r.ok) throw new Error(`cloud rejected: ${await r.text()}`);
      return (await r.json()) as SignedAuthToken;
    },
  };
}

/**
 * Run the LiteZero handshake over an already-open transport.
 * Returns a session ready to send AES-GCM frames.
 */
export async function runUserHandshake(params: {
  identity: UserIdentity;
  droneId: string;
  cloud: CloudClient;
  link: Transport;
  verbose?: boolean;
  /** Optional injection point used by attack scenarios. */
  tamperHello?: (h: HandshakeHello) => HandshakeHello;
}): Promise<UserSession> {
  const { identity, droneId, cloud, link, tamperHello } = params;
  const log = params.verbose ? console.log : () => {};

  const nonceU = randBytes(16);
  const ts = Date.now();
  const msg = sha256(
    Buffer.from(
      `${identity.userId}|${droneId}|${nonceU.toString("base64")}|${ts}`,
      "utf8",
    ),
  );
  const authSig = signEcdsa(identity.signingKey, msg).toString("base64");
  const signed = await cloud.authorize({
    userId: identity.userId,
    droneId,
    nonceU: nonceU.toString("base64"),
    ts,
    userSig: authSig,
  });
  log("[user] cloud issued auth token, exp in",
      signed.token.exp - Date.now(), "ms");

  const eph = ephemeralEcdh();

  // User signs the hello payload directly for the drone to verify.
  // This is the proof-of-possession of sk_U that the drone consumes, separate
  // from the signature to the cloud above. Without sigma_U, a stolen sk_C
  // (or a replayed token) would let an attacker drive the hello themselves.
  const helloDigest = helloSigDigest(
    canonicalToken(signed.token),
    eph.pub,
    nonceU,
  );
  const userSig = signEcdsa(identity.signingKey, helloDigest).toString("base64");

  let hello: HandshakeHello = {
    kind: "hello",
    authToken: signed.token,
    cloudSig: signed.cloudSig,
    userPub: eph.pub.toString("base64"),
    nonceU: nonceU.toString("base64"),
    userSig,
  };
  if (tamperHello) hello = tamperHello(hello);

  // one-shot message waiter (rejects only on first close, never subsequently)
  let settled = false;
  const nextMessage = (): Promise<WireMessage> =>
    new Promise((res, rej) => {
      const onClose = () => {
        if (!settled) {
          settled = true;
          rej(new Error("connection closed"));
        }
      };
      const onMsg = (s: string) => {
        if (settled) return;
        settled = true;
        try {
          res(JSON.parse(s) as WireMessage);
        } catch (e) {
          rej(e);
        }
      };
      link.onMessage(onMsg);
      link.onClose(onClose);
    });

  link.send(JSON.stringify(hello));
  const fin = (await nextMessage()) as
    | HandshakeFinish
    | { kind: "error"; reason: string };
  // clear the one-shot flag so future close events don't affect anything.
  settled = true;
  if (fin.kind === "error") {
    link.close();
    throw new Error(`drone error: ${fin.reason}`);
  }
  if (fin.kind !== "finish") throw new Error(`unexpected ${(fin as { kind: string }).kind}`);

  const dronePub = Buffer.from(fin.dronePub, "base64");
  const nonceD = Buffer.from(fin.nonceD, "base64");
  // Two-branch ECDH (Noise-XK style):
  //   Z_1 = e_U * E_D    ephemeral-ephemeral, provides forward secrecy.
  //   Z_2 = e_U * P_D    ephemeral-static-drone, binds the drone's PUF-anchored
  //                      long-term identity into the session secret.
  // Without Z_2, an attacker with a valid token but no d_D could still finish
  // the handshake by providing its own E_D — which is precisely the flaw the
  // reviewer flagged. Z = Z_1 || Z_2 closes that gap by reducing to Gap-DH on
  // either branch being hard (see §V in the paper).
  // Determine the drone's static pub key P_D from the owner-PINNED record
  // (Option A): it was verified offline against the owner trust anchor at
  // provisioning, so it does not depend on the cloud. Pinning is MANDATORY
  // (Algorithm 1 step 13) — there is no fallback to the token's P_D, because
  // under a stolen sk_C a forged token could advertise a bogus P_D and lure an
  // unpinned user onto a fake drone. If the cloud-signed token advertises a
  // different P_D than the pin, abort — that is a substitution attempt.
  const tokenDronePub = Buffer.from(signed.token.dronePubKey, "base64");
  const pinnedDronePub = identity.pinnedDrones?.get(droneId);
  if (!pinnedDronePub) {
    link.close();
    throw new Error(
      "no owner-pinned P_D for this drone — refusing unpinned handshake",
    );
  }
  if (!timingSafeEqual(pinnedDronePub, tokenDronePub)) {
    link.close();
    throw new Error(
      "drone pubkey mismatch — token P_D differs from owner-pinned P_D",
    );
  }
  const dronePubStatic = pinnedDronePub;
  const z1 = ecdhSharedSecret(eph, dronePub);
  const z2 = ecdhSharedSecret(eph, dronePubStatic);
  const ikm = Buffer.concat([z1, z2]);
  // Zeroize both DH branches and the concatenated IKM as soon as the
  // derived key material is extracted. Matches the drone-side handling
  // in services/drone.ts and closes a dead-secret-lint finding.
  z1.fill(0);
  z2.fill(0);
  const { km, kU2D, kD2U } = deriveSessionKeys(ikm, nonceU, nonceD);
  ikm.fill(0);

  const tokenBytes = canonicalToken(hello.authToken);
  const transcript = transcriptHash({
    tokenBytes,
    cloudSig: Buffer.from(hello.cloudSig, "base64"),
    userPub: eph.pub,
    nonceU,
    userSig: Buffer.from(hello.userSig, "base64"),
    dronePub,
    nonceD,
  });

  const expectedMacD = macWithLabel(km, transcript, "drone");
  if (!timingSafeEqual(expectedMacD, Buffer.from(fin.macD, "base64"))) {
    link.close();
    throw new Error("drone mac invalid — possible MITM");
  }

  const ack: HandshakeAck = {
    kind: "ack",
    macU: macWithLabel(km, transcript, "user").toString("base64"),
  };
  link.send(JSON.stringify(ack));
  log("[user] handshake complete");

  // Session state. Keys are mutable so an in-band rekey can ratchet them; seq
  // stays monotonic across epochs so the GCM nonce (derived from seq) is never
  // reused even though directional keys change.
  let txSeq = 0;
  let rxLastSeq = -1;
  let epoch = 0;
  let curKU2D = kU2D;
  let curKD2U = kD2U;
  const rxWindow = new Set<number>();
  const listeners: ((pt: Buffer) => void)[] = [];
  // Awaiter for a pending rekey-resp control frame.
  let pendingRekey: { epoch: number; resolve: (ePub: Buffer) => void } | null = null;

  const sendCtrl = (ctrl: SessionControl): void => {
    const seq = txSeq++;
    const iv = seqToIv(seq);
    const aad = frameAad(droneId, "u2d", epoch, "ctrl", seq);
    const { ct, tag } = aesGcmEncrypt(curKU2D, Buffer.from(JSON.stringify(ctrl), "utf8"), aad, iv);
    link.send(JSON.stringify({
      kind: "data", dir: "u2d", epoch, chan: "ctrl", seq,
      iv: iv.toString("base64"), ct: ct.toString("base64"), tag: tag.toString("base64"),
    } satisfies SessionFrame));
  };

  link.onMessage((s) => {
    try {
      const m = JSON.parse(s) as WireMessage;
      if (m.kind !== "data" || m.dir !== "d2u") return;
      if (m.epoch !== epoch) return; // stale/old-epoch frame
      if (m.seq <= rxLastSeq - SESSION_REPLAY_WINDOW) return;
      if (rxWindow.has(m.seq)) return;
      const chan = m.chan ?? "app";
      const aad = frameAad(droneId, "d2u", m.epoch, chan, m.seq);
      // @secret-escapes: pt is application-layer plaintext, not a key;
      // ownership passes to the listener which decides its lifetime.
      const pt = aesGcmDecrypt(
        curKD2U,
        {
          iv: Buffer.from(m.iv, "base64"),
          ct: Buffer.from(m.ct, "base64"),
          tag: Buffer.from(m.tag, "base64"),
        },
        aad,
      );
      rxWindow.add(m.seq);
      if (m.seq > rxLastSeq) rxLastSeq = m.seq;
      // Entries below the window can never be accepted again; keep the set bounded.
      for (const sq of rxWindow) {
        if (sq <= rxLastSeq - SESSION_REPLAY_WINDOW) rxWindow.delete(sq);
      }
      if (chan === "ctrl") {
        const ctrl = JSON.parse(pt.toString("utf8")) as SessionControl;
        if (ctrl.type === "rekey-resp" && pendingRekey && ctrl.epoch === pendingRekey.epoch) {
          pendingRekey.resolve(Buffer.from(ctrl.ePub, "base64"));
        }
        return;
      }
      for (const l of listeners) l(pt);
    } catch {
      /* ignore malformed or forged frames */
    }
  });

  return {
    async send(cmd) {
      const seq = txSeq++;
      const iv = seqToIv(seq);
      const aad = frameAad(droneId, "u2d", epoch, "app", seq);
      const { ct, tag } = aesGcmEncrypt(curKU2D, cmd, aad, iv);
      const frame: SessionFrame = {
        kind: "data",
        dir: "u2d",
        epoch,
        chan: "app",
        seq,
        iv: iv.toString("base64"),
        ct: ct.toString("base64"),
        tag: tag.toString("base64"),
      };
      link.send(JSON.stringify(frame));
    },
    async refresh() {
      // Mint a fresh cloud token exactly as at handshake time, then re-present
      // it to the drone in-band over the authenticated channel.
      const n = randBytes(16);
      const t = Date.now();
      const m = sha256(Buffer.from(
        `${identity.userId}|${droneId}|${n.toString("base64")}|${t}`, "utf8"));
      const sig = signEcdsa(identity.signingKey, m).toString("base64");
      const fresh = await cloud.authorize({
        userId: identity.userId, droneId, nonceU: n.toString("base64"), ts: t, userSig: sig,
      });
      sendCtrl({ type: "refresh", token: fresh.token, cloudSig: fresh.cloudSig });
    },
    async rekey() {
      const target = epoch + 1;
      const eph2 = ephemeralEcdh();
      const got = new Promise<Buffer>((resolve) => {
        pendingRekey = { epoch: target, resolve };
      });
      sendCtrl({ type: "rekey-init", epoch: target, ePub: eph2.pub.toString("base64") });
      const dronePub2 = await got;
      pendingRekey = null;
      const ikm2 = ecdhSharedSecret(eph2, dronePub2);
      const next = deriveRekeyKeys(ikm2, transcript, target);
      ikm2.fill(0);
      // Retire old epoch keys (intra-session forward secrecy), install new.
      curKU2D.fill(0);
      curKD2U.fill(0);
      curKU2D = next.kU2D;
      curKD2U = next.kD2U;
      epoch = target;
    },
    async applyPolicy(signed) {
      sendCtrl({ type: "policy", scope: signed.scope, ts: signed.ts, sig: signed.sig });
    },
    epoch() {
      return epoch;
    },
    onFrame(cb) {
      listeners.push(cb);
    },
    close() {
      link.close();
    },
  };
}
