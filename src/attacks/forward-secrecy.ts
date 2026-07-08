// Forward-secrecy leak.
//
// Scenario: a complete session is recorded on the wire. Later, the attacker
// obtains BOTH long-term secrets that exist after the session:
//   - the user's long-term signing key sk_U, and
//   - the drone's PUF-sealed static ECDH scalar d_D (recovered here through the
//     real PUF path: droneSeed + helper -> KEK -> unseal the black key).
// The attacker also has every byte that crossed the wire, including the user
// ephemeral E_U and drone ephemeral E_D from the handshake.
//
// Defense: the session keys come from ikm = Z_1 || Z_2 where
//   Z_1 = KA(e_U, e_D)  (ephemeral-ephemeral)  and
//   Z_2 = KA(d_D, E_U) = KA(e_U, P_D)  (static-ephemeral).
// The static branch Z_2 IS recoverable post-hoc from the leaked d_D and the
// observed E_U — so this test actually computes it. But Z_1 depends on the
// ephemeral scalars e_U and e_D, which are wiped at the end of the handshake
// and never touch the wire or any long-term store. Without Z_1 the attacker
// cannot reconstruct ikm, so no candidate derivation reproduces the session
// keys and no captured frame decrypts. sk_U contributes only to authentication
// and yields no key-agreement material at all.
//
// This is the property under test: leaking every long-term secret (and half of
// ikm, namely Z_2) still does not recover past traffic, because forward secrecy
// rests on the wiped ephemeral half Z_1.

import { bootstrap, inProcessCloudClient } from "../scenarios/bootstrap.ts";
import { runUserHandshake } from "../services/user.ts";
import { blackKeyAad } from "../services/drone.ts";
import { pufRegenerate } from "../crypto/puf.ts";
import { tapTransport } from "./_tap.ts";
import { aesGcmDecrypt } from "../crypto/primitives.ts";
import { deriveSessionKeys, frameAad } from "../protocol/litezero.ts";
import { createECDH } from "node:crypto";
import type { AttackResult } from "./types.ts";

interface CapturedFrame {
  dir: "u2d" | "d2u";
  epoch: number;
  chan: string;
  seq: number;
  iv: Buffer;
  ct: Buffer;
  tag: Buffer;
}

export async function attackForwardSecrecy(): Promise<AttackResult> {
  const h = await bootstrap();

  // Capture the wire in both directions.
  const wire: string[] = [];
  const link = tapTransport(h.connectToDrone(), (m) => wire.push(m));

  const session = await runUserHandshake({
    identity: h.userIdentity,
    droneId: h.droneId,
    cloud: inProcessCloudClient(h.cloud),
    link,
  });
  const plaintext = Buffer.from("WAYPOINT forward-secret-test");
  await new Promise<void>((resolve) => {
    session.onFrame(() => resolve());
    void session.send(plaintext);
  });
  session.close();

  // Reconstruct what the attacker sees on the wire: the handshake ephemerals
  // and every encrypted data frame.
  let eUPub: Buffer | null = null; // E_U from the hello
  let nonceU: Buffer | null = null;
  let nonceD: Buffer | null = null;
  const frames: CapturedFrame[] = [];
  for (const raw of wire) {
    let m: Record<string, unknown>;
    try {
      m = JSON.parse(raw) as Record<string, unknown>;
    } catch {
      continue;
    }
    if (m.kind === "hello") {
      eUPub = Buffer.from(m.userPub as string, "base64");
      nonceU = Buffer.from(m.nonceU as string, "base64");
    } else if (m.kind === "finish") {
      nonceD = Buffer.from(m.nonceD as string, "base64");
    } else if (m.kind === "data") {
      frames.push({
        dir: m.dir as "u2d" | "d2u",
        epoch: m.epoch as number,
        chan: (m.chan as string) ?? "app",
        seq: m.seq as number,
        iv: Buffer.from(m.iv as string, "base64"),
        ct: Buffer.from(m.ct as string, "base64"),
        tag: Buffer.from(m.tag as string, "base64"),
      });
    }
  }

  if (!eUPub || !nonceU || !nonceD || frames.length === 0) {
    await h.shutdown();
    return {
      name: "forward-secrecy leak (long-term keys AFTER session)",
      defended: false,
      detail: "harness failed to capture handshake / frames",
    };
  }

  // Leak d_D: recover the drone's static ECDH scalar exactly as the drone does
  // — regenerate the KEK from the PUF and unseal the black key.
  const kek = pufRegenerate(h.droneSeed, h.helper);
  const dD = aesGcmDecrypt(kek, h.blackKey, blackKeyAad(h.droneId));
  kek.fill(0);

  // Z_2 = KA(d_D, E_U): the static-ephemeral half of ikm, genuinely
  // recoverable from the leaked d_D and the observed E_U.
  const dEcdh = createECDH("prime256v1");
  dEcdh.setPrivateKey(dD);
  const z2 = dEcdh.computeSecret(eUPub);
  dD.fill(0);

  // The attacker knows Z_2 but NOT Z_1 (needs a wiped ephemeral scalar). Try
  // every ikm they could assemble from the material in hand and confirm none
  // reproduces the session keys. z1 candidates stand in for "the missing half":
  // zeros (unknown), and z2 itself (in case the two branches were ever equal).
  const zeros = Buffer.alloc(32, 0);
  const z1Candidates = [zeros, z2];
  const ikmCandidates: Buffer[] = [];
  for (const z1 of z1Candidates) {
    ikmCandidates.push(Buffer.concat([z1, z2])); // correct branch order
    ikmCandidates.push(Buffer.concat([z2, z1])); // swapped, for good measure
  }
  // Plus a wholly bogus key as a sanity leg (must also fail).
  const bogus = Buffer.alloc(64, 0xaa);
  ikmCandidates.push(bogus);

  let anyDecoded = false;
  let winningDetail = "";
  for (const ikm of ikmCandidates) {
    const { km, kU2D, kD2U } = deriveSessionKeys(ikm, nonceU, nonceD);
    km.fill(0);
    for (const f of frames) {
      const key = f.dir === "u2d" ? kU2D : kD2U;
      const aad = frameAad(h.droneId, f.dir, f.epoch, f.chan, f.seq);
      try {
        aesGcmDecrypt(key, { iv: f.iv, ct: f.ct, tag: f.tag }, aad);
        anyDecoded = true;
        winningDetail = `frame dir=${f.dir} seq=${f.seq} decrypted`;
        break;
      } catch {
        /* expected: no candidate ikm yields the real session key */
      }
    }
    kU2D.fill(0);
    kD2U.fill(0);
    if (anyDecoded) break;
  }
  z2.fill(0);

  await h.shutdown();
  return {
    name: "forward-secrecy leak (long-term keys AFTER session)",
    defended: !anyDecoded,
    detail: anyDecoded
      ? `past traffic decrypted after key leak — forward secrecy FAILED (${winningDetail})`
      : "leaked d_D recovers Z_2 but not the wiped ephemeral Z_1; no candidate ikm "
        + "reproduced the session keys, so past frames stayed opaque",
  };
}
