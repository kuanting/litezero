// Token-bearer attack.
//
// Threat: the reviewer observed that if the drone treats the AuthToken as a
// bearer token (valid cloud signature + TTL + droneId = accept), an attacker
// who captures a legitimate token in transit could open a new session with
// an attacker-chosen E_U. This would compromise future sessions even without
// any long-term key leak.
//
// Scenario: the attacker taps the network, intercepts a valid (tok, sigma_C)
// produced by the cloud for the real user, and tries to use it to open a
// fresh session with their own ephemeral e_U and no sk_U.
//
// Defense (v2 protocol): the drone's hello-verify step requires sigma_U =
// Sign(sk_U, H(tok || E_U || n_U)) where E_U is the sender's ephemeral. The
// attacker cannot produce a sigma_U that binds their own E_U without sk_U.
// If they re-use the legitimate user's sigma_U (which bound the *original*
// E_U), the drone will verify sigma_U against the attacker's E_U and fail.

import { bootstrap, inProcessCloudClient } from "../scenarios/bootstrap.ts";
import { runUserHandshake } from "../services/user.ts";
import { ephemeralEcdh, randBytes } from "../crypto/primitives.ts";
import type { HandshakeHello } from "../protocol/messages.ts";
import type { AttackResult } from "./types.ts";

export async function attackTokenBearer(): Promise<AttackResult> {
  const h = await bootstrap();

  // Step 1: real user runs authorize() — cloud returns (tok, sigma_C). We
  // "capture" this by letting the user start a handshake but intercepting
  // the hello message before it reaches the drone.
  let capturedHello: HandshakeHello | null = null;
  try {
    await runUserHandshake({
      identity: h.userIdentity,
      droneId: h.droneId,
      cloud: inProcessCloudClient(h.cloud),
      link: h.connectToDrone(),
      tamperHello: (hello) => {
        capturedHello = { ...hello };
        throw new Error("intercepted"); // abort the user side
      },
    });
  } catch {
    /* intercept path */
  }
  if (!capturedHello) {
    await h.shutdown();
    return {
      name: "bearer-token replay with attacker's own e_U (no sk_U)",
      defended: false,
      detail: "harness failed to capture hello",
    };
  }
  // Snapshot for TypeScript: the guard above proves the capture happened.
  const heardHello = capturedHello as HandshakeHello;

  // Step 2: attacker crafts its own hello using the captured (tok, sigma_C)
  // but with its own E_U (no sk_U, so it cannot recompute sigma_U for a
  // fresh E_U). It tries two strategies:
  //   (a) keep the captured sigma_U  — will fail because E_U differs;
  //   (b) forge sigma_U with a random key — will fail ECDSA verify.
  const attackerEph = ephemeralEcdh();

  // The attacker REUSES the captured token and its bound nonceU (so the drone's
  // nonce-desync and single-use guards pass — the token was never delivered, so
  // its nonce is unburned), and substitutes ONLY its own E_U. This drives the
  // request all the way to the drone's proof-of-possession check, which is the
  // defense this scenario advertises; changing nonceU instead would trip the
  // earlier desync guard and mask the PoP check under an unrelated rejection.
  //
  // Strategy (a): splice the captured sigma_U (which bound the ORIGINAL E_U).
  const spliced: HandshakeHello = {
    ...heardHello,
    userPub: attackerEph.pub.toString("base64"),
    // nonceU and userSig kept as captured — sigma_U now covers the wrong E_U.
  };

  // Strategy (b): forge sigma_U with a random key over the attacker's E_U.
  const forgedHello: HandshakeHello = {
    ...heardHello,
    userPub: attackerEph.pub.toString("base64"),
    userSig: randBytes(64).toString("base64"),
  };

  const tryHello = async (hello: HandshakeHello): Promise<string | null> => {
    const link = h.connectToDrone();
    return new Promise<string | null>((resolve) => {
      link.onMessage((s) => {
        try {
          const m = JSON.parse(s);
          if (m.kind === "error") resolve(String(m.reason));
          else resolve(null); // drone returned a finish = attack succeeded!
        } catch {
          resolve(null);
        }
      });
      link.onClose(() => resolve("connection closed"));
      link.send(JSON.stringify(hello));
    });
  };

  const resA = await tryHello(spliced);
  const resB = await tryHello(forgedHello);

  await h.shutdown();
  // The advertised defense is the drone-side proof-of-possession check: sigma_U
  // must bind the sender's own E_U under the pinned sk_U. Assert BOTH strategies
  // are refused SPECIFICALLY there ("invalid user signature on hello"), so an
  // earlier unrelated abort (e.g. nonce desync) cannot be scored as this defense.
  const pop = /invalid user signature on hello/;
  const defended = resA !== null && resB !== null && pop.test(resA) && pop.test(resB);
  return {
    name: "bearer-token replay with attacker's own e_U (no sk_U)",
    defended,
    detail: defended
      ? `drone rejected both splice and forge at the PoP check (${resA} / ${resB})`
      : `token-bearer replay reached wrong stage — spliced=${resA}, forged=${resB}`,
  };
}
