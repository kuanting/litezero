// Zero-trust cloud authorization service.
//
// The cloud does NOT derive or see session keys. It only:
//   - holds public records about registered users and drones;
//   - verifies users on each request (continuous verification);
//   - signs short-lived AuthTokens that bind a user to a drone + nonce + TTL.
//
// The signed AuthToken is the single artefact that the drone trusts from the
// cloud. Everything else — ECDH, session-key derivation — happens directly
// between the user and the drone.

import http from "node:http";
import {
  exportPublicJwk,
  generateSigningKey,
  importPublicJwk,
  sha256,
  signEcdsa,
  verifyEcdsa,
} from "../crypto/primitives.ts";
import { canonicalToken, policyDigest } from "../protocol/litezero.ts";
import type {
  AuthorizeRequest,
  AuthToken,
  DroneRecord,
  SignedAuthToken,
  UserRecord,
} from "../protocol/messages.ts";
import { CLOUD_PORT, AUTH_TOKEN_TTL_MS } from "../config.ts";

export class CloudService {
  readonly users = new Map<string, UserRecord>();
  readonly drones = new Map<string, DroneRecord>();
  readonly cloudKey = generateSigningKey();

  /* ---------------- registration ---------------- */

  registerUser(rec: UserRecord): void {
    this.users.set(rec.userId, rec);
  }

  /**
   * Rotate a user's verification key. Used for post-compromise recovery:
   * the operator publishes a fresh public key, and subsequent authorization
   * requests must be signed by the matching new private key. Requests
   * signed by the old key will fail verification in `authorize`.
   */
  rotateUser(rec: UserRecord): void {
    if (!this.users.has(rec.userId)) throw new Error("rotateUser: unknown userId");
    this.users.set(rec.userId, rec);
  }

  registerDrone(rec: DroneRecord): void {
    this.drones.set(rec.droneId, rec);
  }

  /**
   * Sign an out-of-band policy attestation for a drone (continuous
   * verification: geo-fence tighten, scope change, revocation). The signature
   * is under sk_C, so the drone authenticates it against its pinned cloud
   * verify key even when the attestation is relayed to the drone over the
   * user's session channel. It carries no key material.
   */
  signPolicy(droneId: string, scope: string[]): { scope: string[]; ts: number; sig: string } {
    const ts = Date.now();
    const sig = signEcdsa(this.cloudKey.privateKey, policyDigest(droneId, scope, ts));
    return { scope, ts, sig: sig.toString("base64") };
  }

  /* ---------------- authorization ---------------- */

  authorize(req: AuthorizeRequest): SignedAuthToken {
    const user = this.users.get(req.userId);
    if (!user) throw new Error("unknown user");

    const drone = this.drones.get(req.droneId);
    if (!drone) throw new Error("unknown drone");

    if (!drone.policy.allowedUsers.includes(req.userId)) {
      throw new Error("policy: user not allowed to control this drone");
    }

    // Continuous verification — re-check the user signature on every request.
    const msg = sha256(
      Buffer.from(
        `${req.userId}|${req.droneId}|${req.nonceU}|${req.ts}`,
        "utf8",
      ),
    );
    const ok = verifyEcdsa(
      importPublicJwk(user.verifyKeyJwk as Parameters<typeof importPublicJwk>[0]),
      msg,
      Buffer.from(req.userSig, "base64"),
    );
    if (!ok) throw new Error("user signature invalid");

    const now = Date.now();
    if (Math.abs(now - req.ts) > 10_000) throw new Error("request clock skew too large");

    // The token carries userVerifyKeyJwk and dronePubKey as an AUTHORIZATION-
    // LAYER convenience (so the cloud's own records travel with the grant).
    // They are NOT the authentication roots: under Option A the drone verifies
    // sigma_U against the owner key it was PINNED with at provisioning, and the
    // user uses the drone's P_D PINNED against the offline operator anchor.
    // This matters because the cloud is only honest-but-vulnerable: a stolen
    // sk_C lets an attacker mint a token advertising its own pk_U or a bogus
    // P_D, but the pinned keys on the endpoints reject both. The cloud thus
    // controls *authorization* (who may fly, for how long), never *identity*.
    const token: AuthToken = {
      userId: req.userId,
      droneId: req.droneId,
      nonceU: req.nonceU,
      iat: now,
      exp: now + AUTH_TOKEN_TTL_MS,
      policy: { scope: ["control", "telemetry"] },
      userVerifyKeyJwk: user.verifyKeyJwk,
      dronePubKey: drone.pubKey,
    };
    const sig = signEcdsa(this.cloudKey.privateKey, canonicalToken(token));
    return {
      token,
      cloudSig: sig.toString("base64"),
      cloudVerifyKeyJwk: exportPublicJwk(this.cloudKey.publicKey),
      // Non-authoritative convenience copy (outside the signature); endpoints
      // use their pinned values, never this. Kept only for the HTTP demo.
      dronePubKey: drone.pubKey,
    };
  }
}

/* ------------------------------------------------------------------ */
/* HTTP wrapper for the multi-process demo                             */
/* ------------------------------------------------------------------ */

async function readBody(req: http.IncomingMessage): Promise<string> {
  return new Promise((resolve, reject) => {
    let data = "";
    req.on("data", (c) => (data += c));
    req.on("end", () => resolve(data));
    req.on("error", reject);
  });
}

export function startCloudServer(cloud: CloudService, port = CLOUD_PORT): http.Server {
  const server = http.createServer(async (req, res) => {
    try {
      if (req.method === "POST" && req.url === "/register/user") {
        const rec = JSON.parse(await readBody(req)) as UserRecord;
        cloud.registerUser(rec);
        res.writeHead(200).end("{}");
        return;
      }
      if (req.method === "POST" && req.url === "/register/drone") {
        const rec = JSON.parse(await readBody(req)) as DroneRecord;
        cloud.registerDrone(rec);
        res.writeHead(200).end("{}");
        return;
      }
      if (req.method === "POST" && req.url === "/authorize") {
        const body = JSON.parse(await readBody(req)) as AuthorizeRequest;
        const signed = cloud.authorize(body);
        res.writeHead(200, { "content-type": "application/json" });
        res.end(JSON.stringify(signed));
        return;
      }
      if (req.method === "GET" && req.url === "/verify-key") {
        res.writeHead(200, { "content-type": "application/json" });
        res.end(JSON.stringify(exportPublicJwk(cloud.cloudKey.publicKey)));
        return;
      }
      res.writeHead(404).end("not found");
    } catch (e) {
      res.writeHead(400, { "content-type": "application/json" });
      res.end(JSON.stringify({ error: (e as Error).message }));
    }
  });
  server.listen(port);
  return server;
}

// Run as standalone process: `tsx src/services/cloud.ts`
if (import.meta.url === `file://${process.argv[1]}`) {
  const cloud = new CloudService();
  startCloudServer(cloud);
  console.log(`[cloud] zero-trust authorization service listening on :${CLOUD_PORT}`);
}
