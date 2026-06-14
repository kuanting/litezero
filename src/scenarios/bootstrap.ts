// Shared test harness.
//
// Wires together a cloud service, a drone service, and a user identity, using
// an in-process transport so everything runs inside a single Node process.
// Attack scenarios can either call `harness.cloud.authorize(...)` directly or
// spin up an HTTP server with `startCloudServer`, depending on what they want
// to test.

import { CloudService } from "../services/cloud.ts";
import { attachDrone, enrollDrone } from "../services/drone.ts";
import type { CloudClient, UserIdentity } from "../services/user.ts";
import {
  exportPublicJwk,
  generateSigningKey,
  sha256,
  signEcdsa,
  verifyEcdsa,
} from "../crypto/primitives.ts";
import { droneIdentityDigest } from "../protocol/litezero.ts";
import { generatePufSeed, type PufSeed } from "../crypto/puf.ts";
import {
  inProcessConnect,
  inProcessListen,
} from "../transport/inprocess.ts";
import type { DroneRecord, UserRecord } from "../protocol/messages.ts";
import type { Transport, TransportServer } from "../transport/types.ts";
import type { KeyObject } from "node:crypto";

export interface Harness {
  cloud: CloudService;
  cloudClient: CloudClient;
  droneSeed: PufSeed;
  droneServer: TransportServer;
  droneId: string;
  userIdentity: UserIdentity;
  /** Offline owner trust-anchor public key (Option A root of identity). */
  ownerVerifyKey: KeyObject;
  /** Re-provision (rotate) the drone's pinned user key after a user-key
   *  compromise. Mirrors the in-depot re-enrollment flow. */
  reprovisionUserKey: (userId: string, verifyKey: KeyObject) => void;
  connectToDrone: () => Transport;
  shutdown: () => Promise<void>;
}

/** Wrap a CloudService so it can be passed to the user as a CloudClient. */
export function inProcessCloudClient(cloud: CloudService): CloudClient {
  return {
    async authorize(req) {
      return cloud.authorize(req);
    },
  };
}

export async function bootstrap(opts?: {
  droneId?: string;
  userId?: string;
  /**
   * Override the drone's application handler. Defaults to a simple "ACK:" echo
   * used by the string-based attack scenarios. The MAVLink demo/attack install
   * a real flight stack here so the session carries MAVLink frames.
   */
  onCommand?: (payload: Buffer, reply: (resp: Buffer) => void) => void;
}): Promise<Harness> {
  const droneId = opts?.droneId ?? "drone-alpha";
  const userId = opts?.userId ?? "alice";

  const cloud = new CloudService();

  // Offline owner trust anchor. In a fielded deployment this key is kept
  // offline; it signs each drone's identity (droneId, P_D) so the user can pin
  // P_D independently of the cloud. It never touches a session.
  const owner = generateSigningKey();

  // User registers.
  const userKey = generateSigningKey();
  const passwordHash = sha256(Buffer.from("hunter2", "utf8")).toString("base64");
  const userRec: UserRecord = {
    userId,
    passwordHash,
    verifyKeyJwk: exportPublicJwk(userKey.publicKey),
  };
  cloud.registerUser(userRec);

  // Drone enrolls PUF and registers pub key.
  const droneSeed = generatePufSeed(droneId);
  const { droneEcdhPub, blackKey, helper } = enrollDrone(droneSeed, droneId);
  const droneRec: DroneRecord = {
    droneId,
    pubKey: droneEcdhPub.toString("base64"),
    policy: { allowedUsers: [userId] },
  };
  cloud.registerDrone(droneRec);

  // The owner certifies the drone identity offline; the user provisions P_D by
  // verifying this certificate against the owner trust anchor (Option A).
  const droneIdCert = signEcdsa(
    owner.privateKey,
    droneIdentityDigest(droneId, droneEcdhPub),
  );
  if (
    !verifyEcdsa(
      owner.publicKey,
      droneIdentityDigest(droneId, droneEcdhPub),
      droneIdCert,
    )
  ) {
    throw new Error("bootstrap: owner drone-identity cert failed to verify");
  }
  const pinnedDrones = new Map<string, Buffer>([[droneId, droneEcdhPub]]);

  // Authorized-user keys PINNED on the drone at provisioning (Option A).
  // Mutable so the owner can rotate a user key on re-enrollment.
  const authorizedUserKeys = new Map<string, KeyObject>([
    [userId, userKey.publicKey],
  ]);

  // Drone transport server.
  const droneServer = inProcessListen();
  attachDrone(
    droneServer,
    {
      droneId,
      pufSeed: droneSeed,
      cloudVerifyKey: cloud.cloudKey.publicKey,
      authorizedUserKeys,
      onCommand: opts?.onCommand ?? ((pt, reply) => {
        reply(Buffer.concat([Buffer.from("ACK:", "utf8"), pt]));
      }),
    },
    blackKey,
    helper,
  );

  const identity: UserIdentity = {
    userId,
    signingKey: userKey.privateKey,
    pinnedDrones,
  };

  return {
    cloud,
    cloudClient: inProcessCloudClient(cloud),
    droneSeed,
    droneServer,
    droneId,
    userIdentity: identity,
    ownerVerifyKey: owner.publicKey,
    reprovisionUserKey: (uid, verifyKey) => {
      authorizedUserKeys.set(uid, verifyKey);
    },
    connectToDrone: () => inProcessConnect(droneServer.endpoint()),
    shutdown: async () => {
      await droneServer.close();
    },
  };
}
