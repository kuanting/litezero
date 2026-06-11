// Wire-format types exchanged during the LiteZero protocol.
//
// All binary fields are transported as base64 strings so messages can go over
// JSON-friendly transports (HTTP body, WebSocket text frame).

export type B64 = string;

/* ------------------------------------------------------------------ */
/* Registration                                                       */
/* ------------------------------------------------------------------ */

/** Public record the cloud stores for each user. */
export interface UserRecord {
  userId: string;
  passwordHash: B64; // SHA-256 of password (toy; prod would use Argon2)
  verifyKeyJwk: unknown; // ECDSA P-256 public key
}

/** Public record the cloud stores for each drone. */
export interface DroneRecord {
  droneId: string;
  pubKey: B64; // uncompressed ECDH public key
  policy: {
    allowedUsers: string[];
  };
}

/* ------------------------------------------------------------------ */
/* Zero-trust authorization                                           */
/* ------------------------------------------------------------------ */

export interface AuthorizeRequest {
  userId: string;
  droneId: string;
  nonceU: B64;
  ts: number;
  /** ECDSA over SHA-256(userId || droneId || nonceU || ts). */
  userSig: B64;
}

export interface AuthToken {
  userId: string;
  droneId: string;
  nonceU: B64;
  iat: number;
  exp: number;
  policy: {
    scope: string[];
  };
  /**
   * User's ECDSA verify key, copied into the token by the cloud as an
   * AUTHORIZATION-layer convenience. NOT the authentication root: under
   * Option A the drone verifies sigma_U against the owner key it was PINNED
   * with at provisioning, so a stolen sk_C cannot substitute the attacker's
   * own pk_U here and command the drone.
   */
  userVerifyKeyJwk: unknown;
  /**
   * Drone's long-term ECDH public point P_D = d_D * G. Travels in the token as
   * a convenience, but the user authenticates P_D against the value it PINNED
   * at provisioning (verified offline under the operator trust anchor), and
   * rejects the token if they disagree. A stolen sk_C therefore cannot
   * substitute a bogus P_D to lure the user onto a fake drone.
   */
  dronePubKey: B64;
}

export interface SignedAuthToken {
  token: AuthToken;
  cloudSig: B64; // ECDSA over JSON(token)
  cloudVerifyKeyJwk: unknown; // convenience
  /**
   * Non-authoritative convenience copy of P_D, OUTSIDE the cloud signature.
   * Endpoints must use their pinned values (operator-anchored P_D on the user,
   * pinned owner key on the drone); never trust this field for crypto. Kept
   * only so the HTTP demo can echo it. (Redundant with token.dronePubKey.)
   */
  dronePubKey: B64;
}

/* ------------------------------------------------------------------ */
/* Handshake                                                          */
/* ------------------------------------------------------------------ */

export interface HandshakeHello {
  kind: "hello";
  authToken: AuthToken;
  cloudSig: B64;
  userPub: B64; // ephemeral ECDH pub E_U
  nonceU: B64;
  /**
   * User's proof-of-possession signature: ECDSA_{sk_U}(H("lz/hello/v1" ||
   * canonicalToken(authToken) || userPub || nonceU)). The drone verifies this
   * against the owner key it was PINNED with at provisioning (Option A), not
   * against authToken.userVerifyKeyJwk, before computing any keys. So even an
   * attacker who steals sk_C and mints tokens at will cannot produce a hello
   * the drone accepts without also holding the real sk_U.
   */
  userSig: B64;
}

export interface HandshakeFinish {
  kind: "finish";
  dronePub: B64; // ephemeral ECDH pub
  nonceD: B64;
  macD: B64; // HMAC(km, transcript || "drone")
}

export interface HandshakeAck {
  kind: "ack";
  macU: B64; // HMAC(km, transcript || "user")
}

/* ------------------------------------------------------------------ */
/* Session                                                            */
/* ------------------------------------------------------------------ */

export type Direction = "u2d" | "d2u";

/**
 * Logical sub-channel inside the encrypted session. "app" carries application
 * commands/telemetry; "ctrl" carries the in-band continuous-verification
 * messages (token refresh, epoch rekey, policy push). The channel tag is bound
 * into the AAD so an app frame can never be reinterpreted as a control frame.
 */
export type Channel = "app" | "ctrl";

export interface SessionFrame {
  kind: "data";
  dir: Direction;
  /** Key epoch this frame was sealed under (0 = post-handshake; bumped per rekey). */
  epoch: number;
  /** Sub-channel; absent is treated as "app" for backward compatibility. */
  chan?: Channel;
  seq: number;
  iv: B64;
  ct: B64;
  tag: B64;
}

/* ------------------------------------------------------------------ */
/* In-band continuous-verification control payloads                    */
/* (these are the *plaintext* of a chan:"ctrl" SessionFrame, so they   */
/*  inherit the session channel's confidentiality + authentication)    */
/* ------------------------------------------------------------------ */

/** Re-present a fresh cloud-signed token to extend authorization (TTL). */
export interface RefreshControl {
  type: "refresh";
  token: AuthToken;
  cloudSig: B64;
}

/** Initiate / answer an ephemeral-ephemeral rekey to a new key epoch. */
export interface RekeyControl {
  type: "rekey-init" | "rekey-resp";
  epoch: number;
  ePub: B64; // fresh ephemeral ECDH public point
}

/** Cloud-signed policy attestation (geo-fence tighten, scope change, revoke). */
export interface PolicyControl {
  type: "policy";
  scope: string[];
  ts: number;
  sig: B64; // ECDSA_{sk_C}(H("lz/policy/v1" || droneId || scope || ts))
}

export type SessionControl = RefreshControl | RekeyControl | PolicyControl;

/* ------------------------------------------------------------------ */
/* Generic envelope                                                   */
/* ------------------------------------------------------------------ */

export type WireMessage =
  | HandshakeHello
  | HandshakeFinish
  | HandshakeAck
  | SessionFrame
  | { kind: "error"; reason: string };
