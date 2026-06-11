// Capability-based attack taxonomy.
//
// The v1 post-mortem showed the v1 attack battery was *scenario-based* —
// we picked attacks that felt relevant (MITM, replay, spoof, …) and tested
// those. That's prone to holes: the reviewers found two flaws (stolen sk_C
// alone, and bearer-token splice) that were not expressed by any of the
// named scenarios. A capability-based battery cannot miss those classes
// of flaw in the same way, because it enumerates *what the attacker can
// do* rather than *what the attack is called*.
//
// Each concrete attack scenario in this folder is tagged with:
//   (a) the subset of capabilities the attacker needs,
//   (b) the security goals it probes, and
//   (c) the expected outcome per goal.
//
// The capability matrix runner in scripts/run-capability-matrix.ts
// aggregates across attacks and prints a per-(capability × goal) coverage
// table, so gaps are visible.
//
// If a combination is MISSING (no scenario tests it) and the expected
// outcome is "defended", the framework emits a warning. Over time, every
// combination of interest should be covered by at least one scenario, or
// explicitly marked as OUT-OF-SCOPE.

/* ------------------------------------------------------------------ */
/* Capabilities                                                       */
/* ------------------------------------------------------------------ */

/**
 * Attacker capabilities in the threat model. A real attacker has the UNION
 * of some subset of these; no single attacker has all of them (by the
 * assumptions of the threat model).
 */
export type Capability =
  | "observe_transit"          // read all messages on the wire
  | "tamper_transit"            // rewrite messages on the wire (active MITM)
  | "replay_old_token"          // has a captured, TTL-valid AuthToken
  | "replay_old_frame"          // has a captured session frame
  | "leak_cloud_db"             // has all public records the cloud stores
  | "leak_sk_C"                 // has the cloud's ECDSA signing key
  | "leak_sk_U"                 // has the user's ECDSA signing key
  | "capture_drone_diff_silicon"// has black key + helper on a different PUF
  | "capture_drone_same_silicon"// has full drone with its original PUF
  | "rogue_peer"                // runs a fake drone/user endpoint
  | "unknown_key_share"         // holds a key that the KDF could confuse
  | "kci_drone_static"          // compromised drone static scalar d_D
  | "replay_old_hello"          // has a captured, TTL-valid hello message
  | "inject_pre_session"        // can send frames during the half-open handshake
  | "leak_old_epoch_key"        // has a retired (pre-rekey) directional key/frame
  ;

/* ------------------------------------------------------------------ */
/* Goals                                                              */
/* ------------------------------------------------------------------ */

export type Goal =
  | "G1_session_confidentiality" // attacker cannot derive Ks
  | "G2_mutual_auth"             // user only talks to the real drone, and vice versa
  | "G3_forward_secrecy"         // past sessions stay secret even after long-term compromise
  | "G4_replay_resistance"       // stale artifacts (token, frame) don't yield a fresh session
  | "G5_zero_trust"              // cloud compromise alone doesn't break past/future sessions
  | "G6_post_compromise_recovery"// after key rotation, fresh sessions are safe
  ;

/* ------------------------------------------------------------------ */
/* Expected outcomes                                                  */
/* ------------------------------------------------------------------ */

export type GoalOutcome =
  | "holds"        // attacker should fail; defense is expected
  | "breaks"       // attacker should succeed; we concede this goal under this capability set
  | "out_of_scope" // not claimed against this capability
  ;

/* ------------------------------------------------------------------ */
/* Attack registration                                                */
/* ------------------------------------------------------------------ */

export interface CapabilityCoverage {
  /** Human-readable name of the scenario. */
  scenario: string;
  /** The capability subset the attacker operates with. */
  capabilities: Capability[];
  /** Goals this scenario probes; each has an expected outcome. */
  expect: Partial<Record<Goal, GoalOutcome>>;
}

/**
 * Coverage map: for every named attack function, declare (capabilities,
 * expected outcomes per goal). The runner cross-checks this against the
 * actual `defended` flag returned by the attack.
 */
export const COVERAGE: CapabilityCoverage[] = [
  {
    scenario: "eavesdrop",
    capabilities: ["observe_transit"],
    expect: {
      G1_session_confidentiality: "holds",
      G2_mutual_auth: "holds",
    },
  },
  {
    scenario: "mitm",
    capabilities: ["observe_transit", "tamper_transit"],
    expect: {
      G1_session_confidentiality: "holds",
      G2_mutual_auth: "holds",
    },
  },
  {
    scenario: "replay-token",
    capabilities: ["observe_transit", "replay_old_token"],
    expect: {
      G4_replay_resistance: "holds",
      G2_mutual_auth: "holds",
    },
  },
  {
    scenario: "replay-frame",
    capabilities: ["observe_transit", "replay_old_frame"],
    expect: {
      G4_replay_resistance: "holds",
    },
  },
  {
    scenario: "spoof-drone",
    capabilities: ["rogue_peer", "observe_transit"],
    expect: {
      G2_mutual_auth: "holds",
    },
  },
  {
    scenario: "stolen-cloud-db",
    capabilities: ["leak_cloud_db", "observe_transit"],
    expect: {
      G1_session_confidentiality: "holds",
      G3_forward_secrecy: "holds",
      G5_zero_trust: "holds",
    },
  },
  {
    scenario: "stolen-cloud-key",
    capabilities: ["leak_sk_C", "leak_cloud_db"],
    expect: {
      G2_mutual_auth: "holds",      // stolen sk_C alone cannot produce sigma_U
      G5_zero_trust: "holds",
    },
  },
  {
    scenario: "token-bearer",
    capabilities: ["observe_transit", "replay_old_token"],
    expect: {
      G2_mutual_auth: "holds",      // captured token not reusable with attacker E_U
      G4_replay_resistance: "holds",
    },
  },
  {
    scenario: "captured-drone",
    capabilities: ["capture_drone_diff_silicon", "leak_cloud_db"],
    expect: {
      G1_session_confidentiality: "holds",  // cannot regenerate KEK -> d_D unreadable
      G3_forward_secrecy: "holds",
    },
  },
  {
    scenario: "kci",
    capabilities: ["kci_drone_static"],
    expect: {
      G2_mutual_auth: "holds",  // key-compromise-impersonation: compromised d_D
                                // lets attacker BE the drone but not impersonate
                                // others to the drone.
    },
  },
  {
    scenario: "uks",
    capabilities: ["unknown_key_share", "tamper_transit"],
    expect: {
      G2_mutual_auth: "holds",
    },
  },
  {
    scenario: "forward-secrecy",
    capabilities: ["capture_drone_same_silicon", "observe_transit"],
    expect: {
      G3_forward_secrecy: "holds",  // e_D was zeroized; past transcripts stay secret
    },
  },
  {
    scenario: "post-compromise",
    capabilities: ["leak_sk_U"],
    expect: {
      G6_post_compromise_recovery: "holds", // after rotateUser, fresh session safe
    },
  },
  {
    scenario: "desync-dos",
    capabilities: ["tamper_transit"],
    expect: {
      // DoS is tolerated; we only require that the session never accepts
      // forged plaintext. Availability is out of scope.
      G1_session_confidentiality: "holds",
      G2_mutual_auth: "holds",
    },
  },
  {
    scenario: "replay-and-tamper",
    capabilities: ["observe_transit", "replay_old_token", "tamper_transit"],
    expect: {
      G4_replay_resistance: "holds",
      G2_mutual_auth: "holds",
    },
  },
  {
    scenario: "powerful-attacker",
    capabilities: [
      "observe_transit",
      "tamper_transit",
      "leak_sk_C",
      "leak_cloud_db",
      "replay_old_token",
    ],
    expect: {
      G2_mutual_auth: "holds",
      G4_replay_resistance: "holds",
    },
  },
  {
    scenario: "hello-replay",
    capabilities: ["observe_transit", "replay_old_hello"],
    expect: {
      // A TTL-valid hello replayed on a new connection is rejected by the
      // drone's single-use nonce cache before any key material is touched.
      G4_replay_resistance: "holds",
      G2_mutual_auth: "holds",
    },
  },
  {
    scenario: "pre-ack-injection",
    capabilities: ["inject_pre_session"],
    expect: {
      // The session opens only after tau_U confirms; no frame is actioned in
      // the half-open window.
      G2_mutual_auth: "holds",
    },
  },
  {
    scenario: "stale-epoch-rekey",
    capabilities: ["observe_transit", "replay_old_frame", "leak_old_epoch_key"],
    expect: {
      // After an in-band rekey, a frame from the retired epoch no longer
      // matches the live key — intra-session forward secrecy.
      G3_forward_secrecy: "holds",
      G4_replay_resistance: "holds",
    },
  },
  {
    scenario: "forged-refresh",
    capabilities: ["observe_transit", "tamper_transit"],
    expect: {
      // Only cloud-signed refresh/policy is applied; a relayed forgery is
      // dropped, so an attacker cannot extend authorization or revoke scope.
      G5_zero_trust: "holds",
    },
  },
  {
    scenario: "mavlink-injection",
    capabilities: ["observe_transit", "tamper_transit"],
    expect: {
      // The carried protocol is real MAVLink v2, which on a bare link has no
      // confidentiality and only weak optional signing. The LiteZero tunnel
      // gives it AEAD confidentiality (no plaintext C2 on the wire) and rejects
      // a forged-but-valid MAVLink command injected as a raw session frame.
      G1_session_confidentiality: "holds",
      G2_mutual_auth: "holds",
    },
  },
];

/* ------------------------------------------------------------------ */
/* Gap analysis                                                        */
/* ------------------------------------------------------------------ */

/**
 * Combinations of capabilities we explicitly claim to defend against
 * but which might not be exercised by any single scenario above. The
 * matrix runner highlights missing coverage to draw the eye.
 */
export interface ExpectedDefense {
  capabilities: Capability[];
  goal: Goal;
  rationale: string;
}

export const EXPECTED_DEFENSES: ExpectedDefense[] = [
  {
    capabilities: ["leak_sk_C", "tamper_transit"],
    goal: "G2_mutual_auth",
    rationale:
      "Stolen sk_C lets the attacker mint any token (even one advertising its " +
      "own pk_U), but the drone checks sigma_U against the PINNED owner key, " +
      "not the token's key, so without sk_U no forged hello is accepted.",
  },
  {
    capabilities: ["leak_cloud_db", "observe_transit"],
    goal: "G1_session_confidentiality",
    rationale:
      "Public records + passive observation reveal no session material; " +
      "ECDH ephemerals are never held by the cloud.",
  },
  {
    capabilities: ["capture_drone_diff_silicon", "leak_cloud_db"],
    goal: "G1_session_confidentiality",
    rationale:
      "Black key is useless without the original PUF; attacker cannot " +
      "recover d_D, so Z_2 stays secret.",
  },
  {
    capabilities: ["replay_old_token", "tamper_transit"],
    goal: "G4_replay_resistance",
    rationale:
      "Drone's sigma_U check binds E_U to the nonce_U that the attacker " +
      "did not sign over.",
  },
  {
    capabilities: ["rogue_peer", "observe_transit"],
    goal: "G2_mutual_auth",
    rationale:
      "The user uses the operator-PINNED P_D and rejects any token whose " +
      "dronePubKey disagrees, so a rogue drone's P_D' = d_D' * G is refused " +
      "even if the cloud (or a stolen sk_C) signs a token over it.",
  },
  {
    capabilities: ["observe_transit", "replay_old_hello"],
    goal: "G4_replay_resistance",
    rationale:
      "A captured TTL-valid hello replayed on a fresh connection is rejected " +
      "by the drone's single-use nonce_U cache before any PUF unwrap or scalar " +
      "multiplication, so it neither commands the drone nor amplifies work.",
  },
  {
    capabilities: ["observe_transit", "replay_old_frame", "leak_old_epoch_key"],
    goal: "G3_forward_secrecy",
    rationale:
      "After an in-band epoch rekey the previous directional keys are zeroized; " +
      "a frame (or key) from the retired epoch cannot decrypt or be accepted " +
      "into the new epoch, giving intra-session forward secrecy.",
  },
];

/**
 * Cases where we knowingly concede: with these capabilities, the stated
 * goal cannot be expected to hold. These are NOT failures of the protocol;
 * they are inherent limits of the threat model. The matrix runner labels
 * them "CONCEDED" rather than expecting a defense.
 */
export const CONCEDED: ExpectedDefense[] = [
  {
    capabilities: ["leak_sk_U"],
    goal: "G2_mutual_auth",
    rationale:
      "With sk_U, the attacker IS the user. Post-compromise recovery " +
      "(G6) is the relevant goal instead.",
  },
  {
    capabilities: ["leak_sk_U", "leak_sk_C"],
    goal: "G1_session_confidentiality",
    rationale:
      "The attacker can mount a full handshake as both the user and as " +
      "a cloud-signing authority; session confidentiality is lost until " +
      "key rotation.",
  },
  {
    capabilities: ["capture_drone_same_silicon"],
    goal: "G2_mutual_auth",
    rationale:
      "Attacker now IS the drone; outside the protocol's reach. Forward " +
      "secrecy (G3) still holds for past sessions.",
  },
];
