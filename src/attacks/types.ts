// Common shape for every attack scenario.

export interface AttackResult {
  name: string;
  /** true = defense succeeded (attack was blocked); false = attack broke us */
  defended: boolean;
  detail: string;
}
