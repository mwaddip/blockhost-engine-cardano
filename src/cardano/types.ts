/**
 * TypeScript types for Cardano datum and redeemer structures.
 * These match the Aiken validators that will be built in Phase 1b.
 */

// ── Datum structures ─────────────────────────────────────────────────

/** Subscription datum stored at the validator UTXO */
export interface SubscriptionDatum {
  planId: number;
  expirySlot: bigint;        // absolute slot number — subscription ends here
  subscriber: string;        // subscriber payment key hash (hex)
  amountRemaining: bigint;   // payment token amount still in the UTXO
  ratePerInterval: bigint;   // cost per collection interval in token base units
  intervalSlots: bigint;     // collection interval in slots (86400 = ~1 day)
  lastCollectedSlot: bigint; // slot of last collection (or creation)
  paymentAsset: AssetId;     // policy + name
  beaconId: string;          // beacon minting policy hash (hex)
  userEncrypted: string;     // hex-encoded encrypted data
}

/** Cardano native asset identifier */
export interface AssetId {
  policyId: string;          // 56 hex chars
  assetName: string;         // hex-encoded asset name
}

// ── Redeemers ────────────────────────────────────────────────────────

export type SubscriptionRedeemer =
  | { tag: "ServiceCollect" }
  | { tag: "SubscriberCancel" }
  | { tag: "SubscriberExtend" }
  | { tag: "Migrate"; newValidatorHash: string };

export type BeaconRedeemer =
  | { tag: "CreateSubscription" }
  | { tag: "CloseSubscription" };

export type NftRedeemer =
  | { tag: "Mint" }
  | { tag: "UpdateReference" };

// ── Plan reference datum ─────────────────────────────────────────────

/** Plan datum held at the plan reference UTXO */
export interface PlanDatum {
  planId: number;
  name: string;
  pricePerDay: bigint;       // in payment token base units
  paymentAssets: AssetId[];  // allowed payment tokens
  active: boolean;
}

// ── CIP-68 NFT reference datum ───────────────────────────────────────

/** CIP-68 reference datum for access credential NFTs */
export interface NftReferenceDatum {
  userEncrypted: string;     // hex-encoded encrypted connection details
}

// ── Network ──────────────────────────────────────────────────────────

/** Cardano network type */
export type CardanoNetwork = "mainnet" | "preprod" | "preview";
