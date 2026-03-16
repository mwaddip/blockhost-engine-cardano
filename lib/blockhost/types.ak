use cardano/assets.{PolicyId}

/// Payment asset identifier (policy_id + asset_name)
pub type AssetId {
  policy_id: PolicyId,
  asset_name: ByteArray,
}

/// Subscription datum — stored in each subscriber's UTXO at the validator address
///
/// All time fields use POSIX milliseconds (not slot numbers) because the
/// validator's validity_range is expressed in POSIX time. Slot numbers are
/// not available in the script context.
pub type SubscriptionDatum {
  /// Plan identifier (maps to off-chain plan config)
  plan_id: Int,
  /// Expiration time (POSIX milliseconds — subscription ends at this time)
  expiry: Int,
  /// Subscriber's payment address key hash (for refund verification)
  subscriber_key_hash: ByteArray,
  /// Amount of payment token currently remaining in this UTXO
  amount_remaining: Int,
  /// Cost per collection interval in payment token base units
  rate_per_interval: Int,
  /// Collection interval in milliseconds (e.g. 86_400_000 = 1 day)
  interval_ms: Int,
  /// POSIX ms of the last partial collection (or subscription creation)
  last_collected: Int,
  /// What token was used for payment
  payment_asset: AssetId,
  /// Beacon minting policy hash (for cross-referencing)
  beacon_policy_id: ByteArray,
  /// ECIES-encrypted connection details (for the server to decrypt)
  user_encrypted: ByteArray,
}

/// Plan reference datum — stored in a reference UTXO readable by anyone
pub type PlanDatum {
  plan_id: Int,
  name: ByteArray,
  /// Price per day in payment token base units
  price_per_day: Int,
  /// List of accepted payment token policy IDs
  accepted_payment_assets: List<AssetId>,
  active: Bool,
}

/// NFT reference datum (CIP-68) — stores encrypted connection details
pub type NftReferenceDatum {
  /// ECIES-encrypted connection details
  user_encrypted: ByteArray,
}

/// Subscription validator redeemers
pub type SubscriptionRedeemer {
  /// Service collects payment (server-authorized)
  ServiceCollect
  /// Subscriber cancels and reclaims funds
  SubscriberCancel
  /// Subscriber extends (spend-and-recreate with more funds)
  SubscriberExtend
  /// Server migrates UTXO to a new validator (upgrade path)
  Migrate { new_validator_hash: ByteArray }
}

/// Beacon minting policy redeemers
pub type BeaconRedeemer {
  /// Mint beacon when subscription is created
  CreateSubscription
  /// Burn beacon when subscription is consumed/cancelled
  CloseSubscription
}

/// NFT minting policy redeemers
pub type NftRedeemer {
  /// Mint a new NFT (user token + CIP-68 reference token)
  MintNft
  /// Burn NFT
  BurnNft
}
