use cardano/assets.{PolicyId}

/// Payment asset identifier (policy_id + asset_name)
pub type AssetId {
  policy_id: PolicyId,
  asset_name: ByteArray,
}

/// Subscription datum — stored in each subscriber's UTXO at the validator address
pub type SubscriptionDatum {
  /// Plan identifier (maps to off-chain plan config)
  plan_id: Int,
  /// Expiration timestamp (POSIX milliseconds)
  expiry: Int,
  /// Subscriber's payment address key hash (for refund verification)
  subscriber_key_hash: ByteArray,
  /// Amount of payment token locked
  amount_paid: Int,
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
