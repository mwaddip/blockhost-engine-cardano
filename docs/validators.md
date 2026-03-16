# Aiken Validators

Three Plutus validators compiled from Aiken control the on-chain subscription lifecycle. All three are parameterized — key hashes and script hashes are baked in at deploy time via `aiken blueprint apply`.

## Subscription Validator (`validators/subscription.ak`)

Spending validator. Controls all spending of subscription UTXOs locked at the validator address.

### Datum: `SubscriptionDatum`

Stored as an inline datum on every subscription UTXO:

| Field | Type | Description |
|-------|------|-------------|
| `plan_id` | `Int` | Subscription plan identifier (maps to off-chain plan config) |
| `expiry` | `Int` | Expiration timestamp (POSIX milliseconds) |
| `subscriber_key_hash` | `ByteArray` | Subscriber's payment key hash (authorizes cancel/extend) |
| `amount_paid` | `Int` | Amount of payment token locked in this UTXO |
| `payment_asset` | `AssetId` | Token used for payment (`{ policy_id, asset_name }`) |
| `beacon_policy_id` | `ByteArray` | Beacon minting policy hash (for cross-referencing) |
| `user_encrypted` | `ByteArray` | ECIES-encrypted connection details (server decrypts on provisioning) |

### Parameters

| Parameter | Description |
|-----------|-------------|
| `server_key_hash` | Server's verification key hash — authorizes `ServiceCollect` and `Migrate` |
| `service_address_key_hash` | Service treasury key hash — not validated on-chain (enforced off-chain by tx construction) |

### Redeemers

#### `ServiceCollect`

Server collects payment after the subscription period ends.

- Transaction must be signed by `server_key_hash`
- The beacon token must be burned in the same transaction (enforced by the beacon minting policy)
- Funds go to the service address (enforced by off-chain transaction construction)

#### `SubscriberCancel`

Subscriber cancels and reclaims their locked funds.

- Transaction must be signed by `datum.subscriber_key_hash`
- The beacon token must be burned in the same transaction
- Refund goes to the subscriber (enforced off-chain)

#### `SubscriberExtend`

Subscriber extends their subscription by spending the UTXO and recreating it with updated terms.

- Transaction must be signed by `datum.subscriber_key_hash`
- A continuing output must exist at the same script address
- The continuing output must carry an inline datum where:
  - `plan_id`, `subscriber_key_hash`, `payment_asset`, `beacon_policy_id` are unchanged
  - `amount_paid` does not decrease
  - `expiry` does not decrease

#### `Migrate { new_validator_hash }`

Server migrates UTXOs to a new validator version (upgrade path).

- Transaction must be signed by `server_key_hash`
- At least one output must go to the script address identified by `new_validator_hash`

---

## Beacon Minting Policy (`validators/beacon.ak`)

Minting policy. Controls creation and destruction of beacon tokens that make subscription UTXOs discoverable (CIP-89 pattern).

### Beacon Name Computation

Each subscription gets a unique beacon token whose asset name is derived off-chain:

```
beacon_name = sha256(plan_id_bytes(4, big-endian) ++ subscriber_payment_key_hash(28 bytes))
```

Implemented in `src/cardano/beacon.ts`:

```typescript
computeBeaconName(planId: number, subscriberKeyHash: string): string
// Returns 64-char hex (sha256 output)
```

The beacon policy ID + beacon name together form the fully qualified asset: `<policyId><beaconName>`.

### Parameters

| Parameter | Description |
|-----------|-------------|
| `subscription_validator_hash` | Script hash of the subscription validator — ensures beacons only live at the right address |

### Redeemers

#### `CreateSubscription`

Mint one beacon per new subscription.

- All minted tokens under this policy must have quantity `+1`
- At least one output must go to the subscription validator address

#### `CloseSubscription`

Burn beacon when a subscription is consumed or cancelled.

- All tokens under this policy in the transaction must have quantity `-1` (all being burned)

---

## NFT Minting Policy (`validators/nft.ak`)

Minting policy. Controls access credential NFTs following the CIP-68 convention.

### CIP-68 Pattern

Each NFT consists of two tokens minted together under the same policy:

| Token | Asset name prefix | Goes to |
|-------|-------------------|---------|
| User token | `000de140` + identifier bytes | Subscriber's wallet |
| Reference token | `000643b0` + identifier bytes | Reference address (with inline `NftReferenceDatum`) |

The reference token is locked at a reference address that the engine controls. Its inline datum holds:

```
NftReferenceDatum {
  user_encrypted: ByteArray   -- ECIES-encrypted connection details
}
```

The PAM module on VMs reads the GECOS field (set by the provisioner), not the on-chain datum directly.

### Parameters

| Parameter | Description |
|-----------|-------------|
| `server_key_hash` | Server's verification key hash — only the server can mint or burn |

### Redeemers

#### `MintNft`

Mint a new access credential NFT pair (user token + reference token).

- Transaction must be signed by `server_key_hash`
- All minted tokens under this policy must have quantity `+1`

#### `BurnNft`

Burn an existing NFT pair.

- Transaction must be signed by `server_key_hash`
- All tokens under this policy in the transaction must have quantity `-1`

---

## Plan Reference UTXOs

Plan definitions are stored off-chain as reference UTXOs with inline `PlanDatum`:

```
PlanDatum {
  plan_id:                  Int
  name:                     ByteArray
  price_per_day:            Int           -- payment token base units
  accepted_payment_assets:  List<AssetId>
  active:                   Bool
}
```

These UTXOs are readable by anyone (no spending required). The signup page reads them via Blockfrost to display available plans and pricing. Plans are created via `bw plan create` (requires MeshJS integration — see [cli.md](cli.md)).

---

## Parameterization

Validators are parameterized at deploy time using `aiken blueprint apply`. The `plutus.json` blueprint (generated by `aiken build`) contains the unparameterized validator scripts. The deploy script applies the server key hash and other parameters, producing the final script addresses and policy IDs that go into `web3-defaults.yaml`.

```bash
aiken build                         # Produces plutus.json
blockhost-deploy-contracts          # Applies parameters, derives addresses
```

After deployment, the subscription validator address (bech32), beacon policy ID, and NFT policy ID are written to `/etc/blockhost/web3-defaults.yaml`.
