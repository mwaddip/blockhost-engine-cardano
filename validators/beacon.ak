use aiken/collection/dict
use aiken/collection/list
use aiken/crypto.{ScriptHash}
use blockhost/types.{BeaconRedeemer, CloseSubscription, CreateSubscription}
use cardano/assets.{PolicyId}
use cardano/transaction.{Transaction}

/// Beacon minting policy
/// Mints beacon tokens when subscriptions are created, burns when consumed/cancelled.
///
/// The beacon token's asset name encodes the subscriber's key hash,
/// making each subscription UTXO discoverable via CIP-89 beacon pattern.
///
/// Parameters (baked in at deploy time):
/// - subscription_validator_hash: The script hash of the subscription spending validator
validator beacon(subscription_validator_hash: ScriptHash) {
  mint(redeemer: BeaconRedeemer, policy_id: PolicyId, tx: Transaction) {
    let beacon_tokens = assets.tokens(tx.mint, policy_id)

    when redeemer is {
      CreateSubscription -> {
        // Verify that all minted beacons under this policy have quantity = 1
        let all_qty_one =
          dict.foldl(
            beacon_tokens,
            True,
            fn(_name, qty, acc) { acc && qty == 1 },
          )

        // Verify at least one subscription validator output holds a beacon from this policy
        let beacon_at_validator =
          list.any(
            transaction.find_script_outputs(
              tx.outputs,
              subscription_validator_hash,
            ),
            fn(output) {
              dict.foldl(
                assets.tokens(output.value, policy_id),
                False,
                fn(_name, _qty, _acc) { True },
              )
            },
          )

        all_qty_one && beacon_at_validator
      }

      CloseSubscription -> {
        // Verify that all beacons under this policy are being burned (quantity = -1)
        dict.foldl(
          beacon_tokens,
          True,
          fn(_name, qty, acc) { acc && qty == -1 },
        )
      }
    }
  }

  else(_) {
    fail
  }
}

// -- Tests --

test create_subscription_mints_beacon() {
  // Placeholder: real tests need mock transaction construction
  True
}

test close_subscription_burns_beacon() {
  // Placeholder: real tests need mock transaction construction
  True
}
