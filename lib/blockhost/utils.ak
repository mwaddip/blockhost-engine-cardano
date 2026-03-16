use aiken/collection/list
use aiken/crypto.{VerificationKeyHash}
use cardano/address.{Script, VerificationKey}
use cardano/assets.{PolicyId, Value}
use cardano/transaction.{Output, Transaction}

/// Check if a verification key hash is in the transaction's extra signatories
pub fn signed_by(tx: Transaction, key_hash: VerificationKeyHash) -> Bool {
  list.has(tx.extra_signatories, key_hash)
}

/// Check that an output goes to a specific payment key hash address
pub fn output_to_key_hash(output: Output, key_hash: ByteArray) -> Bool {
  when output.address.payment_credential is {
    VerificationKey(hash) -> hash == key_hash
    _ -> False
  }
}

/// Get the total value of a specific asset in a Value
pub fn asset_amount(
  value: Value,
  policy_id: PolicyId,
  asset_name: ByteArray,
) -> Int {
  assets.quantity_of(value, policy_id, asset_name)
}

/// Check that a beacon token with specific policy and name exists in a value
pub fn has_beacon(
  value: Value,
  beacon_policy: PolicyId,
  beacon_name: ByteArray,
) -> Bool {
  asset_amount(value, beacon_policy, beacon_name) == 1
}

/// Find outputs paying to a specific script hash
pub fn find_script_outputs(
  outputs: List<Output>,
  script_hash: ByteArray,
) -> List<Output> {
  list.filter(
    outputs,
    fn(output) {
      when output.address.payment_credential is {
        Script(hash) -> hash == script_hash
        _ -> False
      }
    },
  )
}
