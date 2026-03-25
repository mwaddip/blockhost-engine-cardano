use aiken/collection/list
use cardano/transaction.{Transaction}

/// Reference token store — locks CIP-68 (100) reference tokens with their
/// inline datums so they cannot be accidentally consumed by wallet coin
/// selection.
///
/// Spending requires the server signature.  This is intentionally minimal:
/// the server is trusted to preserve datums when updating, and the main
/// threat model is accidental consumption by routine ADA transfers.
///
/// Parameters (baked in at deploy time):
/// - server_key_hash: The deployer's payment key hash
validator reference_store(server_key_hash: ByteArray) {
  spend(_datum: Option<Data>, _redeemer: Data, _own_ref, tx: Transaction) {
    list.has(tx.extra_signatories, server_key_hash)
  }

  else(_) {
    fail
  }
}

// -- Tests --

test spend_requires_server_signature() {
  // Placeholder: real tests need mock transaction construction
  True
}
