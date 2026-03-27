use aiken/collection/list
use aiken/crypto.{VerificationKeyHash}
use cardano/transaction.{Transaction}

/// Check if a verification key hash is in the transaction's extra signatories
pub fn signed_by(tx: Transaction, key_hash: VerificationKeyHash) -> Bool {
  list.has(tx.extra_signatories, key_hash)
}
