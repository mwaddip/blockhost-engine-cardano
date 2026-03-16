use aiken/collection/list
use aiken/crypto.{VerificationKeyHash}
use blockhost/types.{
  Migrate, ServiceCollect, SubscriberCancel, SubscriberExtend,
  SubscriptionDatum, SubscriptionRedeemer,
}
use blockhost/utils.{signed_by}
use cardano/address.{Script, VerificationKey}
use aiken/interval.{Finite}
use cardano/transaction.{InlineDatum, Input, Output, OutputReference, Transaction}

/// Find the script's own input from the transaction inputs
fn find_own_input(
  inputs: List<Input>,
  own_ref: OutputReference,
) -> Option<Input> {
  list.find(inputs, fn(input) { input.output_reference == own_ref })
}

/// Find a continuing output at the same script address as our input
fn find_continuing_output(
  tx: Transaction,
  own_ref: OutputReference,
) -> Option<Output> {
  expect Some(own_input) = find_own_input(tx.inputs, own_ref)
  let own_address = own_input.output.address
  list.find(tx.outputs, fn(output) { output.address == own_address })
}

/// Extract an inline SubscriptionDatum from an output
fn get_inline_datum(output: Output) -> Option<SubscriptionDatum> {
  when output.datum is {
    InlineDatum(data) -> {
      expect datum: SubscriptionDatum = data
      Some(datum)
    }
    _ -> None
  }
}

/// Compute how many complete intervals have elapsed since last collection.
/// Uses tx validity lower bound as the "current" slot (trustless — the node
/// guarantees the tx can only be included at or after this slot).
fn elapsed_intervals(datum: SubscriptionDatum, tx_lower_slot: Int) -> Int {
  let elapsed_slots = tx_lower_slot - datum.last_collected_slot
  if elapsed_slots <= 0 {
    0
  } else {
    elapsed_slots / datum.interval_slots
  }
}

/// Compute the claimable amount based on elapsed intervals.
fn claimable_amount(datum: SubscriptionDatum, tx_lower_slot: Int) -> Int {
  let intervals = elapsed_intervals(datum, tx_lower_slot)
  let earned = intervals * datum.rate_per_interval
  // Can't claim more than what remains
  if earned > datum.amount_remaining {
    datum.amount_remaining
  } else {
    earned
  }
}

/// Extract the transaction's lower validity bound (invalid_before slot).
/// Returns None if no lower bound is set.
fn tx_lower_bound(tx: Transaction) -> Option<Int> {
  when tx.validity_range.lower_bound.bound_type is {
    Finite(slot) -> Some(slot)
    _ -> None
  }
}

/// The subscription spending validator.
/// Controls all spending of subscription UTXOs.
///
/// Parameters (baked in at deploy time via `aiken blueprint apply`):
/// - server_key_hash: The server's verification key hash (authorizes ServiceCollect & Migrate)
/// - service_address_key_hash: The service treasury address key hash (where collected funds go)
validator subscription(
  server_key_hash: VerificationKeyHash,
  service_address_key_hash: VerificationKeyHash,
) {
  spend(
    datum_opt: Option<SubscriptionDatum>,
    redeemer: SubscriptionRedeemer,
    own_ref: OutputReference,
    tx: Transaction,
  ) {
    expect Some(datum) = datum_opt

    when redeemer is {
      // Server collects earned payment — partial collection, UTXO continues
      ServiceCollect -> {
        expect signed_by(tx, server_key_hash)
        // Tx must have a lower validity bound (trustless time reference)
        expect Some(current_slot) = tx_lower_bound(tx)
        let earned = claimable_amount(datum, current_slot)
        // Must have something to claim
        expect earned > 0
        // Must find a continuing output with updated datum
        expect Some(continuing_output) = find_continuing_output(tx, own_ref)
        expect Some(new_datum) = get_inline_datum(continuing_output)
        // Updated slot for next collection
        let intervals = elapsed_intervals(datum, current_slot)
        let new_last_collected =
          datum.last_collected_slot + intervals * datum.interval_slots
        // Validate the continuing output datum
        and {
          new_datum.plan_id == datum.plan_id,
          new_datum.expiry_slot == datum.expiry_slot,
          new_datum.subscriber_key_hash == datum.subscriber_key_hash,
          new_datum.rate_per_interval == datum.rate_per_interval,
          new_datum.interval_slots == datum.interval_slots,
          new_datum.payment_asset == datum.payment_asset,
          new_datum.beacon_policy_id == datum.beacon_policy_id,
          new_datum.user_encrypted == datum.user_encrypted,
          // Amount reduced by exactly what was earned
          new_datum.amount_remaining == datum.amount_remaining - earned,
          // Collection timestamp advanced
          new_datum.last_collected_slot == new_last_collected,
        }
      }

      // Subscriber cancels — fair split: earned to service, remainder to subscriber
      // Beacon is burned, UTXO fully consumed
      SubscriberCancel -> {
        expect signed_by(tx, datum.subscriber_key_hash)
        // Tx must have a lower validity bound
        expect Some(current_slot) = tx_lower_bound(tx)
        let earned = claimable_amount(datum, current_slot)
        let refund = datum.amount_remaining - earned
        // Verify the service gets its earned portion (if any)
        let service_paid =
          if earned > 0 {
            list.any(
              tx.outputs,
              fn(output) {
                when output.address.payment_credential is {
                  VerificationKey(hash) ->
                    hash == service_address_key_hash
                  _ -> False
                }
              },
            )
          } else {
            True
          }
        // Verify the subscriber gets their refund (if any)
        let subscriber_refunded =
          if refund > 0 {
            list.any(
              tx.outputs,
              fn(output) {
                when output.address.payment_credential is {
                  VerificationKey(hash) ->
                    hash == datum.subscriber_key_hash
                  _ -> False
                }
              },
            )
          } else {
            True
          }
        and {
          service_paid,
          subscriber_refunded,
        }
      }

      // Subscriber extends — spend-and-recreate with more funds and/or longer expiry
      SubscriberExtend -> {
        expect signed_by(tx, datum.subscriber_key_hash)
        expect Some(continuing_output) = find_continuing_output(tx, own_ref)
        expect Some(new_datum) = get_inline_datum(continuing_output)

        and {
          // Immutable fields
          new_datum.plan_id == datum.plan_id,
          new_datum.subscriber_key_hash == datum.subscriber_key_hash,
          new_datum.payment_asset == datum.payment_asset,
          new_datum.beacon_policy_id == datum.beacon_policy_id,
          new_datum.rate_per_interval == datum.rate_per_interval,
          new_datum.interval_slots == datum.interval_slots,
          new_datum.last_collected_slot == datum.last_collected_slot,
          // Can only increase
          new_datum.amount_remaining >= datum.amount_remaining,
          new_datum.expiry_slot >= datum.expiry_slot,
        }
      }

      // Migration to new validator (upgrade escape hatch)
      Migrate { new_validator_hash } -> {
        expect signed_by(tx, server_key_hash)
        list.any(
          tx.outputs,
          fn(output) {
            when output.address.payment_credential is {
              Script(hash) -> hash == new_validator_hash
              _ -> False
            }
          },
        )
      }
    }
  }

  else(_) {
    fail
  }
}

// -- Tests --

test service_collect_requires_server_signature() {
  // Placeholder: real tests need mock transaction construction
  // Verifies the type system compiles correctly
  True
}

test subscriber_cancel_requires_subscriber_signature() {
  // Placeholder: real tests need mock transaction construction
  True
}

test subscriber_extend_preserves_datum_invariants() {
  // Placeholder: real tests need mock transaction construction
  True
}

test migrate_requires_server_and_new_output() {
  // Placeholder: real tests need mock transaction construction
  True
}
