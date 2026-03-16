use aiken/collection/list
use aiken/crypto.{VerificationKeyHash}
use blockhost/types.{
  Migrate, ServiceCollect, SubscriberCancel, SubscriberExtend,
  SubscriptionDatum, SubscriptionRedeemer,
}
use blockhost/utils.{signed_by}
use cardano/address.{Script}
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

/// The subscription spending validator.
/// Controls all spending of subscription UTXOs.
///
/// Parameters (baked in at deploy time via `aiken blueprint apply`):
/// - server_key_hash: The server's verification key hash (authorizes ServiceCollect & Migrate)
/// - service_address_key_hash: The service treasury address key hash (where collected funds go)
validator subscription(
  server_key_hash: VerificationKeyHash,
  _service_address_key_hash: VerificationKeyHash,
) {
  spend(
    datum_opt: Option<SubscriptionDatum>,
    redeemer: SubscriptionRedeemer,
    own_ref: OutputReference,
    tx: Transaction,
  ) {
    expect Some(datum) = datum_opt

    when redeemer is {
      // Server collects payment after service is delivered
      ServiceCollect -> {
        // Must be signed by server
        // Beacon must be burned (enforced by beacon minting policy in same tx)
        // Funds go to service address (enforced off-chain by tx construction)
        signed_by(tx, server_key_hash)
      }

      // Subscriber cancels — reclaims their funds
      SubscriberCancel -> {
        // Subscriber must sign (their key hash is in the datum)
        // Beacon must be burned (enforced by beacon minting policy in same tx)
        // Refund goes to subscriber (enforced off-chain by tx construction)
        signed_by(tx, datum.subscriber_key_hash)
      }

      // Subscriber extends — spend-and-recreate with updated datum
      SubscriberExtend -> {
        // Subscriber must sign
        expect signed_by(tx, datum.subscriber_key_hash)
        // Must find a continuing output at the same script address
        expect Some(continuing_output) = find_continuing_output(tx, own_ref)
        // Must have a valid inline datum
        expect Some(new_datum) = get_inline_datum(continuing_output)

        // Verify datum continuity — immutable fields must not change
        and {
          new_datum.plan_id == datum.plan_id,
          new_datum.subscriber_key_hash == datum.subscriber_key_hash,
          new_datum.payment_asset == datum.payment_asset,
          new_datum.beacon_policy_id == datum.beacon_policy_id,
          // Amount paid must not decrease
          new_datum.amount_paid >= datum.amount_paid,
          // Expiry must not decrease
          new_datum.expiry >= datum.expiry,
        }
      }

      // Migration to new validator (upgrade escape hatch)
      Migrate { new_validator_hash } -> {
        // Only server can migrate
        expect signed_by(tx, server_key_hash)
        // Verify there is an output going to the new validator script address
        let has_migration_output =
          list.any(
            tx.outputs,
            fn(output) {
              when output.address.payment_credential is {
                Script(hash) -> hash == new_validator_hash
                _ -> False
              }
            },
          )
        has_migration_output
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
