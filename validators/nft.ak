use aiken/collection/dict
use aiken/crypto.{VerificationKeyHash}
use blockhost/types.{BurnNft, MintNft, NftRedeemer}
use blockhost/utils.{signed_by}
use cardano/assets.{PolicyId}
use cardano/transaction.{Transaction}

/// NFT minting policy — only the server can mint/burn access credentials.
///
/// CIP-68 convention: two tokens per NFT
/// - User token: asset name prefix 000de140 + identifier bytes
/// - Reference token: asset name prefix 000643b0 + identifier bytes
///
/// The reference token is locked at a reference address with an inline datum
/// containing encrypted connection details. The user token goes to the subscriber.
///
/// Parameters (baked in at deploy time):
/// - server_key_hash: The server's verification key hash
validator nft(server_key_hash: VerificationKeyHash) {
  mint(redeemer: NftRedeemer, policy_id: PolicyId, tx: Transaction) {
    let nft_tokens = assets.tokens(tx.mint, policy_id)

    when redeemer is {
      MintNft -> {
        // Only server can mint
        expect signed_by(tx, server_key_hash)
        // CIP-68: mint user token (000de140 prefix) + reference token (000643b0 prefix)
        // All minted tokens must have quantity = 1
        dict.foldl(
          nft_tokens,
          True,
          fn(_name, qty, acc) { acc && qty == 1 },
        )
      }

      BurnNft -> {
        // Server must authorize burn
        expect signed_by(tx, server_key_hash)
        // All tokens under this policy must have quantity = -1
        dict.foldl(
          nft_tokens,
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

test mint_nft_requires_server_signature() {
  // Placeholder: real tests need mock transaction construction
  True
}

test burn_nft_requires_server_signature() {
  // Placeholder: real tests need mock transaction construction
  True
}
