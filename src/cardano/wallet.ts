/**
 * CIP-1852 key derivation from BIP39 mnemonic.
 *
 * Derives payment and stake keys from a mnemonic phrase following
 * Cardano's CIP-1852 derivation standard:
 *   m/1852'/1815'/0'/0/0  — payment key
 *   m/1852'/1815'/0'/2/0  — stake key
 */

import { Bip32PrivateKey } from "@stricahq/bip32ed25519";
import { mnemonicToEntropy, validateMnemonic } from "bip39";
import { pubKeyAddress, serializeAddressObj } from "@meshsdk/core";
import type { CardanoNetwork } from "./types.js";

export interface CardanoWallet {
  paymentKey: Uint8Array;      // Ed25519 private key (signing key)
  paymentPubKey: Uint8Array;   // Ed25519 public key
  paymentKeyHash: string;      // blake2b-224 hash of pubkey (hex)
  stakeKey: Uint8Array;        // stake signing key
  stakePubKey: Uint8Array;     // stake public key
  stakeKeyHash: string;        // blake2b-224 hash of stake pubkey (hex)
  address: string;             // bech32 base address
  network: CardanoNetwork;
}

/**
 * Derive a Cardano wallet from a BIP39 mnemonic.
 * Path: m/1852'/1815'/0' (CIP-1852)
 * Payment key: m/1852'/1815'/0'/0/0
 * Stake key:   m/1852'/1815'/0'/2/0
 */
export async function deriveWallet(
  mnemonic: string,
  network: CardanoNetwork,
): Promise<CardanoWallet> {
  if (!validateMnemonic(mnemonic)) {
    throw new Error("Invalid mnemonic");
  }

  const entropy = mnemonicToEntropy(mnemonic);
  const rootKey = await Bip32PrivateKey.fromEntropy(Buffer.from(entropy, "hex"));

  // CIP-1852 derivation path: m/1852'/1815'/0'
  // Hardened derivation uses index + 0x80000000
  const accountKey = rootKey
    .derive(2147485500)  // 1852' (purpose)
    .derive(2147485463)  // 1815' (coin type)
    .derive(2147483648); // 0'    (account)

  // Payment key: m/1852'/1815'/0'/0/0
  const paymentBip32Key = accountKey.derive(0).derive(0);
  const paymentPrivKey = paymentBip32Key.toPrivateKey();
  const paymentPubKey = paymentPrivKey.toPublicKey();

  // Stake key: m/1852'/1815'/0'/2/0
  const stakeBip32Key = accountKey.derive(2).derive(0);
  const stakePrivKey = stakeBip32Key.toPrivateKey();
  const stakePubKey = stakePrivKey.toPublicKey();

  // Get key hashes (blake2b-224, computed by the library)
  const paymentKeyHash = paymentPubKey.hash().toString("hex");
  const stakeKeyHash = stakePubKey.hash().toString("hex");

  // Build bech32 base address using MeshJS
  const networkId = network === "mainnet" ? 1 : 0;
  const addrObj = pubKeyAddress(paymentKeyHash, stakeKeyHash);
  const address = serializeAddressObj(addrObj, networkId);

  return {
    paymentKey: new Uint8Array(paymentPrivKey.toBytes()),
    paymentPubKey: new Uint8Array(paymentPubKey.toBytes()),
    paymentKeyHash,
    stakeKey: new Uint8Array(stakePrivKey.toBytes()),
    stakePubKey: new Uint8Array(stakePubKey.toBytes()),
    stakeKeyHash,
    address,
    network,
  };
}
