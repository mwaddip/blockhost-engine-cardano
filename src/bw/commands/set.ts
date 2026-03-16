/**
 * bw set encrypt <nft_id> <data>
 *
 * Update the CIP-68 reference token's datum with new encrypted data.
 *
 * Finds the reference token UTXO (identified by the CIP-68 (100) asset name),
 * spends it, and recreates it with an updated NftReferenceDatum containing
 * the new userEncrypted value.
 *
 * Uses Lucid Evolution for transaction building and submission.
 */

import { Constr, Data } from "@lucid-evolution/lucid";
import type { Addressbook } from "../../fund-manager/types.js";
import { initLucidWithWallet } from "../lucid-helpers.js";
import { loadWeb3Config } from "../../fund-manager/web3-config.js";
import { referenceTokenAssetName } from "../../nft/mint.js";

// ── Datum encoding ───────────────────────────────────────────────────────────

/**
 * Encode an NftReferenceDatum to CBOR hex.
 *
 * Aiken NftReferenceDatum = Constr(0, [user_encrypted: ByteArray])
 */
function encodeNftReferenceDatum(userEncryptedHex: string): string {
  const d = new Constr(0, [userEncryptedHex]);
  return Data.to(d);
}

// ── CLI handler ──────────────────────────────────────────────────────────────

/**
 * CLI handler
 */
export async function setCommand(
  args: string[],
  book: Addressbook,
): Promise<void> {
  const [subCommand, ...rest] = args;

  if (subCommand === "encrypt") {
    await setEncryptCommand(rest, book);
    return;
  }

  console.error("Usage: bw set encrypt <nft_id> <data>");
  process.exit(1);
}

async function setEncryptCommand(
  args: string[],
  book: Addressbook,
): Promise<void> {
  if (args.length < 2) {
    console.error("Usage: bw set encrypt <nft_id> <data>");
    console.error("  <nft_id>  — integer token ID");
    console.error("  <data>    — hex-encoded encrypted data");
    process.exit(1);
  }

  const [nftIdStr, data] = args;
  if (!nftIdStr || !data) {
    console.error("Usage: bw set encrypt <nft_id> <data>");
    process.exit(1);
  }

  const tokenId = parseInt(nftIdStr, 10);
  if (!Number.isInteger(tokenId) || tokenId < 0) {
    console.error(`Invalid nft_id: ${nftIdStr}`);
    process.exit(1);
  }

  const web3 = loadWeb3Config();
  const nftPolicyId = web3.nftPolicyId;

  // Compute the CIP-68 reference token unit
  const refAssetName = referenceTokenAssetName(tokenId);
  const refUnit = nftPolicyId + refAssetName;

  // Determine signing role — prefer "server"
  const signingRole =
    book["server"]?.keyfile
      ? "server"
      : Object.entries(book).find(([, e]) => e.keyfile)?.[0];
  if (!signingRole) {
    throw new Error("No signing wallet available in addressbook");
  }

  const lucid = await initLucidWithWallet(signingRole, book);

  // Find the UTXO holding the reference token
  console.error(`Looking up reference token: ${refUnit.slice(0, 20)}...`);
  let refUtxo;
  try {
    refUtxo = await lucid.utxoByUnit(refUnit);
  } catch {
    throw new Error(
      `Reference token ${refUnit} not found on-chain. Has this NFT been minted?`,
    );
  }

  console.error(
    `Found at ${refUtxo.txHash}#${refUtxo.outputIndex}`,
  );

  // The reference token is held at a script address.
  // To spend it, we need the NFT minting policy as a spending validator.
  // For now, we treat this as a simple spend if the UTXO is at our own address,
  // or as a script spend if it's at a script address.

  const { getAddressDetails } = await import("@lucid-evolution/lucid");
  const utxoAddrDetails = getAddressDetails(refUtxo.address);
  const isScriptAddr = utxoAddrDetails.paymentCredential?.type === "Script";

  // Encode the new datum
  const newDatumCbor = encodeNftReferenceDatum(data);

  // Build the output assets — same as input (keep the reference token + min ADA)
  const outputAssets: Record<string, bigint> = {
    lovelace: refUtxo.assets["lovelace"] ?? 2_000_000n,
    [refUnit]: 1n,
  };

  let tx;
  if (isScriptAddr) {
    // Script spend — we need the NFT validator and an UpdateReference-like redeemer
    // NftRedeemer in the Aiken contract is: MintNft (index 0) | BurnNft (index 1)
    // For updating the reference datum, we use the spending validator's redeemer.
    // Since the Aiken contract defines nft.nft.mint (minting) and nft.nft.else (spend),
    // the spend redeemer is typically Void (any data). We pass unit/void.
    const spendRedeemer = Data.to(new Constr(0, []));

    // Load the NFT validator script for spending
    const fs = await import("fs");
    const CONFIG_DIR = process.env["BLOCKHOST_CONFIG_DIR"] ?? "/etc/blockhost";
    let plutusPath = "plutus.json";
    if (!fs.existsSync(plutusPath)) {
      plutusPath = `${CONFIG_DIR}/plutus.json`;
    }

    if (fs.existsSync(plutusPath)) {
      const { applyParamsToScript } = await import("@lucid-evolution/lucid");
      const plutus = JSON.parse(fs.readFileSync(plutusPath, "utf8")) as {
        validators: Array<{ title: string; compiledCode: string }>;
      };
      const nftSpend = plutus.validators.find(
        (v) => v.title === "nft.nft.else",
      );

      if (nftSpend) {
        // NFT validator takes server_key_hash as parameter
        const signerAddr = await lucid.wallet().address();
        const signerDetails = getAddressDetails(signerAddr);
        const serverKeyHash = signerDetails.paymentCredential?.hash;
        if (!serverKeyHash) {
          throw new Error("Could not extract payment key hash from signer");
        }

        const parameterizedScript = applyParamsToScript(
          nftSpend.compiledCode,
          [serverKeyHash],
        );

        const nftValidator = {
          type: "PlutusV3" as const,
          script: parameterizedScript,
        };

        tx = lucid
          .newTx()
          .collectFrom([refUtxo], spendRedeemer)
          .attach.SpendingValidator(nftValidator)
          .addSignerKey(serverKeyHash)
          .pay.ToAddressWithData(
            refUtxo.address,
            { kind: "inline", value: newDatumCbor },
            outputAssets,
          );
      } else {
        throw new Error("nft.nft.else validator not found in plutus.json");
      }
    } else {
      throw new Error(
        "plutus.json not found — cannot spend script-locked reference token",
      );
    }
  } else {
    // Simple spend — UTXO is at a regular address (e.g., during testing)
    tx = lucid
      .newTx()
      .pay.ToAddressWithData(
        refUtxo.address,
        { kind: "inline", value: newDatumCbor },
        outputAssets,
      );
  }

  const completed = await tx.complete();
  const signed = await completed.sign.withWallet().complete();
  const txHash = await signed.submit();
  console.log(txHash);
  console.error(
    `Updated reference datum for token ${tokenId}`,
  );
}
