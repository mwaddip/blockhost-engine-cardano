/**
 * bw set encrypt <nft_id> <data>
 *
 * Update the CIP-68 reference token's datum with new encrypted data.
 *
 * Uses the minimal tx toolkit (src/cardano/) — no Lucid.
 */

import type { Addressbook } from "../../fund-manager/types.js";
import { loadWeb3Config } from "../../fund-manager/web3-config.js";
import { getProvider } from "../../cardano/provider.js";
import { deriveWallet } from "../../cardano/wallet.js";
import { getPaymentKeyHash } from "../../cardano/address.js";
import { Constr, Data } from "../../cardano/data.js";
import { parseKoiosUtxos, buildAndSubmitScriptTx } from "../../cardano/tx.js";
import type { Utxo, Assets } from "../../cardano/tx.js";
import { hexToBytes, bytesToHex, cborArray, cborBytes, decodeCbor } from "../../cardano/cbor.js";
import { referenceTokenAssetName } from "../../nft/mint.js";
import * as fs from "fs";

const CONFIG_DIR = process.env["BLOCKHOST_CONFIG_DIR"] ?? "/etc/blockhost";

// ── Datum encoding ───────────────────────────────────────────────────────────

function encodeNftReferenceDatum(userEncryptedHex: string): string {
  const d = new Constr(0, [userEncryptedHex]);
  return Data.to(d);
}

// ── Script parameterization ─────────────────────────────────────────────────

/**
 * Apply parameters to a UPLC script (Plutus V3).
 *
 * Takes a flat CBOR-encoded UPLC script and wraps it in applied lambdas
 * for each parameter: apply(apply(script, param1), param2)...
 *
 * The script's outer CBOR is: bytes(inner_flat_bytes)
 * The parameterized script is: bytes(apply(original, encoded_params))
 *
 * For Aiken-compiled scripts, parameters are Plutus Data values
 * encoded as CBOR and passed via the double-CBOR wrapping convention.
 *
 * This matches Lucid's applyParamsToScript behavior.
 */
function applyParamsToScript(compiledCode: string, params: string[]): string {
  // The compiledCode is hex CBOR: a single CBOR bytes item containing the flat UPLC
  // To apply parameters, we wrap in Plutus apply nodes.
  // The convention used by CIP-57 / Aiken / Lucid:
  //   1. Decode the outer CBOR bytes wrapper to get the raw program bytes
  //   2. For each param, create: CBOR-array [2, program, CBOR-array [1, param_as_data]]
  //      where 2 = Apply, 1 = Const, and param_as_data is CBOR-in-CBOR (tag 24)
  //   3. Re-wrap in CBOR bytes

  let scriptBytes = hexToBytes(compiledCode);

  // Unwrap outer CBOR bytes if present
  const decoded = decodeCbor(scriptBytes, 0);
  if (decoded.value instanceof Uint8Array) {
    scriptBytes = decoded.value;
  }

  // Apply each parameter
  let program = scriptBytes;
  for (const paramHex of params) {
    // Encode the parameter as Plutus Data CBOR-in-CBOR
    const paramData = hexToBytes(Data.to(paramHex));

    // Build: [2, program, [1, tag24(paramData)]]
    // This is the UPLC Apply(program, Const(paramData)) encoding
    // Using list encoding that Aiken/Lucid expect
    const constNode = cborArray([
      new Uint8Array([0x01]), // Const tag
      cborArray([            // Const value: [type_tag, data]
        new Uint8Array([0x05]), // type tag for Data
        new Uint8Array([0xd8, 0x18, ...cborBytes(paramData)]), // tag 24 + CBOR bytes
      ]),
    ]);

    program = cborArray([
      new Uint8Array([0x02]), // Apply tag
      cborBytes(program),     // wrapped program
      constNode,
    ]).slice(0); // ensure clean copy
  }

  // Re-wrap in CBOR bytes
  return bytesToHex(cborBytes(program));
}

// ── CLI handler ──────────────────────────────────────────────────────────────

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

  // Determine signing role
  const signingRole =
    book["server"]?.keyfile
      ? "server"
      : Object.entries(book).find(([, e]) => e.keyfile)?.[0];
  if (!signingRole) throw new Error("No signing wallet available in addressbook");

  const signerEntry = book[signingRole]!;
  const mnemonic = fs.readFileSync(signerEntry.keyfile!, "utf8").trim();
  const wallet = await deriveWallet(mnemonic, web3.network);
  const provider = getProvider(web3.network, web3.blockfrostProjectId);

  const serverKeyHash = getPaymentKeyHash(wallet.address);
  if (!serverKeyHash) throw new Error("Could not extract payment key hash from signer");

  // Find the UTXO holding the reference token
  console.error(`Looking up reference token: ${refUnit.slice(0, 20)}...`);
  const rawUtxos = await provider.fetchUtxos(wallet.address, refUnit);
  const utxos = parseKoiosUtxos(rawUtxos);

  let refUtxo: Utxo | undefined;
  let refAddress = "";
  for (const u of utxos) {
    if ((u.tokens[refUnit] ?? 0n) > 0n) {
      refUtxo = u;
      // Extract address from raw response
      const rawEntry = (rawUtxos as Array<Record<string, unknown>>).find(
        r => r["tx_hash"] === u.txHash && Number(r["tx_index"] ?? 0) === u.index,
      );
      refAddress = (rawEntry?.["address"] as string) ?? wallet.address;
      break;
    }
  }

  if (!refUtxo) {
    // Try broader search — token might be at a script address
    const holders = await provider.fetchAssetAddresses(refUnit);
    for (const h of holders) {
      const addrUtxos = await provider.fetchUtxos(h.address, refUnit);
      const parsed = parseKoiosUtxos(addrUtxos);
      for (const u of parsed) {
        if ((u.tokens[refUnit] ?? 0n) > 0n) {
          refUtxo = u;
          refAddress = h.address;
          break;
        }
      }
      if (refUtxo) break;
    }
  }

  if (!refUtxo) {
    throw new Error(`Reference token ${refUnit} not found on-chain. Has this NFT been minted?`);
  }

  console.error(`Found at ${refUtxo.txHash}#${refUtxo.index}`);

  // Determine if this is a script address (header nibble 0x1 or 0x3 = script payment)
  const { addressToHex } = await import("../../cardano/tx.js");
  const addrHex = addressToHex(refAddress);
  const headerByte = parseInt(addrHex.slice(0, 2), 16);
  const addrType = (headerByte >> 4) & 0x0f;
  const isScriptAddr = addrType === 1 || addrType === 3 || addrType === 5 || addrType === 7;

  // Encode the new datum
  const newDatumCbor = encodeNftReferenceDatum(data);

  // Output assets: keep reference token + min ADA
  const outputAssets: Assets = {
    lovelace: refUtxo.lovelace > 2_000_000n ? refUtxo.lovelace : 2_000_000n,
    [refUnit]: 1n,
  };

  if (isScriptAddr) {
    // Script spend — load NFT validator
    let plutusPath = "plutus.json";
    if (!fs.existsSync(plutusPath)) {
      plutusPath = `${CONFIG_DIR}/plutus.json`;
    }
    if (!fs.existsSync(plutusPath)) {
      throw new Error("plutus.json not found — cannot spend script-locked reference token");
    }

    const plutus = JSON.parse(fs.readFileSync(plutusPath, "utf8")) as {
      validators: Array<{ title: string; compiledCode: string }>;
    };
    const nftSpend = plutus.validators.find(v => v.title === "nft.nft.else");
    if (!nftSpend) throw new Error("nft.nft.else validator not found in plutus.json");

    const parameterizedScript = applyParamsToScript(nftSpend.compiledCode, [serverKeyHash]);
    const spendRedeemer = Data.to(new Constr(0, []));

    const txHash = await buildAndSubmitScriptTx({
      provider,
      walletAddress: wallet.address,
      scriptInputs: [{
        utxo: refUtxo,
        address: refAddress,
        redeemerCbor: spendRedeemer,
      }],
      outputs: [{
        address: refAddress,
        assets: outputAssets,
        datumCbor: newDatumCbor,
      }],
      spendingScriptCbor: parameterizedScript,
      requiredSigners: [serverKeyHash],
      signingKey: new Uint8Array([...wallet.paymentKey]),
    });

    console.log(txHash);
  } else {
    // Simple spend — UTXO at a regular address
    const txHash = await buildAndSubmitScriptTx({
      provider,
      walletAddress: wallet.address,
      scriptInputs: [],
      outputs: [{
        address: refAddress,
        assets: outputAssets,
        datumCbor: newDatumCbor,
      }],
      signingKey: new Uint8Array([...wallet.paymentKey]),
    });

    console.log(txHash);
  }

  console.error(`Updated reference datum for token ${tokenId}`);
}
