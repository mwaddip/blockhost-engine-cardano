/**
 * Minimal Cardano transaction builder for ADA and native token transfers.
 *
 * Uses raw CBOR construction (no CML, no Lucid) backed by:
 * - src/cardano/cbor.ts (encoder/decoder)
 * - src/cardano/provider.ts (Koios/Blockfrost queries + protocol params)
 * - noble-bip32ed25519 (Ed25519 signing)
 * - bech32 (address encoding)
 *
 * Fee calculation: two-pass deterministic (build → measure → compute → rebuild).
 */

import {
  cborUint,
  cborBytes,
  cborArray,
  cborMap,
  cborTag,
  hexToBytes,
  bytesToHex,
} from "./cbor.js";
import type { CardanoProvider, ProtocolParams } from "./provider.js";
import { PrivateKey } from "noble-bip32ed25519";
import { blake2b } from "@noble/hashes/blake2b";

// ── Types ───────────────────────────────────────────────────────────────────

/** A parsed UTXO from Koios /address_utxos response. */
export interface Utxo {
  txHash: string;
  index: number;
  lovelace: bigint;
  /** Tokens as { "policyId+assetNameHex": quantity } */
  tokens: Record<string, bigint>;
}

/** Assets for a transaction output. lovelace is always present. */
export interface Assets {
  lovelace: bigint;
  [unit: string]: bigint;
}

// ── Address helpers ─────────────────────────────────────────────────────────

const BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

/** Decode a bech32 Cardano address to raw bytes (hex). */
export function addressToHex(addr: string): string {
  const sep = addr.lastIndexOf("1");
  const data: number[] = [];
  for (let i = sep + 1; i < addr.length; i++) {
    const v = BECH32_CHARSET.indexOf(addr.charAt(i));
    if (v === -1) throw new Error("Invalid bech32 character");
    data.push(v);
  }
  // Remove 6-byte checksum
  const words = data.slice(0, -6);
  // Convert 5-bit groups → 8-bit bytes
  let acc = 0;
  let bits = 0;
  const result: number[] = [];
  for (const w of words) {
    acc = (acc << 5) | w;
    bits += 5;
    while (bits >= 8) {
      bits -= 8;
      result.push((acc >> bits) & 0xff);
    }
  }
  return result.map((b) => b.toString(16).padStart(2, "0")).join("");
}

// ── Parse Koios UTXOs ───────────────────────────────────────────────────────

/** Parse Koios /address_utxos response into typed Utxo[]. */
export function parseKoiosUtxos(raw: unknown[]): Utxo[] {
  return (raw as Array<Record<string, unknown>>).map((u) => {
    const tokens: Record<string, bigint> = {};
    const assetList = u["asset_list"] as Array<Record<string, string>> | undefined;
    if (assetList) {
      for (const a of assetList) {
        const unit = (a["policy_id"] ?? "") + (a["asset_name"] ?? "");
        tokens[unit] = BigInt(a["quantity"] ?? "0");
      }
    }
    return {
      txHash: u["tx_hash"] as string,
      index: Number(u["tx_index"] ?? 0),
      lovelace: BigInt((u["value"] as string) ?? "0"),
      tokens,
    };
  });
}

// ── Coin selection ──────────────────────────────────────────────────────────

/** Simple greedy coin selection. Returns selected UTXOs or throws. */
export function selectUtxos(
  utxos: Utxo[],
  required: Assets,
): { selected: Utxo[]; inputTotal: Assets } {
  const selected: Utxo[] = [];
  const inputTotal: Assets = { lovelace: 0n };

  const remaining = new Map<string, bigint>();
  for (const [unit, qty] of Object.entries(required)) {
    if (qty > 0n) remaining.set(unit, qty);
  }

  for (const utxo of utxos) {
    if (remaining.size === 0) break;

    let useful = false;
    if (remaining.has("lovelace") && utxo.lovelace > 0n) useful = true;
    for (const unit of Object.keys(utxo.tokens)) {
      if (remaining.has(unit)) useful = true;
    }
    if (!useful && remaining.has("lovelace") && utxo.lovelace > 0n) useful = true;

    if (useful) {
      selected.push(utxo);
      inputTotal.lovelace += utxo.lovelace;
      for (const [unit, qty] of Object.entries(utxo.tokens)) {
        inputTotal[unit] = (inputTotal[unit] ?? 0n) + qty;
      }
      for (const [unit, needed] of remaining) {
        const have = unit === "lovelace" ? inputTotal.lovelace : (inputTotal[unit] ?? 0n);
        if (have >= needed) remaining.delete(unit);
      }
    }
  }

  if (remaining.size > 0) {
    const missing = Array.from(remaining.entries())
      .map(([u, q]) => `${u}: need ${q}, have ${u === "lovelace" ? inputTotal.lovelace : (inputTotal[u] ?? 0n)}`)
      .join(", ");
    throw new Error(`Insufficient funds: ${missing}`);
  }

  return { selected, inputTotal };
}

// ── Fee calculation ─────────────────────────────────────────────────────────

/** Calculate the minimum fee for a transaction of the given byte size. */
export function calculateFee(txSizeBytes: number, pp: ProtocolParams): bigint {
  return BigInt(pp.minFeeA) * BigInt(txSizeBytes) + BigInt(pp.minFeeB);
}

// ── CBOR builders ───────────────────────────────────────────────────────────

/** Sort inputs lexicographically by (txHash, index) — Conway requirement. */
function sortInputs(utxos: Utxo[]): Utxo[] {
  return [...utxos].sort((a, b) => {
    if (a.txHash < b.txHash) return -1;
    if (a.txHash > b.txHash) return 1;
    return a.index - b.index;
  });
}

/** Encode transaction inputs as CBOR (tag 258 set). */
function buildInputsCbor(utxos: Utxo[]): Uint8Array {
  return cborTag(
    258,
    cborArray(
      utxos.map((u) =>
        cborArray([cborBytes(hexToBytes(u.txHash)), cborUint(BigInt(u.index))]),
      ),
    ),
  );
}

/** Build CBOR for a simple output (ADA only or ADA + tokens). */
function buildOutputCbor(addrHex: string, lovelace: bigint, tokens?: [string, bigint][]): Uint8Array {
  const addrBytes = cborBytes(hexToBytes(addrHex));
  if (tokens && tokens.length > 0) {
    const multiAsset = buildMultiAssetCbor(tokens);
    return cborMap([
      [cborUint(0n), addrBytes],
      [cborUint(1n), cborArray([cborUint(lovelace), multiAsset])],
    ]);
  }
  return cborMap([
    [cborUint(0n), addrBytes],
    [cborUint(1n), cborUint(lovelace)],
  ]);
}

/** Build CBOR for multi-asset value: Map<PolicyId, Map<AssetName, Qty>> */
function buildMultiAssetCbor(tokens: [string, bigint][]): Uint8Array {
  const byPolicy = new Map<string, [string, bigint][]>();
  for (const [unit, qty] of tokens) {
    const policyId = unit.slice(0, 56);
    const assetName = unit.slice(56);
    let list = byPolicy.get(policyId);
    if (!list) {
      list = [];
      byPolicy.set(policyId, list);
    }
    list.push([assetName, qty]);
  }

  const policyEntries: [Uint8Array, Uint8Array][] = [];
  for (const [policyId, assets] of byPolicy) {
    const assetEntries: [Uint8Array, Uint8Array][] = assets.map(([name, qty]) => [
      cborBytes(hexToBytes(name)),
      cborUint(qty),
    ]);
    policyEntries.push([cborBytes(hexToBytes(policyId)), cborMap(assetEntries)]);
  }
  return cborMap(policyEntries);
}

/** Build a transaction body CBOR map. */
function buildTxBody(
  inputs: Utxo[],
  outputs: Uint8Array[],
  fee: bigint,
  ttl: bigint,
): Uint8Array {
  return cborMap([
    [cborUint(0n), buildInputsCbor(inputs)],
    [cborUint(1n), cborArray(outputs)],
    [cborUint(2n), cborUint(fee)],
    [cborUint(3n), cborUint(ttl)],
  ]);
}

/** Sign a tx body hash and return the full witness set CBOR. */
function buildWitnessSet(
  txBodyHash: Uint8Array,
  kL: Uint8Array,
  kR: Uint8Array,
  PrivateKey: typeof import("noble-bip32ed25519").PrivateKey,
): {
  witnessSet: Uint8Array;
  pubKeyBytes: Uint8Array;
} {
  const privKey = new PrivateKey(kL, kR);
  const signature = privKey.sign(txBodyHash);
  const pubKeyBytes = privKey.toPublicKey().toBytes();

  const vkeyWitness = cborArray([cborBytes(pubKeyBytes), cborBytes(signature)]);
  const witnessSet = cborMap([
    [cborUint(0n), cborArray([vkeyWitness])],
  ]);
  return { witnessSet, pubKeyBytes };
}

/** Assemble a full signed transaction from body + witness set. */
function assembleTx(txBody: Uint8Array, witnessSet: Uint8Array): Uint8Array {
  return cborArray([
    txBody,
    witnessSet,
    new Uint8Array([0xf5]), // true (isValid)
    new Uint8Array([0xf6]), // null (no auxiliary data)
  ]);
}

// ── Transaction builder ─────────────────────────────────────────────────────

/** Build, sign, and submit a simple ADA/token transfer with proper fee calculation. */
export async function buildAndSubmitTransfer(params: {
  provider: CardanoProvider;
  fromAddress: string;
  toAddress: string;
  assets: Assets;
  signingKey: Uint8Array; // 64-byte Ed25519 extended private key (kL + kR)
}): Promise<string> {
  const { provider, fromAddress, toAddress, assets, signingKey } = params;
  const kL = signingKey.slice(0, 32);
  const kR = signingKey.slice(32, 64);

  // 1. Fetch UTXOs, protocol params, and tip concurrently
  const [rawUtxos, pp, tip] = await Promise.all([
    provider.fetchUtxos(fromAddress),
    provider.fetchProtocolParams(),
    provider.fetchTip(),
  ]);

  const utxos = parseKoiosUtxos(rawUtxos);
  if (utxos.length === 0) throw new Error("No UTXOs at sender address");
  const ttl = BigInt(tip.slot + 900);

  const toAddrHex = addressToHex(toAddress);
  const fromAddrHex = addressToHex(fromAddress);

  // 2. First pass: build with a generous placeholder fee to determine coin selection
  const maxFee = 500000n; // 0.5 ADA — well above any simple tx fee
  const required: Assets = { lovelace: assets.lovelace + maxFee };
  for (const [unit, qty] of Object.entries(assets)) {
    if (unit !== "lovelace") required[unit] = qty;
  }
  const { selected, inputTotal } = selectUtxos(utxos, required);
  const sortedInputs = sortInputs(selected);

  // Compute change tokens (same regardless of fee)
  const changeTokens: [string, bigint][] = [];
  for (const [unit, qty] of Object.entries(inputTotal)) {
    if (unit === "lovelace") continue;
    const sent = assets[unit] ?? 0n;
    const rem = qty - sent;
    if (rem > 0n) changeTokens.push([unit, rem]);
  }

  // Helper: build outputs for a given fee
  const hasTokens = Object.keys(assets).some((u) => u !== "lovelace");
  const tokenEntries = Object.entries(assets).filter(([u]) => u !== "lovelace");

  function buildOutputs(fee: bigint): Uint8Array[] {
    const outs: Uint8Array[] = [];

    // Recipient output
    if (hasTokens) {
      outs.push(buildOutputCbor(toAddrHex, assets.lovelace, tokenEntries));
    } else {
      outs.push(buildOutputCbor(toAddrHex, assets.lovelace));
    }

    // Change output
    const changeLv = inputTotal.lovelace - assets.lovelace - fee;
    if (changeLv >= 1000000n || changeTokens.length > 0) {
      const actualChangeLv = changeLv < 1000000n ? 1000000n : changeLv;
      if (changeTokens.length > 0) {
        outs.push(buildOutputCbor(fromAddrHex, actualChangeLv, changeTokens));
      } else {
        outs.push(buildOutputCbor(fromAddrHex, actualChangeLv));
      }
    }

    return outs;
  }

  // 3. First pass: build full tx with placeholder fee to measure size
  const firstOutputs = buildOutputs(maxFee);
  const firstBody = buildTxBody(sortedInputs, firstOutputs, maxFee, ttl);
  const firstBodyHash = blake2b(firstBody, { dkLen: 32 });
  const { witnessSet: firstWitness } = buildWitnessSet(firstBodyHash, kL, kR, PrivateKey);
  const firstTx = assembleTx(firstBody, firstWitness);

  // 4. Calculate exact fee from measured size
  const exactFee = calculateFee(firstTx.length, pp);

  // 5. Second pass: rebuild with correct fee
  const finalOutputs = buildOutputs(exactFee);
  const finalBody = buildTxBody(sortedInputs, finalOutputs, exactFee, ttl);
  const finalBodyHash = blake2b(finalBody, { dkLen: 32 });
  const { witnessSet: finalWitness } = buildWitnessSet(finalBodyHash, kL, kR, PrivateKey);
  const finalTx = assembleTx(finalBody, finalWitness);

  // Sanity check: the fee we computed covers the final tx size
  const verifyFee = calculateFee(finalTx.length, pp);
  if (verifyFee > exactFee) {
    // Size grew (fee field encoding changed) — use the larger fee
    // This can happen if the fee shrink causes the CBOR encoding to change size,
    // but since we go from a larger placeholder to a smaller exact fee, the change
    // output grows and the tx size stays the same or shrinks. If it grew, rebuild.
    const safeOutputs = buildOutputs(verifyFee);
    const safeBody = buildTxBody(sortedInputs, safeOutputs, verifyFee, ttl);
    const safeBodyHash = blake2b(safeBody, { dkLen: 32 });
    const { witnessSet: safeWitness } = buildWitnessSet(safeBodyHash, kL, kR, PrivateKey);
    const safeTx = assembleTx(safeBody, safeWitness);

    const txHash = await provider.submitTx(bytesToHex(safeTx));
    return txHash;
  }

  // 6. Submit
  const txHash = await provider.submitTx(bytesToHex(finalTx));
  return txHash;
}
