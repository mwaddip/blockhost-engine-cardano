/**
 * Minimal Cardano transaction builder for ADA and native token transfers.
 *
 * Uses raw CBOR construction (no CML, no Lucid) backed by:
 * - src/cardano/cbor.ts (encoder/decoder)
 * - src/cardano/provider.ts (Koios/Blockfrost queries)
 * - noble-bip32ed25519 (Ed25519 signing via src/cardano/wallet.ts)
 * - bech32 (address encoding)
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
import type { CardanoProvider } from "./provider.js";

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

  // Track what we still need
  const remaining = new Map<string, bigint>();
  for (const [unit, qty] of Object.entries(required)) {
    if (qty > 0n) remaining.set(unit, qty);
  }

  for (const utxo of utxos) {
    if (remaining.size === 0) break;

    let useful = false;
    // Check if this UTXO contributes to any remaining requirement
    if (remaining.has("lovelace") && utxo.lovelace > 0n) useful = true;
    for (const unit of Object.keys(utxo.tokens)) {
      if (remaining.has(unit)) useful = true;
    }

    if (!useful && remaining.has("lovelace")) {
      // Even if it doesn't have specific tokens, ADA is always useful
      useful = utxo.lovelace > 0n;
    }

    if (useful) {
      selected.push(utxo);
      inputTotal.lovelace += utxo.lovelace;
      for (const [unit, qty] of Object.entries(utxo.tokens)) {
        inputTotal[unit] = (inputTotal[unit] ?? 0n) + qty;
      }

      // Update remaining
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

// ── Transaction builder ─────────────────────────────────────────────────────

/** Build, sign, and submit a simple ADA/token transfer. */
export async function buildAndSubmitTransfer(params: {
  provider: CardanoProvider;
  fromAddress: string;
  toAddress: string;
  assets: Assets;
  signingKey: Uint8Array; // 64-byte Ed25519 extended private key
}): Promise<string> {
  const { provider, fromAddress, toAddress, assets, signingKey } = params;

  // 1. Fetch UTXOs
  const rawUtxos = await provider.fetchUtxos(fromAddress);
  const utxos = parseKoiosUtxos(rawUtxos);
  if (utxos.length === 0) throw new Error("No UTXOs at sender address");

  // 2. Get current slot for TTL
  const tip = await provider.fetchTip();
  const ttl = BigInt(tip.slot + 900); // 15 minutes

  // 3. Estimate fee (generous for simple tx)
  const estimatedFee = 200000n;

  // 4. Coin selection
  const required: Assets = { lovelace: assets.lovelace + estimatedFee };
  for (const [unit, qty] of Object.entries(assets)) {
    if (unit !== "lovelace") required[unit] = qty;
  }
  const { selected, inputTotal } = selectUtxos(utxos, required);

  // 5. Build outputs
  const toAddrHex = addressToHex(toAddress);
  const fromAddrHex = addressToHex(fromAddress);

  const outputs: Uint8Array[] = [];

  // Recipient output
  const hasTokens = Object.keys(assets).some((u) => u !== "lovelace");
  if (hasTokens) {
    // Multi-asset output
    const tokenEntries = Object.entries(assets).filter(([u]) => u !== "lovelace");
    const multiAsset = buildMultiAssetCbor(tokenEntries);
    const valueCbor = cborArray([cborUint(assets.lovelace), multiAsset]);
    outputs.push(
      cborMap([
        [cborUint(0n), cborBytes(hexToBytes(toAddrHex))],
        [cborUint(1n), valueCbor],
      ]),
    );
  } else {
    outputs.push(
      cborMap([
        [cborUint(0n), cborBytes(hexToBytes(toAddrHex))],
        [cborUint(1n), cborUint(assets.lovelace)],
      ]),
    );
  }

  // Change output
  const changeLovelace = inputTotal.lovelace - assets.lovelace - estimatedFee;
  const changeTokens: [string, bigint][] = [];
  for (const [unit, qty] of Object.entries(inputTotal)) {
    if (unit === "lovelace") continue;
    const sent = assets[unit] ?? 0n;
    const rem = qty - sent;
    if (rem > 0n) changeTokens.push([unit, rem]);
  }

  if (changeLovelace >= 1000000n || changeTokens.length > 0) {
    const changeLv = changeLovelace < 1000000n ? 1000000n : changeLovelace;
    if (changeTokens.length > 0) {
      const multiAsset = buildMultiAssetCbor(changeTokens);
      const valueCbor = cborArray([cborUint(changeLv), multiAsset]);
      outputs.push(
        cborMap([
          [cborUint(0n), cborBytes(hexToBytes(fromAddrHex))],
          [cborUint(1n), valueCbor],
        ]),
      );
    } else {
      outputs.push(
        cborMap([
          [cborUint(0n), cborBytes(hexToBytes(fromAddrHex))],
          [cborUint(1n), cborUint(changeLv)],
        ]),
      );
    }
  }

  // 6. Sort inputs lexicographically (Conway requirement)
  selected.sort((a, b) => {
    if (a.txHash < b.txHash) return -1;
    if (a.txHash > b.txHash) return 1;
    return a.index - b.index;
  });

  // 7. Build transaction body
  const inputsCbor = cborTag(
    258,
    cborArray(
      selected.map((u) =>
        cborArray([cborBytes(hexToBytes(u.txHash)), cborUint(BigInt(u.index))]),
      ),
    ),
  );

  const txBody = cborMap([
    [cborUint(0n), inputsCbor],    // inputs
    [cborUint(1n), cborArray(outputs)], // outputs
    [cborUint(2n), cborUint(estimatedFee)], // fee
    [cborUint(3n), cborUint(ttl)], // TTL
  ]);

  // 8. Sign — Ed25519 over tx body hash
  const { blake2b } = await import("@noble/hashes/blake2b");
  const txBodyHash = blake2b(txBody, { dkLen: 32 });

  // Import the signing function from noble-bip32ed25519
  const { PrivateKey } = await import("noble-bip32ed25519");
  // signingKey is 64 bytes: kL(32) + kR(32) for extended Ed25519
  const privKey = new PrivateKey(signingKey.slice(0, 32), signingKey.slice(32, 64));
  const signature = privKey.sign(txBodyHash);
  const pubKey = privKey.toPublicKey().toBytes();

  // 9. Build witness set
  const vkeyWitness = cborArray([cborBytes(pubKey), cborBytes(signature)]);
  const witnessSet = cborMap([
    [cborUint(0n), cborArray([vkeyWitness])], // vkey witnesses
  ]);

  // 10. Assemble full transaction: [body, witnesses, true, null]
  const fullTx = cborArray([
    txBody,
    witnessSet,
    new Uint8Array([0xf5]), // true (valid)
    new Uint8Array([0xf6]), // null (no auxiliary data)
  ]);

  // 11. Submit
  const txHash = await provider.submitTx(bytesToHex(fullTx));
  return txHash;
}

// ── Multi-asset CBOR builder ────────────────────────────────────────────────

/** Build CBOR for multi-asset value: Map<PolicyId, Map<AssetName, Qty>> */
function buildMultiAssetCbor(tokens: [string, bigint][]): Uint8Array {
  // Group by policy ID
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
