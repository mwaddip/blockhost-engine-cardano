/**
 * bw balance <role> [token]
 *
 * Query ADA and/or native token balance for an address or addressbook role.
 * Uses CardanoProvider (Koios or Blockfrost) directly — no Lucid.
 *
 * Core function executeBalance() is used by fund-manager as well.
 */

import type { Addressbook } from "../../fund-manager/types.js";
import type { AssetId } from "../../cardano/types.js";
import {
  resolveAddress,
  resolveToken,
  formatAda,
  formatToken,
} from "../cli-utils.js";
import { getProvider } from "cmttk";
import { loadNetworkConfig } from "../../fund-manager/web3-config.js";
import { parseKoiosUtxos } from "cmttk";

// ── Types ─────────────────────────────────────────────────────────────────────

export interface BalanceResult {
  address: string;
  adaBalance: bigint;       // lovelace
  tokenBalance?: bigint;    // raw token units (if token arg given)
  tokenAsset?: AssetId;
}

// ── Core function (used by fund-manager) ─────────────────────────────────────

/**
 * Query ADA and optionally a native token balance for an address/role.
 *
 * @param roleOrAddr  Addressbook role or bech32 address
 * @param tokenArg    Optional: "ada", "stable", or "policyId.assetName"
 * @param book        Addressbook for role resolution
 */
export async function executeBalance(
  roleOrAddr: string,
  tokenArg: string | undefined,
  book: Addressbook,
): Promise<BalanceResult> {
  const address = resolveAddress(roleOrAddr, book);
  const { network, blockfrostProjectId } = loadNetworkConfig();
  const provider = getProvider(network, blockfrostProjectId);

  // Fetch UTXOs and sum balances
  let amounts: Array<{ unit: string; quantity: string }> = [];
  try {
    const rawUtxos = await provider.fetchUtxos(address);
    const utxos = parseKoiosUtxos(rawUtxos);

    // Aggregate all assets across UTXOs
    const totals = new Map<string, bigint>();
    for (const utxo of utxos) {
      totals.set("lovelace", (totals.get("lovelace") ?? 0n) + utxo.lovelace);
      for (const [unit, qty] of Object.entries(utxo.tokens)) {
        totals.set(unit, (totals.get(unit) ?? 0n) + qty);
      }
    }
    amounts = Array.from(totals.entries()).map(([unit, qty]) => ({
      unit,
      quantity: qty.toString(),
    }));
  } catch {
    // Address not found or no UTXOs — treat as zero
    amounts = [];
  }

  // ADA balance
  const lovelaceEntry = amounts.find((a) => a.unit === "lovelace");
  const adaBalance = BigInt(lovelaceEntry?.quantity ?? "0");

  const result: BalanceResult = { address, adaBalance };

  if (tokenArg) {
    const asset = resolveToken(tokenArg);

    if (asset.policyId === "" && asset.assetName === "") {
      // Requested "ada" — already have it
      return result;
    }

    const unit = asset.policyId + asset.assetName;
    const tokenEntry = amounts.find((a) => a.unit === unit);
    result.tokenBalance = BigInt(tokenEntry?.quantity ?? "0");
    result.tokenAsset = asset;
  }

  return result;
}

// ── CLI handler ───────────────────────────────────────────────────────────────

export async function balanceCommand(
  args: string[],
  book: Addressbook,
): Promise<void> {
  if (args.length < 1) {
    console.error("Usage: bw balance <role> [token]");
    process.exit(1);
  }

  const [roleOrAddr, tokenArg] = args;
  if (!roleOrAddr) {
    console.error("Usage: bw balance <role> [token]");
    process.exit(1);
  }

  const result = await executeBalance(roleOrAddr, tokenArg, book);

  console.log(`\nBalances for ${roleOrAddr} (${result.address}):\n`);
  console.log(`  ADA          ${formatAda(result.adaBalance)}`);

  if (result.tokenBalance !== undefined && result.tokenAsset) {
    const { policyId, assetName } = result.tokenAsset;
    const label = assetName
      ? Buffer.from(assetName, "hex").toString("utf8").replace(/[^\x20-\x7e]/g, "?")
      : policyId.slice(0, 12) + "...";
    console.log(`  ${label.padEnd(12)} ${formatToken(result.tokenBalance, 0, "")}`);
  }

  console.log();
}
