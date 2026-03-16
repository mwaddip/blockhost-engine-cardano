/**
 * bw balance <role> [token]
 *
 * Query ADA and/or native token balance for an address or addressbook role.
 *
 * ADA balance: sum the `amount` array from Blockfrost /addresses/{addr},
 * filtering for unit "lovelace".
 *
 * Token balance: filter the same amount array for the specific asset unit
 * (policyId + assetName, concatenated — Blockfrost's convention).
 *
 * Core function executeBalance() is used by fund-manager as well.
 */

import type { BlockFrostAPI } from "@blockfrost/blockfrost-js";
import type { Addressbook } from "../../fund-manager/types.js";
import type { AssetId } from "../../cardano/types.js";
import {
  resolveAddress,
  resolveToken,
  getBlockfrostClient,
  formatAda,
  formatToken,
} from "../cli-utils.js";

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
 * @param client      Pre-built Blockfrost client (allows injection in tests / fund-manager)
 */
export async function executeBalance(
  roleOrAddr: string,
  tokenArg: string | undefined,
  book: Addressbook,
  client?: BlockFrostAPI,
): Promise<BalanceResult> {
  const address = resolveAddress(roleOrAddr, book);
  const bf = client ?? getBlockfrostClient();

  // Fetch address info from Blockfrost
  let amounts: Array<{ unit: string; quantity: string }>;
  try {
    const info = await bf.addresses(address);
    amounts = info.amount as Array<{ unit: string; quantity: string }>;
  } catch (err: unknown) {
    if (isNotFound(err)) {
      // Address exists but has never received funds — treat as zero
      amounts = [];
    } else {
      throw err;
    }
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

// ── Utility ───────────────────────────────────────────────────────────────────

function isNotFound(err: unknown): boolean {
  return (
    typeof err === "object" &&
    err !== null &&
    "status_code" in err &&
    (err as { status_code: number }).status_code === 404
  );
}
