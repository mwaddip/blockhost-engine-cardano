/**
 * bw swap <amount> <from-token> ada <wallet>
 *
 * Swap native tokens for ADA via a DEX aggregator.
 *
 * TODO: DEX integration not yet implemented.
 * Will require integration with a Cardano DEX (e.g. Minswap or SundaeSwap)
 * and depends on full MeshJS transaction building.
 */

import type { Addressbook } from "../../fund-manager/types.js";
import { resolveToken } from "../cli-utils.js";

/**
 * CLI handler
 */
export async function swapCommand(
  args: string[],
  _book: Addressbook,
): Promise<void> {
  if (args.length < 4) {
    console.error("Usage: bw swap <amount> <from-token> ada <wallet>");
    console.error("  Example: bw swap 100 stable ada hot");
    process.exit(1);
  }

  const [amountStr, fromTokenArg, toTokenArg, walletRole] = args;
  if (!amountStr || !fromTokenArg || !toTokenArg || !walletRole) {
    console.error("Usage: bw swap <amount> <from-token> ada <wallet>");
    process.exit(1);
  }

  if (toTokenArg.toLowerCase() !== "ada") {
    console.error(`Only 'ada' is supported as to-token, got: ${toTokenArg}`);
    process.exit(1);
  }

  const fromAsset = resolveToken(fromTokenArg);
  const label = fromAsset.policyId
    ? `${fromAsset.policyId.slice(0, 8)}...${fromAsset.assetName}`
    : "ADA";

  console.log(
    `[TODO] Swap ${amountStr} ${label} → ADA for wallet ${walletRole}`,
  );
  console.log("TODO: DEX integration not yet implemented.");
  console.log(
    "      Will require a Cardano DEX (e.g. Minswap/SundaeSwap) and MeshJS tx building.",
  );
}
