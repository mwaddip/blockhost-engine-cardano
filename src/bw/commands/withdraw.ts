/**
 * bw withdraw <to>
 *
 * Batch-collect mature subscription UTXOs from the validator script.
 *
 * TODO: Requires building a transaction that consumes multiple script UTXOs
 * with a ServiceCollect redeemer. This is complex and depends on full
 * MeshJS integration plus a funded testnet wallet.
 *
 * Core function executeWithdraw() is used by fund-manager.
 */

import type { Addressbook } from "../../fund-manager/types.js";
import { resolveAddress } from "../cli-utils.js";

/**
 * Core withdraw operation — used by both CLI and fund-manager.
 *
 * @param toRole  Addressbook role or bech32 address to receive collected ADA
 * @param book    Addressbook
 */
export async function executeWithdraw(
  toRole: string,
  book: Addressbook,
): Promise<void> {
  const toAddress = resolveAddress(toRole, book);
  console.log(`[TODO] Batch collection to ${toAddress}`);
  console.log("TODO: batch collection not yet implemented.");
  console.log(
    "      Requires MeshJS tx builder consuming multiple validator UTXOs",
    "with ServiceCollect redeemer.",
  );
  throw new Error("executeWithdraw: not yet implemented (MeshJS tx building pending)");
}

/**
 * CLI handler
 */
export async function withdrawCommand(
  args: string[],
  book: Addressbook,
): Promise<void> {
  if (args.length < 1) {
    console.error("Usage: bw withdraw <to>");
    console.error("  Example: bw withdraw admin");
    process.exit(1);
  }

  const [toRole] = args;
  if (!toRole) {
    console.error("Usage: bw withdraw <to>");
    process.exit(1);
  }

  await executeWithdraw(toRole, book);
}
