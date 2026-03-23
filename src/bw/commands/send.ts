/**
 * bw send <amount> <token> <from> <to>
 *
 * Send ADA or native tokens from a signing wallet to a recipient.
 * Uses the minimal tx builder (src/cardano/tx.ts) — no Lucid.
 *
 * Core function executeSend() is also used by fund-manager.
 */

import type { Addressbook } from "../../fund-manager/types.js";
import { resolveAddress, resolveToken } from "../cli-utils.js";
import { getProvider } from "cmttk";
import { loadNetworkConfig } from "../../fund-manager/web3-config.js";
import { deriveWallet } from "cmttk";
import { buildAndSubmitTransfer } from "cmttk";
import type { Assets } from "cmttk";
import * as fs from "fs";

/**
 * Core send operation — used by both CLI and fund-manager.
 *
 * @param amountStr  Human-readable amount (e.g. "1.5" for 1.5 ADA, or base units for tokens)
 * @param tokenArg   Token shortcut or "policyId.assetName"
 * @param fromRole   Addressbook role (must have keyfile)
 * @param toRole     Addressbook role or bech32 address
 * @param book       Addressbook
 */
export async function executeSend(
  amountStr: string,
  tokenArg: string,
  fromRole: string,
  toRole: string,
  book: Addressbook,
): Promise<void> {
  const asset = resolveToken(tokenArg);
  const toAddress = resolveAddress(toRole, book);

  // Load sender wallet
  const fromEntry = book[fromRole];
  if (!fromEntry) throw new Error(`Role '${fromRole}' not found in addressbook`);
  if (!fromEntry.keyfile) throw new Error(`Role '${fromRole}' has no keyfile — cannot sign`);

  const mnemonic = fs.readFileSync(fromEntry.keyfile, "utf8").trim();
  const { network, blockfrostProjectId } = loadNetworkConfig();
  const wallet = await deriveWallet(mnemonic, network);
  const provider = getProvider(network, blockfrostProjectId);

  const isAda = asset.policyId === "" && asset.assetName === "";

  let assets: Assets;
  if (isAda) {
    const lovelace = BigInt(Math.round(parseFloat(amountStr) * 1_000_000));
    assets = { lovelace };
  } else {
    const unit = asset.policyId + asset.assetName;
    const amount = BigInt(amountStr);
    assets = { lovelace: 2_000_000n, [unit]: amount };
  }

  const txHash = await buildAndSubmitTransfer({
    provider,
    fromAddress: wallet.address,
    toAddress,
    assets,
    signingKey: new Uint8Array([...wallet.paymentKey]),
  });
  console.log(txHash);
}

/**
 * CLI handler
 */
export async function sendCommand(
  args: string[],
  book: Addressbook,
): Promise<void> {
  if (args.length < 4) {
    console.error("Usage: bw send <amount> <token> <from> <to>");
    console.error("  Example: bw send 10 ada hot admin");
    console.error("  Example: bw send 100 stable server hot");
    process.exit(1);
  }

  const [amountStr, tokenArg, fromRole, toRole] = args;
  if (!amountStr || !tokenArg || !fromRole || !toRole) {
    console.error("Usage: bw send <amount> <token> <from> <to>");
    process.exit(1);
  }

  const amount = parseFloat(amountStr);
  if (!Number.isFinite(amount) || amount <= 0) {
    console.error(`Invalid amount: ${amountStr}`);
    process.exit(1);
  }

  await executeSend(amountStr, tokenArg, fromRole, toRole, book);
}
