/**
 * bw split <amount> <token> <ratios> <from> <to1> <to2> ...
 *
 * Split an ADA or native token amount from a signing wallet to multiple
 * recipients according to a ratio string (e.g. "60/40" or "50/30/20").
 *
 * Ratios must be positive integers that sum to 100.
 * The last recipient receives any rounding dust.
 *
 * The ratio math is chain-agnostic. Each share is sent via executeSend().
 *
 * TODO: executeSend() is a stub pending MeshJS integration.
 */

import type { Addressbook } from "../../fund-manager/types.js";
import { resolveAddress, resolveToken, formatAda, formatToken } from "../cli-utils.js";
import { executeSend } from "./send.js";

/**
 * CLI handler
 */
export async function splitCommand(
  args: string[],
  book: Addressbook,
): Promise<void> {
  if (args.length < 5) {
    console.error(
      "Usage: bw split <amount> <token> <ratios> <from> <to1> <to2> ...",
    );
    console.error("  Example: bw split 10 ada 60/40 hot dev broker");
    console.error("  Example: bw split 100 stable 50/50 hot dev admin");
    process.exit(1);
  }

  const [amountStr, tokenArg, ratiosStr, fromRole, ...recipientRoles] = args;
  if (!amountStr || !tokenArg || !ratiosStr || !fromRole) {
    console.error(
      "Usage: bw split <amount> <token> <ratios> <from> <to1> <to2> ...",
    );
    process.exit(1);
  }

  const amount = parseFloat(amountStr);
  if (!Number.isFinite(amount) || amount <= 0) {
    console.error(`Invalid amount: ${amountStr}`);
    process.exit(1);
  }

  // Parse ratios
  const ratios = ratiosStr.split("/").map(Number);
  if (ratios.some(isNaN) || ratios.some((r) => r <= 0)) {
    console.error(
      `Invalid ratios: ${ratiosStr}. Use format like 60/40 or 50/30/20`,
    );
    process.exit(1);
  }

  const ratioSum = ratios.reduce((a, b) => a + b, 0);
  if (ratioSum !== 100) {
    console.error(`Ratios must sum to 100, got ${ratioSum}`);
    process.exit(1);
  }

  if (ratios.length !== recipientRoles.length) {
    console.error(
      `Number of ratios (${ratios.length}) must match number of recipients (${recipientRoles.length})`,
    );
    process.exit(1);
  }

  // Resolve recipients
  const recipients: string[] = [];
  for (const role of recipientRoles) {
    recipients.push(resolveAddress(role, book));
  }

  const asset = resolveToken(tokenArg);
  const isAda = asset.policyId === "" && asset.assetName === "";

  // For ADA: convert amount string to lovelace, then split.
  // For tokens: split raw units (the caller supplies amounts in base units when splitting tokens).
  // We use a fixed-point approach: treat the amount string as-is and split into ratios.
  // Since executeSend() receives a human-readable string, we compute each share's human string.

  // Parse total into bigint base units for precise splitting
  // ADA: 6 decimal places; tokens: assume 0 (most Cardano tokens are indivisible)
  const decimals = isAda ? 6 : 0;

  // Parse amountStr to base units — supports decimal input for ADA
  const totalBaseUnits = parseAmountToBaseUnits(amountStr, decimals);
  let remaining = totalBaseUnits;

  const label = isAda ? "ADA" : `${asset.policyId.slice(0, 8)}...`;
  console.log(
    `Splitting ${isAda ? formatAda(totalBaseUnits) : formatToken(totalBaseUnits, decimals)} from ${fromRole}:`,
  );
  for (let i = 0; i < recipients.length; i++) {
    const ratio = ratios[i];
    const recipientRole = recipientRoles[i];
    if (ratio === undefined || !recipientRole) continue;

    const isLast = i === recipients.length - 1;
    const share = isLast ? remaining : (totalBaseUnits * BigInt(ratio)) / 100n;
    remaining -= share;

    const shareStr = formatBaseUnitsToAmount(share, decimals);
    const display = isAda
      ? formatAda(share)
      : formatToken(share, decimals);
    console.log(`  ${recipientRole}: ${display}`);

    // Delegate to executeSend (stub for now — will build tx when MeshJS lands)
    await executeSend(shareStr, tokenArg, fromRole, recipientRole, book);
  }

  console.log("Done.");
  void label; // suppress unused-variable warning — used in console.log above
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/**
 * Parse a human-readable amount string into base units.
 *
 * "1.5" with decimals=6 → 1_500_000n
 * "100" with decimals=0 → 100n
 */
function parseAmountToBaseUnits(amountStr: string, decimals: number): bigint {
  const parts = amountStr.split(".");
  const wholePart = parts[0] ?? "0";
  const fracPart = (parts[1] ?? "").slice(0, decimals).padEnd(decimals, "0");
  return BigInt(wholePart) * BigInt(10 ** decimals) + BigInt(fracPart || "0");
}

/**
 * Format base units back to a decimal string for passing to executeSend.
 */
function formatBaseUnitsToAmount(baseUnits: bigint, decimals: number): string {
  if (decimals === 0) return baseUnits.toString();
  const factor = BigInt(10 ** decimals);
  const whole = baseUnits / factor;
  const frac = baseUnits % factor;
  return `${whole.toString()}.${frac.toString().padStart(decimals, "0")}`;
}
