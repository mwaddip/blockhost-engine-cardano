/**
 * Hot wallet distribution logic (Cardano).
 *
 * Steps 2-5 of the fund cycle (chain-agnostic math, adapted from OPNet
 * distribution.ts with lovelace units):
 *
 *  2. Top up hot wallet ADA (server → hot if hot is low)
 *  3. Top up server stablecoin buffer (hot → server stablecoin)
 *  4. Revenue shares (hot → dev/broker per revenue-share.json)
 *  5. Remainder to admin (hot → admin)
 *
 * All transfers use executeSend() — no inline transfer code.
 * executeSend is stubbed pending MeshJS; errors are caught and logged so
 * one failure does not short-circuit subsequent steps.
 */

import type { Addressbook, FundManagerConfig, RevenueShareConfig } from "./types.js";
import { resolveRole } from "./addressbook.js";
import { executeBalance } from "../bw/commands/balance.js";
import { executeSend } from "../bw/commands/send.js";
import { formatAda } from "../bw/cli-utils.js";

// ── Step 2: Hot wallet ADA top-up ─────────────────────────────────────────────

/**
 * Ensure hot wallet has enough ADA for transaction fees.
 * Server sends ADA to bring hot wallet up to hot_wallet_gas_lovelace target.
 */
export async function topUpHotWalletGas(
  book: Addressbook,
  config: FundManagerConfig,
): Promise<void> {
  if (!book["hot"]?.address) return;
  if (!book["server"]?.address || !book["server"]?.keyfile) return;

  const hotBal = await executeBalance("hot", undefined, book);
  if (hotBal.adaBalance >= config.hot_wallet_gas_lovelace) return;

  const needed = config.hot_wallet_gas_lovelace - hotBal.adaBalance;

  // Require server to keep a healthy reserve for minting and other operations
  const MIN_SERVER_RESERVE = 20_000_000n; // 20 ADA
  const serverBal = await executeBalance("server", undefined, book);
  if (serverBal.adaBalance < needed + MIN_SERVER_RESERVE) {
    console.warn(
      `[FUND] Server ADA too low to top up hot wallet ` +
      `(server: ${formatAda(serverBal.adaBalance)}, needed: ${formatAda(needed)})`,
    );
    return;
  }

  console.log(`[FUND] Topping up hot wallet gas: ${formatAda(needed)}`);
  await executeSend(formatAda(needed, false), "ada", "server", "hot", book);
  console.log("[FUND] Hot wallet gas top-up complete");
}

// ── Step 3: Server stablecoin buffer ─────────────────────────────────────────

/**
 * Ensure server wallet has enough stablecoin for VM provisioning.
 * Hot wallet sends stablecoin to server if server balance is below buffer.
 */
export async function topUpServerStablecoinBuffer(
  book: Addressbook,
  config: FundManagerConfig,
): Promise<void> {
  if (!book["server"]?.address) return;
  if (!book["hot"]?.address) return;

  const serverBal = await executeBalance("server", "stable", book);
  if (serverBal.tokenBalance === undefined) {
    // No payment token configured — skip silently
    return;
  }

  if (serverBal.tokenBalance >= config.server_stablecoin_buffer_lovelace) return;

  const needed = config.server_stablecoin_buffer_lovelace - serverBal.tokenBalance;

  const hotBal = await executeBalance("hot", "stable", book);
  if ((hotBal.tokenBalance ?? 0n) < needed) {
    console.warn(
      `[FUND] Hot wallet stablecoin insufficient for server buffer top-up ` +
      `(hot: ${hotBal.tokenBalance ?? 0n}, needed: ${needed})`,
    );
    return;
  }

  // Stablecoin amounts: pass as integer string (base units)
  const neededStr = needed.toString();
  console.log(`[FUND] Topping up server stablecoin buffer: ${neededStr} base units`);
  await executeSend(neededStr, "stable", "hot", "server", book);
  console.log("[FUND] Server stablecoin buffer topped up");
}

// ── Step 4: Revenue shares ────────────────────────────────────────────────────

/**
 * Distribute ADA revenue shares from hot wallet to configured recipients.
 *
 * Uses integer basis-point arithmetic (no float) to avoid rounding errors.
 * The last recipient receives the remainder to avoid dust from integer division.
 */
export async function distributeRevenueShares(
  book: Addressbook,
  revenueConfig: RevenueShareConfig,
): Promise<void> {
  if (!revenueConfig.enabled || revenueConfig.recipients.length === 0) {
    return;
  }

  const totalBps =
    revenueConfig.total_bps ??
    Math.round((revenueConfig.total_percent ?? 0) * 100);
  if (totalBps <= 0) return;

  if (!book["hot"]?.address) return;

  const hotBal = await executeBalance("hot", undefined, book);
  if (hotBal.adaBalance === 0n) {
    console.log("[FUND] Hot wallet ADA balance is zero, skipping revenue shares");
    return;
  }

  // Total ADA available for revenue sharing
  const totalShareAmount = (hotBal.adaBalance * BigInt(totalBps)) / 10_000n;
  if (totalShareAmount === 0n) return;

  console.log(
    `[FUND] Distributing revenue shares: ${formatAda(totalShareAmount)} ` +
    `(${totalBps} bps of ${formatAda(hotBal.adaBalance)})`,
  );

  let distributed = 0n;
  const recipients = revenueConfig.recipients;

  for (let i = 0; i < recipients.length; i++) {
    const recipient = recipients[i]!;
    const recipientAddress = resolveRole(recipient.role, book);
    if (!recipientAddress) {
      console.error(
        `[FUND] Revenue share recipient '${recipient.role}' not in addressbook`,
      );
      continue;
    }

    const recipientBps =
      recipient.bps ?? Math.round((recipient.percent ?? 0) * 100);

    const isLast = i === recipients.length - 1;
    const share = isLast
      ? totalShareAmount - distributed
      : (totalShareAmount * BigInt(recipientBps)) / BigInt(totalBps);
    distributed += share;

    if (share === 0n) continue;

    try {
      const shareStr = formatAda(share, false);
      await executeSend(shareStr, "ada", "hot", recipient.role, book);
      console.log(
        `[FUND] Revenue share: sent ${formatAda(share)} to ` +
        `${recipient.role} (${recipientBps} bps)`,
      );
    } catch (err) {
      console.error(
        `[FUND] Error sending revenue share to ${recipient.role}: ${err}`,
      );
    }
  }
}

// ── Step 5: Remainder to admin ────────────────────────────────────────────────

/**
 * Send all remaining ADA from hot wallet to admin.
 */
export async function sendRemainderToAdmin(
  book: Addressbook,
): Promise<void> {
  const adminAddress = resolveRole("admin", book);
  if (!adminAddress) {
    console.error("[FUND] Cannot send remainder: admin not in addressbook");
    return;
  }

  if (!book["hot"]?.address) return;

  const hotBal = await executeBalance("hot", undefined, book);
  if (hotBal.adaBalance === 0n) {
    console.log("[FUND] Hot wallet ADA balance is zero, nothing to send to admin");
    return;
  }

  try {
    const amountStr = formatAda(hotBal.adaBalance, false);
    await executeSend(amountStr, "ada", "hot", "admin", book);
    console.log(`[FUND] Remainder: sent ${formatAda(hotBal.adaBalance)} to admin`);
  } catch (err) {
    console.error(`[FUND] Error sending remainder to admin: ${err}`);
  }
}
