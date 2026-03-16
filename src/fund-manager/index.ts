/**
 * Fund Manager Module (Cardano)
 *
 * Periodic task integrated into the monitor polling loop:
 *   - Fund cycle (every 24h): batch-collect mature subscription UTXOs,
 *     then distribute collected ADA to hot/server/dev/broker/admin.
 *
 * No gas check cycle — Cardano has deterministic fees so there is no
 * gas market volatility to monitor.
 *
 * Follows the same pattern as the OPNet fund-manager/index.ts but simplified.
 */

import { spawnSync } from "child_process";
import { getBlockfrost } from "../cardano/provider.js";
import { getCommand } from "../provisioner.js";
import { loadFundManagerConfig, loadRevenueShareConfig } from "./config.js";
import { loadState, updateState } from "./state.js";
import { loadWeb3Config } from "./web3-config.js";
import { loadAddressbook, ensureHotWallet } from "./addressbook.js";
import { runFundCycle as collectSubscriptions } from "./withdrawal.js";
import {
  topUpHotWalletGas,
  topUpServerStablecoinBuffer,
  distributeRevenueShares,
  sendRemainderToAdmin,
} from "./distribution.js";

import * as fs from "fs";

let fundCycleInProgress = false;

const TESTING_MODE_FILE = "/etc/blockhost/.testing-mode";
const testingMode = fs.existsSync(TESTING_MODE_FILE);

// ── Scheduling helpers ────────────────────────────────────────────────────────

/**
 * Check if the fund cycle is due to run based on its configured interval.
 *
 * Testing mode: runs every 30 seconds instead of the configured interval.
 */
export function shouldRunFundCycle(): boolean {
  const state = loadState();
  if (testingMode) {
    // Run every 30 seconds in testing mode
    return Date.now() - state.last_fund_cycle >= 30_000;
  }
  const config = loadFundManagerConfig();
  const intervalMs = config.fund_cycle_interval_hours * 3_600_000;
  return Date.now() - state.last_fund_cycle >= intervalMs;
}

/**
 * Return true if a provisioner VM-create command is currently running.
 * We skip fund cycles during provisioning to avoid ADA balance race conditions.
 */
export function isProvisioningInProgress(): boolean {
  try {
    const createCmd = getCommand("create");
    const result = spawnSync("pgrep", ["-f", createCmd], { timeout: 5000 });
    return result.status === 0;
  } catch {
    // getCommand() may throw if manifest not loaded — treat as not in progress
    return false;
  }
}

// ── Fund cycle ────────────────────────────────────────────────────────────────

/**
 * Run the full fund collection and distribution cycle.
 *
 * 1. Batch-collect mature subscription UTXOs to hot wallet
 * 2. Top up hot wallet ADA from server if below threshold
 * 3. Top up server stablecoin buffer from hot wallet
 * 4. Distribute revenue shares (if enabled)
 * 5. Send remainder to admin
 */
export async function runFundManager(): Promise<void> {
  if (fundCycleInProgress) return;
  fundCycleInProgress = true;

  try {
    if (isProvisioningInProgress()) {
      console.log("[FUND] Provisioning in progress, deferring fund cycle");
      return;
    }

    const web3Config = loadWeb3Config();
    const client = getBlockfrost(
      web3Config.blockfrostProjectId,
      web3Config.network,
    );

    console.log("[FUND] Starting fund cycle...");

    // Load addressbook and ensure hot wallet exists
    let book = loadAddressbook();
    if (Object.keys(book).length === 0) {
      console.error("[FUND] Addressbook empty, skipping fund cycle");
      return;
    }
    book = await ensureHotWallet(book);

    const config = loadFundManagerConfig();

    // Step 1: Batch-collect subscription UTXOs to hot wallet
    try {
      await collectSubscriptions(
        book,
        config,
        client,
        web3Config.subscriptionValidatorAddress,
        web3Config.beaconPolicyId,
      );
    } catch (err) {
      console.error(`[FUND] Step 1 (collection) failed: ${err}`);
    }

    // Steps 2-5: each wrapped so a single failure doesn't skip the rest

    try {
      // Step 2: Top up hot wallet ADA from server
      await topUpHotWalletGas(book, config, client);
    } catch (err) {
      console.error(`[FUND] Step 2 (hot wallet gas) failed: ${err}`);
    }

    try {
      // Step 3: Top up server stablecoin buffer from hot wallet
      await topUpServerStablecoinBuffer(book, config, client);
    } catch (err) {
      console.error(`[FUND] Step 3 (stablecoin buffer) failed: ${err}`);
    }

    try {
      // Step 4: Revenue shares (hot → dev/broker)
      const revenueConfig = loadRevenueShareConfig();
      await distributeRevenueShares(book, revenueConfig, client);
    } catch (err) {
      console.error(`[FUND] Step 4 (revenue shares) failed: ${err}`);
    }

    try {
      // Step 5: Remainder to admin (hot → admin)
      await sendRemainderToAdmin(book, client);
    } catch (err) {
      console.error(`[FUND] Step 5 (remainder to admin) failed: ${err}`);
    }

    console.log("[FUND] Fund cycle complete");
  } catch (err) {
    console.error(`[FUND] Error during fund cycle: ${err}`);
  } finally {
    updateState({ last_fund_cycle: Date.now() });
    fundCycleInProgress = false;
  }
}
