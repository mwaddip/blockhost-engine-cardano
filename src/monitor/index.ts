/**
 * BlockHost Cardano monitor — main polling loop.
 *
 * Polls Koios every 30 seconds for beacon token UTXOs.  Detects new
 * subscriptions, extensions, and removals by diffing the current chain
 * state against our known state.  Runs periodic reconciliation, fund
 * cycles, and collateral checks.  Handles graceful shutdown on
 * SIGINT/SIGTERM.
 */

import { getProvider } from "cmttk";
import type { CardanoProvider } from "cmttk";
import { loadWeb3Config } from "../fund-manager/web3-config.js";
import { scanBeacons, type ScanDiff } from "./scanner.js";
import {
  handleSubscriptionCreated,
  handleSubscriptionExtended,
  handleSubscriptionRemoved,
} from "../handlers/index.js";
import { runReconciliation as reconcileNftOwnership } from "../reconcile/index.js";
import {
  runFundManager,
  shouldRunFundCycle,
  shouldRunCollateralCheck,
  runCollateralCheck,
  isProvisioningInProgress,
} from "../fund-manager/index.js";
import {
  processAdminCommands,
  initAdminCommands,
  shutdownAdminCommands,
  loadAdminConfig,
} from "../admin/index.js";

// ── Testing mode ──────────────────────────────────────────────────────────────

import * as fs from "fs";

const TESTING_MODE_FILE = "/etc/blockhost/.testing-mode";
const testingMode = fs.existsSync(TESTING_MODE_FILE);

// ── Intervals ─────────────────────────────────────────────────────────────────

const POLL_INTERVAL_MS = testingMode ? 30_000 : 60_000;               // 30s test / 60s prod
const RECONCILE_INTERVAL_MS = testingMode ? 120_000 : 3_600_000;     // 2min test / 1hr prod
const ADMIN_SCAN_INTERVAL_MS = testingMode ? 120_000 : 300_000;      // 2min test / 5min prod

// ── State ─────────────────────────────────────────────────────────────────────

let running = true;
let lastReconcile = 0;
let lastAdminScan = 0;

// ── Periodic tasks ────────────────────────────────────────────────────────────

async function runReconciliation(
  provider: CardanoProvider,
  nftPolicyId: string,
): Promise<void> {
  await reconcileNftOwnership(provider, nftPolicyId);
}

async function runFundCycle(): Promise<void> {
  if (!shouldRunFundCycle()) return;
  if (isProvisioningInProgress()) {
    console.log("[MONITOR] Provisioning in progress, deferring fund cycle");
    return;
  }
  await runFundManager();
}

// ── Core poll loop ────────────────────────────────────────────────────────────

async function poll(
  provider: CardanoProvider,
  beaconPolicyId: string,
  nftPolicyId: string,
  adminConfig: ReturnType<typeof loadAdminConfig>,
): Promise<void> {
  while (running) {
    try {
      const diff: ScanDiff = await scanBeacons(provider, beaconPolicyId);

      // Process new subscriptions
      for (const sub of diff.created) {
        try {
          await handleSubscriptionCreated(sub);
        } catch (err) {
          console.error(`[MONITOR] Error handling new subscription ${sub.beaconName}: ${err}`);
        }
      }

      // Process extensions (same beacon, new UTXO ref)
      for (const { old, new: updated } of diff.extended) {
        try {
          await handleSubscriptionExtended(old, updated);
        } catch (err) {
          console.error(`[MONITOR] Error handling extension ${updated.beaconName}: ${err}`);
        }
      }

      // Process removals (beacon burned — collected or cancelled)
      for (const sub of diff.removed) {
        try {
          await handleSubscriptionRemoved(sub);
        } catch (err) {
          console.error(`[MONITOR] Error handling removal ${sub.beaconName}: ${err}`);
        }
      }

      const now = Date.now();

      // Scan admin wallet transactions for metadata commands (label 7368)
      if (adminConfig && now - lastAdminScan >= ADMIN_SCAN_INTERVAL_MS) {
        try {
          await processAdminCommands(provider, adminConfig);
        } catch (err) {
          console.error(`[MONITOR] Admin command scan error: ${err}`);
        }
        lastAdminScan = now;
      }

      // Periodic reconciliation (every 1 hour)
      if (now - lastReconcile >= RECONCILE_INTERVAL_MS) {
        console.log("[MONITOR] Running reconciliation...");
        try {
          await runReconciliation(provider, nftPolicyId);
        } catch (err) {
          console.error(`[MONITOR] Reconciliation error: ${err}`);
        }
        lastReconcile = now;
      }

      // Periodic fund cycle (interval managed by fund-manager state)
      try {
        await runFundCycle();
      } catch (err) {
        console.error(`[MONITOR] Fund cycle error: ${err}`);
      }

      // Periodic collateral check (hourly)
      try {
        if (shouldRunCollateralCheck()) {
          await runCollateralCheck();
        }
      } catch (err) {
        console.error(`[MONITOR] Collateral check error: ${err}`);
      }
    } catch (err) {
      console.error(`[MONITOR] Poll error: ${err}`);
    }

    // Wait before next beacon scan
    await sleep(POLL_INTERVAL_MS);
  }
}

// ── Shutdown ──────────────────────────────────────────────────────────────────

function setupShutdown(): void {
  let shuttingDown = false;

  const shutdown = (signal: string) => {
    if (shuttingDown) return; // guard against double-signal
    shuttingDown = true;
    console.log(`\n[MONITOR] Received ${signal}, shutting down...`);
    running = false;
    // Allow the current poll iteration to finish, then exit
    setTimeout(() => process.exit(0), 2000);
  };

  process.on("SIGINT", () => shutdown("SIGINT"));
  process.on("SIGTERM", () => shutdown("SIGTERM"));
}

// ── Entry point ───────────────────────────────────────────────────────────────

async function main(): Promise<void> {
  console.log("==============================================");
  console.log("  BlockHost Cardano Monitor");
  if (testingMode) {
    console.log("  *** TESTING MODE ACTIVE ***");
    console.log(`  Poll: ${POLL_INTERVAL_MS / 1000}s | Reconcile: ${RECONCILE_INTERVAL_MS / 1000}s | Admin: ${ADMIN_SCAN_INTERVAL_MS / 1000}s | Fund: 10min`);
  }
  console.log("==============================================");

  setupShutdown();

  let config;
  try {
    config = loadWeb3Config();
  } catch (err) {
    console.error(`[MONITOR] Fatal: could not load web3-defaults.yaml: ${err}`);
    process.exit(1);
  }

  const provider = getProvider(config.network, config.blockfrostProjectId || undefined, config.koiosUrl || undefined);

  // Load admin config (optional — null means admin commands are disabled)
  const adminConfig = loadAdminConfig();
  if (adminConfig) {
    initAdminCommands();
    console.log(`Admin wallet:     ${adminConfig.wallet_address}`);
  } else {
    console.log(`Admin commands:   disabled (no admin config in blockhost.yaml)`);
  }

  // Register shutdown hook for admin (closes active knock sessions on exit)
  process.on("SIGTERM", () => {
    shutdownAdminCommands().catch(() => undefined);
  });
  process.on("SIGINT", () => {
    shutdownAdminCommands().catch(() => undefined);
  });

  console.log(`Network:          ${config.network}`);
  console.log(`Provider:         ${provider.name}`);
  console.log(`Validator:        ${config.subscriptionValidatorAddress}`);
  console.log(`Beacon policy:    ${config.beaconPolicyId}`);
  console.log(`Poll interval:    ${POLL_INTERVAL_MS / 1000}s`);
  console.log(`Reconcile every:  ${RECONCILE_INTERVAL_MS / 3_600_000}h`);
  console.log("----------------------------------------------\n");

  // Start reconcile timer from now so first reconcile fires on schedule
  lastReconcile = Date.now();

  console.log("Monitor is running. Press Ctrl+C to stop.\n");
  await poll(
    provider,
    config.beaconPolicyId,
    config.nftPolicyId,
    adminConfig,
  );
}

main().catch((err) => {
  console.error(`[MONITOR] Fatal error: ${err}`);
  process.exit(1);
});

// ── Helpers ───────────────────────────────────────────────────────────────────

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
