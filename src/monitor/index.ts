/**
 * BlockHost Cardano monitor — main polling loop.
 *
 * Polls Blockfrost every 30 seconds for beacon token UTXOs at the subscription
 * validator address.  Detects new subscriptions, extensions, and removals by
 * diffing the current chain state against our known state.  Handler dispatch
 * is stubbed (Task 4).  Runs periodic reconciliation and fund cycles.
 * Handles graceful shutdown on SIGINT/SIGTERM.
 */

import { BlockFrostAPI } from "@blockfrost/blockfrost-js";
import { loadWeb3Config } from "../fund-manager/web3-config.js";
import { getBlockfrost } from "../cardano/provider.js";
import { scanBeacons, type ScanDiff } from "./scanner.js";
import type { TrackedSubscription } from "./scanner.js";

// ── Intervals ─────────────────────────────────────────────────────────────────

const POLL_INTERVAL_MS = 30_000;        // 30 seconds between beacon scans
const RECONCILE_INTERVAL_MS = 3_600_000; // 1 hour
const FUND_CYCLE_INTERVAL_MS = 86_400_000; // 24 hours

// ── State ─────────────────────────────────────────────────────────────────────

let running = true;
let lastReconcile = 0;
let lastFundCycle = 0;

// ── Dispatch stubs (replaced by Task 4 handlers) ──────────────────────────────

async function handleSubscriptionCreated(sub: TrackedSubscription): Promise<void> {
  console.log(
    `[MONITOR] New subscription: beacon=${sub.beaconName} utxo=${sub.utxoRef}` +
    ` planId=${sub.datum.planId} expiry=${sub.datum.expiry} subscriber=${sub.datum.subscriber}`,
  );
  // TODO (Task 4): provision VM, mint NFT, write state
}

async function handleSubscriptionExtended(
  old: TrackedSubscription,
  updated: TrackedSubscription,
): Promise<void> {
  console.log(
    `[MONITOR] Subscription extended: beacon=${updated.beaconName}` +
    ` old_utxo=${old.utxoRef} new_utxo=${updated.utxoRef}` +
    ` new_expiry=${updated.datum.expiry}`,
  );
  // TODO (Task 4): update expiry in DB, schedule new teardown timer
}

async function handleSubscriptionRemoved(sub: TrackedSubscription): Promise<void> {
  console.log(
    `[MONITOR] Subscription removed: beacon=${sub.beaconName} utxo=${sub.utxoRef}` +
    ` planId=${sub.datum.planId} subscriber=${sub.datum.subscriber}`,
  );
  // TODO (Task 4): collect/cancel handler — suspend or destroy VM
}

// ── Periodic tasks ────────────────────────────────────────────────────────────

async function runReconciliation(
  _client: BlockFrostAPI,
): Promise<void> {
  // TODO (Task 5): compare on-chain beacon state with local DB and fix drift
  console.log("[MONITOR] Reconciliation complete (stub).");
}

async function runFundCycle(
  _client: BlockFrostAPI,
): Promise<void> {
  // TODO (Phase 5 Fund Manager): withdraw funds, distribute revenue shares
  console.log("[MONITOR] Fund cycle complete (stub).");
}

// ── Core poll loop ────────────────────────────────────────────────────────────

async function poll(
  client: BlockFrostAPI,
  validatorAddress: string,
  beaconPolicyId: string,
): Promise<void> {
  while (running) {
    try {
      const diff: ScanDiff = await scanBeacons(client, validatorAddress, beaconPolicyId);

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

      // Periodic reconciliation (every 1 hour)
      if (now - lastReconcile >= RECONCILE_INTERVAL_MS) {
        console.log("[MONITOR] Running reconciliation...");
        try {
          await runReconciliation(client);
        } catch (err) {
          console.error(`[MONITOR] Reconciliation error: ${err}`);
        }
        lastReconcile = now;
      }

      // Periodic fund cycle (every 24 hours)
      if (now - lastFundCycle >= FUND_CYCLE_INTERVAL_MS) {
        console.log("[MONITOR] Running fund cycle...");
        try {
          await runFundCycle(client);
        } catch (err) {
          console.error(`[MONITOR] Fund cycle error: ${err}`);
        }
        lastFundCycle = now;
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
  console.log("==============================================");

  setupShutdown();

  let config;
  try {
    config = loadWeb3Config();
  } catch (err) {
    console.error(`[MONITOR] Fatal: could not load web3-defaults.yaml: ${err}`);
    process.exit(1);
  }

  const client = getBlockfrost(config.blockfrostProjectId, config.network);

  console.log(`Network:          ${config.network}`);
  console.log(`Validator:        ${config.subscriptionValidatorAddress}`);
  console.log(`Beacon policy:    ${config.beaconPolicyId}`);
  console.log(`Poll interval:    ${POLL_INTERVAL_MS / 1000}s`);
  console.log(`Reconcile every:  ${RECONCILE_INTERVAL_MS / 3_600_000}h`);
  console.log(`Fund cycle every: ${FUND_CYCLE_INTERVAL_MS / 3_600_000}h`);
  console.log("----------------------------------------------\n");

  // Start timers from now so the first periodic task fires on schedule
  lastReconcile = Date.now();
  lastFundCycle = Date.now();

  console.log("Monitor is running. Press Ctrl+C to stop.\n");
  await poll(client, config.subscriptionValidatorAddress, config.beaconPolicyId);
}

main().catch((err) => {
  console.error(`[MONITOR] Fatal error: ${err}`);
  process.exit(1);
});

// ── Helpers ───────────────────────────────────────────────────────────────────

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
