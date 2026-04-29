/**
 * Reconciler for the Cardano engine.
 *
 * Runs every cycle (triggered by the monitor polling loop) and performs three
 * passes over active/suspended VMs:
 *
 *   1. NFT ownership: query the on-chain holder of the (222) user token,
 *      compare against the local owner_wallet, propagate transfers to the
 *      VM's GECOS field. Persists `gecos_synced` for retry.
 *   2. NFT minting check: warn when `nft_minted=false` for a VM whose token
 *      isn't on-chain either (indicates a minting failure).
 *   3. Network config sync: for any VM with `network_config_synced != true`,
 *      retry `blockhost-network-hook push-vm-config` and flip the flag on
 *      success. Idempotent — safe to call repeatedly.
 */

import type { CardanoProvider } from "@mwaddip/cmttk";
import { spawnSync } from "child_process";
import { findNftHolder } from "../nft/reference.js";
import { getCommand } from "../provisioner.js";
import { STATE_DIR, PYTHON_TIMEOUT_MS } from "../paths.js";

// ── Constants ─────────────────────────────────────────────────────────────────

// ── Types ─────────────────────────────────────────────────────────────────────

interface VmRecord {
  vm_name: string;
  owner_wallet: string;
  nft_token_id: number | null;
  nft_minted: boolean;
  status: string;
  gecos_synced?: boolean;
  network_config_synced?: boolean;
}

const GUEST_EXEC_TIMEOUT_MS = 30_000;

// ── Concurrency guard ─────────────────────────────────────────────────────────

let reconcileInProgress = false;

// ── Public API ────────────────────────────────────────────────────────────────

/**
 * Run NFT ownership reconciliation.
 *
 * Safe to call concurrently — a second invocation while one is running
 * returns immediately without doing any work.
 */
export async function runReconciliation(
  provider: CardanoProvider,
  nftPolicyId: string,
): Promise<void> {
  if (reconcileInProgress) {
    console.log("[RECONCILE] Already in progress, skipping");
    return;
  }

  reconcileInProgress = true;

  try {
    console.log("[RECONCILE] Starting reconciliation...");

    const vms = listActiveVms();
    if (vms.length === 0) {
      console.log("[RECONCILE] No active/suspended VMs to reconcile");
      return;
    }

    let checked = 0;
    let transferred = 0;
    let errors = 0;

    // Pass 1+2: NFT ownership + minting check
    for (const vm of vms) {
      if (vm.nft_token_id === null) continue;

      try {
        const currentHolder = await findNftHolder(provider, nftPolicyId, vm.nft_token_id);

        if (currentHolder === null) {
          if (vm.nft_minted) {
            // Token was supposed to be minted but isn't on-chain — operator attention needed
            console.warn(
              `[RECONCILE] NFT #${vm.nft_token_id} for ${vm.vm_name} not found on-chain (minting failure?)`,
            );
          }
          continue;
        }

        checked++;

        if (currentHolder.toLowerCase() !== vm.owner_wallet.toLowerCase()) {
          // Ownership transfer detected
          console.log(
            `[RECONCILE] Ownership transfer detected for ${vm.vm_name}: ` +
            `${vm.owner_wallet} → ${currentHolder}`,
          );

          // Persist new owner (marks gecos_synced = false in the DB)
          updateOwnerInDb(vm.vm_name, currentHolder);

          // Update GECOS on the VM
          if (callUpdateGecos(vm.vm_name, currentHolder, vm.nft_token_id)) {
            console.log(`[RECONCILE] GECOS updated for ${vm.vm_name}`);
            markGecosSynced(vm.vm_name, true);
          } else {
            console.warn(
              `[RECONCILE] GECOS update failed for ${vm.vm_name} (will retry next cycle)`,
            );
            // gecos_synced = false was already written by updateOwnerInDb
          }

          transferred++;
        } else if (!vm.gecos_synced) {
          // Ownership unchanged but previous GECOS write failed — retry
          console.log(`[RECONCILE] Retrying GECOS update for ${vm.vm_name}`);
          if (callUpdateGecos(vm.vm_name, vm.owner_wallet, vm.nft_token_id)) {
            console.log(`[RECONCILE] GECOS retry succeeded for ${vm.vm_name}`);
            markGecosSynced(vm.vm_name, true);
          } else {
            console.warn(`[RECONCILE] GECOS retry failed for ${vm.vm_name}, will try again next cycle`);
          }
        }
      } catch (err) {
        console.error(
          `[RECONCILE] Error checking NFT #${vm.nft_token_id} for ${vm.vm_name}: ${err}`,
        );
        errors++;
      }
    }

    // Pass 3: network config sync — retry push-vm-config for any VM whose
    // initial post-mint push didn't confirm. Plugins implement push-vm-config
    // as idempotent (no-op for broker/manual/none), so we can call it freely.
    let networkAttempted = 0;
    let networkSynced = 0;
    for (const vm of vms) {
      if (vm.network_config_synced === true) continue;
      networkAttempted++;
      if (pushVmConfig(vm.vm_name)) {
        setNetworkConfigSynced(vm.vm_name, true);
        console.log(`[RECONCILE] Network config synced for ${vm.vm_name}`);
        networkSynced++;
      } else {
        console.warn(
          `[RECONCILE] push-vm-config failed for ${vm.vm_name}, will retry next cycle`,
        );
      }
    }

    console.log(
      `[RECONCILE] Done: checked=${checked}, transfers=${transferred}, errors=${errors}, ` +
      `network_synced=${networkSynced}/${networkAttempted}`,
    );
  } finally {
    reconcileInProgress = false;
  }
}

// ── Database helpers (Python subprocess) ─────────────────────────────────────

/**
 * Query the Python vm_db for all active/suspended VMs.
 * Returns an empty array on error.
 */
function listActiveVms(): VmRecord[] {
  const script = `
import json
from blockhost.vm_db import get_database
db = get_database()
vms = db.list_vms()
result = []
for vm in vms:
    if vm.get('status') in ('active', 'suspended'):
        result.append({
            'vm_name': vm.get('vm_name', ''),
            'owner_wallet': vm.get('wallet_address', vm.get('owner', '')),
            'nft_token_id': vm.get('nft_token_id'),
            'nft_minted': bool(vm.get('nft_minted')),
            'status': vm.get('status', ''),
            'gecos_synced': bool(vm.get('gecos_synced', True)),
            'network_config_synced': bool(vm.get('network_config_synced', False)),
        })
print(json.dumps(result))
`;

  const result = spawnSync("python3", ["-c", script], {
    timeout: PYTHON_TIMEOUT_MS,
    cwd: STATE_DIR,
    encoding: "utf8",
  });

  if (result.status !== 0) {
    console.error("[RECONCILE] Failed to list VMs from database");
    return [];
  }

  try {
    return JSON.parse(result.stdout) as VmRecord[];
  } catch {
    console.error("[RECONCILE] Failed to parse VM list from database");
    return [];
  }
}

/**
 * Update the owner_wallet for a VM in the Python vm_db.
 * Also sets gecos_synced = False so a retry is attempted if update-gecos fails.
 */
function updateOwnerInDb(vmName: string, newOwner: string): void {
  const script = `
import os
from blockhost.vm_db import get_database
db = get_database()
vm = db.get_vm(os.environ['VM_NAME'])
if vm:
    vm['wallet_address'] = os.environ['NEW_OWNER']
    vm['gecos_synced'] = False
    db.save_vm(vm)
`;

  const result = spawnSync("python3", ["-c", script], {
    timeout: PYTHON_TIMEOUT_MS,
    cwd: STATE_DIR,
    encoding: "utf8",
    env: { ...process.env, VM_NAME: vmName, NEW_OWNER: newOwner },
  });

  if (result.status !== 0) {
    console.error(`[RECONCILE] Failed to update owner in database for ${vmName}`);
  }
}

/**
 * Set gecos_synced flag for a VM in the Python vm_db.
 */
function markGecosSynced(vmName: string, synced: boolean): void {
  const script = `
import os
from blockhost.vm_db import get_database
db = get_database()
vm = db.get_vm(os.environ['VM_NAME'])
if vm:
    vm['gecos_synced'] = os.environ['SYNCED'] == 'true'
    db.save_vm(vm)
`;

  const result = spawnSync("python3", ["-c", script], {
    timeout: PYTHON_TIMEOUT_MS,
    cwd: STATE_DIR,
    encoding: "utf8",
    env: { ...process.env, VM_NAME: vmName, SYNCED: synced ? "true" : "false" },
  });

  if (result.status !== 0) {
    console.warn(`[RECONCILE] Failed to persist gecos_synced for ${vmName}`);
  }
}

// ── Provisioner call ──────────────────────────────────────────────────────────

/**
 * Call the provisioner's update-gecos command.
 * Returns true on exit 0, false otherwise.
 */
function callUpdateGecos(vmName: string, walletAddress: string, nftTokenId: number): boolean {
  try {
    const cmd = getCommand("update-gecos");
    const result = spawnSync(
      cmd,
      [vmName, walletAddress, "--nft-id", String(nftTokenId)],
      { timeout: 30_000, cwd: STATE_DIR, encoding: "utf8" },
    );

    if (result.status === 0) return true;

    const errMsg = (result.stderr ?? result.stdout ?? "").trim();
    console.warn(
      `[RECONCILE] update-gecos failed for ${vmName}: ${errMsg || `exit ${String(result.status)}`}`,
    );
    return false;
  } catch (err) {
    console.warn(`[RECONCILE] update-gecos error for ${vmName}: ${err}`);
    return false;
  }
}

// ── Network hook dispatcher ───────────────────────────────────────────────────

/**
 * Push mode-specific config into the VM via `blockhost-network-hook`.
 * Returns true on exit 0, false otherwise.
 */
function pushVmConfig(vmName: string): boolean {
  const result = spawnSync(
    "blockhost-network-hook",
    ["push-vm-config", vmName],
    { timeout: GUEST_EXEC_TIMEOUT_MS, encoding: "utf8" },
  );
  if (result.status === 0) return true;
  const errMsg = (result.stderr ?? result.stdout ?? "").toString().trim();
  console.warn(
    `[RECONCILE] push-vm-config failed for ${vmName}: ${errMsg || `exit ${String(result.status)}`}`,
  );
  return false;
}

/**
 * Persist `network_config_synced` on a VM record via the vmdb update-fields
 * CLI (lockfile-routed; safe against concurrent writers).
 */
function setNetworkConfigSynced(vmName: string, synced: boolean): void {
  const fields = JSON.stringify({ network_config_synced: synced });
  const result = spawnSync(
    "blockhost-vmdb",
    ["update-fields", vmName, "--fields", fields],
    { timeout: PYTHON_TIMEOUT_MS },
  );
  if (result.status !== 0) {
    const errMsg = result.stderr ? result.stderr.toString().trim() : "";
    console.warn(
      `[RECONCILE] Failed to persist network_config_synced=${String(synced)} for ${vmName}${errMsg ? ": " + errMsg : ""}`,
    );
  }
}
