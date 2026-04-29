/**
 * Subscription event handlers — provision, extend, and destroy VMs.
 *
 * Adapts the OPNet handler pipeline for Cardano's beacon-based detection model.
 * Input is TrackedSubscription (from the beacon scanner), not a contract event.
 *
 * Pipeline for new subscriptions:
 *   1. Decrypt userEncrypted from datum (ECIES with server key)
 *   2. Call provisioner create with --owner-wallet and --expiry-days
 *   3. Parse JSON summary from provisioner stdout
 *   4. Resolve subscriber-facing host via `blockhost-network-hook public-address`
 *   5. Encrypt connection details with user signature (SHAKE256 + AES-GCM)
 *   6. Call blockhost-mint-nft → token_id
 *   7. Push VM-side config via `blockhost-network-hook push-vm-config`
 *   8. Call provisioner update-gecos with VM name, wallet, NFT token ID
 *   9. Mark NFT minted in database
 *
 * Network-mode awareness lives in the dispatcher (`blockhost-network-hook`)
 * and its plugins. The engine never branches on broker/manual/onion and never
 * reads any active-mode config file. Step 4 returns whatever the active
 * plugin produces; step 7 is best-effort with reconciler retry.
 */

import { spawn, spawnSync } from "child_process";
import { bech32 } from "bech32";
import type { TrackedSubscription } from "../monitor/scanner.js";
import { eciesDecrypt, symmetricEncrypt, loadServerPrivateKey } from "../crypto.js";
import { getCommand } from "../provisioner.js";
import { isFundCycleInProgress } from "../fund-manager/index.js";
import { loadNetworkConfig } from "../fund-manager/web3-config.js";
import { allocateCounter } from "../state/counter.js";
import { STATE_DIR, PYTHON_TIMEOUT_MS } from "../paths.js";

// ── Constants ─────────────────────────────────────────────────────────────────
const SSH_PORT = 22;
const NEXT_VM_ID_FILE = `${STATE_DIR}/next-vm-id`;
const GUEST_EXEC_TIMEOUT_MS = 30_000;

// ── Network hook dispatcher ───────────────────────────────────────────────────

/**
 * Resolve the subscriber-facing host for a VM via the network-hook dispatcher.
 *
 * The dispatcher reads `vm-db.network_mode[<vm>]` and forwards to the plugin's
 * `public-address` command. Returns the host string on success, or null on
 * non-zero exit / empty output. Engines treat null as a hard failure — no
 * fallback to bridge IP, since that would mint NFTs with garbage data.
 */
function resolvePublicAddress(vmName: string): string | null {
  const result = spawnSync(
    "blockhost-network-hook",
    ["public-address", vmName],
    { timeout: PYTHON_TIMEOUT_MS, encoding: "utf8" },
  );
  if (result.status !== 0) {
    const errMsg = (result.stderr ?? "").toString().trim();
    console.error(
      `[ERROR] blockhost-network-hook public-address failed for ${vmName}: ${errMsg || `exit ${String(result.status)}`}`,
    );
    return null;
  }
  const host = (result.stdout ?? "").toString().trim();
  return host.length > 0 ? host : null;
}

/**
 * Push mode-specific config into the VM via the network-hook dispatcher.
 * Idempotent. Returns true on exit 0, false otherwise. Reconciler retries
 * failed pushes on its next cycle.
 */
function pushVmConfig(vmName: string): boolean {
  const result = spawnSync(
    "blockhost-network-hook",
    ["push-vm-config", vmName],
    { timeout: GUEST_EXEC_TIMEOUT_MS, encoding: "utf8" },
  );
  if (result.status !== 0) {
    const errMsg = (result.stderr ?? "").toString().trim();
    console.warn(
      `[WARN] blockhost-network-hook push-vm-config failed for ${vmName}: ${errMsg || `exit ${String(result.status)}`}`,
    );
    return false;
  }
  return true;
}

/**
 * Release per-VM network resources (host- and guest-side) via the dispatcher.
 * Idempotent. Best-effort — logs a warning on failure but does not throw.
 */
function networkHookCleanup(vmName: string): void {
  const result = spawnSync(
    "blockhost-network-hook",
    ["cleanup", vmName],
    { timeout: GUEST_EXEC_TIMEOUT_MS, encoding: "utf8" },
  );
  if (result.status !== 0) {
    const errMsg = (result.stderr ?? "").toString().trim();
    console.warn(
      `[WARN] blockhost-network-hook cleanup failed for ${vmName}: ${errMsg || `exit ${String(result.status)}`}`,
    );
  }
}

/**
 * Persist the engine-defined `network_config_synced` boolean on a VM record.
 * Routed through `blockhost-vmdb update-fields` so the write goes through
 * common's lockfile and races safely with the reconciler and other writers.
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
      `[WARN] Failed to record network_config_synced=${String(synced)} for ${vmName}${errMsg ? ": " + errMsg : ""}`,
    );
  }
}

// ── VM ID counter ─────────────────────────────────────────────────────────────

/**
 * Format a VM ID as a VM name: blockhost-001, blockhost-042, etc.
 */
function formatVmName(vmId: number): string {
  return `blockhost-${vmId.toString().padStart(3, "0")}`;
}

// ── Expiry calculation ────────────────────────────────────────────────────────

/**
 * Milliseconds per day.
 */
const MS_PER_DAY = 86_400_000n;

/**
 * Calculate days remaining from the current POSIX ms timestamp until expiry.
 * currentMs defaults to 0 if not provided. Returns at least 1.
 */
function calculateExpiryDays(expiry: bigint, currentMs?: bigint): number {
  const now = currentMs ?? 0n;
  if (expiry <= now) return 1;
  const msRemaining = expiry - now;
  const days = Number(msRemaining / MS_PER_DAY);
  return Math.max(1, days);
}

/**
 * Calculate additional days between two expiry POSIX ms timestamps.
 * Used when a subscription is extended.
 */
function calculateAdditionalDays(oldExpiry: bigint, newExpiry: bigint): number {
  if (newExpiry <= oldExpiry) return 0;
  const msDelta = newExpiry - oldExpiry;
  const days = Number(msDelta / MS_PER_DAY);
  return Math.max(1, days);
}

// ── Crypto helpers ────────────────────────────────────────────────────────────

/**
 * Decrypt ECIES-encrypted datum field using the server private key.
 * Returns the decrypted plaintext (user signature), or null on failure.
 */
function decryptUserSignature(userEncryptedHex: string): string | null {
  try {
    const privateKey = loadServerPrivateKey();
    return eciesDecrypt(privateKey, userEncryptedHex);
  } catch (err) {
    console.error(`[ERROR] Failed to decrypt user signature: ${err}`);
    return null;
  }
}

/**
 * Encrypt connection details with the user's signature as key material.
 * Returns hex-encoded ciphertext, or null on failure.
 */
function encryptConnectionDetails(
  userSignature: string,
  hostname: string,
  username: string,
): string | null {
  const connectionDetails = JSON.stringify({
    hostname,
    port: SSH_PORT,
    username,
  });

  try {
    return symmetricEncrypt(userSignature, connectionDetails);
  } catch (err) {
    console.error(`[ERROR] Failed to encrypt connection details: ${err}`);
    return null;
  }
}

// ── Command runner ────────────────────────────────────────────────────────────

function runCommand(
  command: string,
  args: string[],
): Promise<{ stdout: string; stderr: string; code: number }> {
  return new Promise((resolve) => {
    const proc = spawn(command, args, { cwd: STATE_DIR });
    let stdout = "";
    let stderr = "";
    proc.stdout.on("data", (data) => { stdout += data.toString(); });
    proc.stderr.on("data", (data) => { stderr += data.toString(); });
    proc.on("close", (code) => {
      resolve({ stdout, stderr, code: code ?? 1 });
    });
  });
}

// ── Output parsers ────────────────────────────────────────────────────────────

/** Summary JSON emitted by blockhost-vm-create (last JSON line in stdout) */
interface VmCreateSummary {
  status: string;
  vm_name: string;
  ip: string;
  ipv6?: string;
  vmid: number;
  username: string;
}

function parseVmSummary(stdout: string): VmCreateSummary | null {
  const lines = stdout.trim().split("\n");
  for (let i = lines.length - 1; i >= 0; i--) {
    const line = lines[i]!.trim();
    if (line.startsWith("{")) {
      try {
        return JSON.parse(line) as VmCreateSummary;
      } catch {
        return null;
      }
    }
  }
  return null;
}

function parseMintOutput(stdout: string): number | null {
  const trimmed = stdout.trim();
  const id = parseInt(trimmed, 10);
  return isNaN(id) ? null : id;
}

// ── Database helpers ──────────────────────────────────────────────────────────

/**
 * Mark an NFT as minted in the VM database via the blockhost-vmdb CLI.
 */
function markNftMinted(vmName: string, nftTokenId: number): void {
  const result = spawnSync(
    "blockhost-vmdb",
    ["mark-nft-minted", vmName, String(nftTokenId)],
    { timeout: PYTHON_TIMEOUT_MS },
  );
  if (result.status !== 0) {
    const errMsg = result.stderr ? result.stderr.toString().trim() : "";
    console.error(
      `[WARN] Failed to mark NFT ${nftTokenId} as minted in database${errMsg ? ": " + errMsg : ""}`,
    );
  }
}

/**
 * Look up a VM name by beacon (with subscriber fallback). Read-only query
 * against vm_db; no mutation, no race. Returns null if no VM matches.
 *
 * Used by the extend and remove handlers, both of which receive a beacon
 * name and need to resolve it to a vm_name before issuing the actual
 * mutator call (extend-expiry / destroy).
 */
function lookupVmName(beaconName: string, subscriber: string): string | null {
  const script = `
import os, sys
from blockhost.vm_db import get_database

db = get_database()
vm = db.get_vm_by_beacon(os.environ['BEACON_NAME']) or db.get_vm_by_owner(os.environ['SUBSCRIBER'])
if vm:
    print(vm['vm_name'])
else:
    sys.exit(1)
`;
  const result = spawnSync("python3", ["-c", script], {
    cwd: STATE_DIR,
    timeout: PYTHON_TIMEOUT_MS,
    env: { ...process.env, BEACON_NAME: beaconName, SUBSCRIBER: subscriber },
    encoding: "utf8",
  });
  if (result.status !== 0) return null;
  return (result.stdout ?? "").toString().trim() || null;
}

/**
 * Record beacon_name and utxo_ref on a VM entry so the scanner can skip
 * the beacon on restart. Goes through vm_db's lockfile (via the
 * blockhost-vmdb CLI) to avoid racing the reconciler and other writers
 * (set_nft_minted, extend_expiry). beacon_name and utxo_ref are
 * Cardano-owned field names; common stays agnostic and just merges them.
 */
function updateBeaconInfo(vmName: string, beaconName: string, utxoRef: string): void {
  const fields = JSON.stringify({ beacon_name: beaconName, utxo_ref: utxoRef });
  const result = spawnSync(
    "blockhost-vmdb",
    ["update-fields", vmName, "--fields", fields],
    { timeout: PYTHON_TIMEOUT_MS },
  );
  if (result.status !== 0) {
    const errMsg = result.stderr ? result.stderr.toString().trim() : "";
    console.warn(
      `[WARN] Failed to record beacon info for ${vmName}${errMsg ? ": " + errMsg : ""}`,
    );
  }
}

// ── VM lifecycle helpers ──────────────────────────────────────────────────────

async function destroyVm(vmName: string): Promise<{ success: boolean; output: string }> {
  const result = await runCommand(getCommand("destroy"), [vmName]);
  return {
    success: result.code === 0,
    output: (result.code === 0 ? result.stdout : result.stderr || result.stdout).trim(),
  };
}

// ── Handler: new subscription ─────────────────────────────────────────────────

/**
 * Handle a newly-detected beacon UTXO.
 *
 * Allocates a VM ID from the local counter, then runs the full 8-step
 * provisioning pipeline: decrypt → create VM → parse summary → encrypt
 * connection details → mint NFT → parse token ID → update GECOS → mark minted.
 */
export async function handleSubscriptionCreated(sub: TrackedSubscription): Promise<void> {
  const { datum, beaconName, utxoRef } = sub;

  // Validate subscriber key hash (28 bytes = 56 hex chars)
  if (!/^[0-9a-fA-F]{56}$/.test(datum.subscriber)) {
    console.error(
      `[ERROR] Invalid subscriber key hash for beacon ${beaconName}: ${datum.subscriber}`,
    );
    return;
  }

  // Defer if the fund cycle is collecting subscription UTXOs in this process.
  // Both paths spend deployer-wallet UTXOs and would race on selection.
  // The scanner re-detects the beacon on the next pass and we retry.
  if (isFundCycleInProgress()) {
    console.log(
      `[INFO] Fund cycle in progress, deferring provisioning for beacon ${beaconName}`,
    );
    return;
  }

  const vmId = await allocateCounter(NEXT_VM_ID_FILE);
  const vmName = formatVmName(vmId);
  const expiryDays = calculateExpiryDays(datum.expiry, BigInt(Date.now()));

  console.log("\n========== SUBSCRIPTION CREATED ==========");
  console.log(`Beacon:      ${beaconName}`);
  console.log(`UTXO:        ${utxoRef}`);
  console.log(`Plan ID:     ${datum.planId}`);
  console.log(`Subscriber:  ${datum.subscriber}`);
  console.log(`Expiry (POSIX ms): ${datum.expiry}`);
  console.log(`Amount:      ${datum.amountRemaining} (rate: ${datum.ratePerInterval}/${datum.intervalMs} ms)`);
  console.log(`User enc:    ${datum.userEncrypted.length > 10 ? datum.userEncrypted.slice(0, 10) + "..." : datum.userEncrypted}`);
  console.log("------------------------------------------");
  console.log(`Provisioning VM: ${vmName} (${expiryDays} days)`);

  // Step 1: Decrypt user signature (fail fast before spending time on VM create)
  let userSignature: string | null = null;
  if (datum.userEncrypted && datum.userEncrypted.length > 0) {
    console.log("Decrypting user signature...");
    userSignature = decryptUserSignature(datum.userEncrypted);
    if (!userSignature) {
      // Subscriber paid and supplied an encrypted signature, but we cannot
      // decrypt it. Continuing would mint an NFT with no encrypted connection
      // details — the subscriber would never be able to authenticate against
      // their VM. Abort and let an operator investigate.
      console.error(
        `[ERROR] Aborting provisioning for beacon ${beaconName}: ` +
        `userEncrypted is set but ECIES decryption failed`,
      );
      console.log("==========================================\n");
      return;
    }
    console.log("User signature decrypted successfully");
  }

  // Step 2: Create VM
  const createArgs = [
    vmName,
    "--owner-wallet", datum.subscriber,
    "--expiry-days", expiryDays.toString(),
    "--apply",
  ];

  console.log("Creating VM...");
  const createResult = await runCommand(getCommand("create"), createArgs);

  if (createResult.code !== 0) {
    console.error(`[ERROR] Failed to provision VM ${vmName}`);
    console.error(createResult.stderr || createResult.stdout);
    console.log("==========================================\n");
    return;
  }

  console.log(`[OK] VM ${vmName} provisioned successfully`);

  // Save beacon name to vms.json so the scanner can skip it on restart.
  // Non-fatal — scanner will re-detect but provisioner will skip existing VM.
  updateBeaconInfo(vmName, beaconName, utxoRef);

  // Step 3: Parse JSON summary from provisioner stdout
  const summary = parseVmSummary(createResult.stdout);
  if (!summary) {
    console.log("[INFO] No JSON summary from provisioner");
    console.log(createResult.stdout);
    console.log("==========================================\n");
    return;
  }

  console.log(`[INFO] VM summary: ip=${summary.ip}, vmid=${summary.vmid}`);

  // Step 4: Resolve subscriber-facing host via the network-hook dispatcher.
  // The dispatcher reads vm-db.network_mode for this VM and forwards to the
  // active plugin. No fallback — minting an NFT against the bridge IP would
  // bake garbage data into the on-chain credential.
  const host = resolvePublicAddress(vmName);
  if (!host) {
    console.error(
      `[ERROR] Aborting provisioning for ${vmName}: blockhost-network-hook public-address returned no host`,
    );
    console.log("==========================================\n");
    return;
  }
  console.log(`[INFO] Connection endpoint: ${host}`);

  // Step 5: Encrypt connection details with user signature
  let userEncryptedOut = "";

  if (userSignature) {
    const encrypted = encryptConnectionDetails(userSignature, host, summary.username);
    if (encrypted) {
      userEncryptedOut = encrypted;
      console.log("[OK] Connection details encrypted");
    } else {
      console.warn("[WARN] Failed to encrypt connection details, minting without user data");
    }
  }

  // Step 6: Mint NFT
  // The subscriber field is a payment key hash — mint script needs a bech32 address.
  // Build an enterprise address (key hash only, no staking) from the payment credential.
  const { network: currentNetwork } = loadNetworkConfig();
  const headerByte = currentNetwork === "mainnet" ? 0x61 : 0x60;
  const addrBytes = Buffer.from([headerByte, ...Buffer.from(datum.subscriber, "hex")]);
  const subscriberAddress = bech32.encode(
    currentNetwork === "mainnet" ? "addr" : "addr_test",
    bech32.toWords(addrBytes),
    256,
  );
  const mintArgs: string[] = ["--owner-wallet", subscriberAddress];
  if (userEncryptedOut) {
    // Strip 0x prefix if present — mint script expects raw hex
    const cleanHex = userEncryptedOut.startsWith("0x") ? userEncryptedOut.slice(2) : userEncryptedOut;
    mintArgs.push("--user-encrypted", cleanHex);
  }

  console.log("Minting NFT...");
  const mintResult = await runCommand("blockhost-mint-nft", mintArgs);

  if (mintResult.code !== 0) {
    console.error(`[WARN] NFT minting failed for ${vmName} (VM is still operational)`);
    console.error(mintResult.stderr || mintResult.stdout);
    console.error(
      `[WARN] Retry manually: blockhost-mint-nft --owner-wallet ${datum.subscriber} --user-encrypted <hex>`,
    );
    console.log("==========================================\n");
    return;
  }

  // Parse token ID from mint stdout
  const actualTokenId = parseMintOutput(mintResult.stdout);
  if (actualTokenId === null) {
    console.error(`[WARN] Could not parse token ID from mint output: ${mintResult.stdout.trim()}`);
    console.log("==========================================\n");
    return;
  }

  console.log(`[OK] NFT minted for ${vmName} (token #${actualTokenId})`);

  // Step 7: Push mode-specific VM-side config via the network-hook dispatcher.
  // Best-effort: the reconciler retries on its next cycle if the guest agent
  // wasn't ready yet. Either outcome writes network_config_synced so the
  // reconciler has a definitive flag to gate retries on.
  const pushed = pushVmConfig(vmName);
  setNetworkConfigSynced(vmName, pushed);
  if (pushed) {
    console.log(`[OK] VM config pushed for ${vmName}`);
  } else {
    console.warn(`[WARN] push-vm-config failed for ${vmName}; reconciler will retry`);
  }

  // Step 8: Update GECOS with actual token ID
  // Wait for the guest agent to start — the VM was just created and may
  // still be booting.  Retry a few times with delays.
  // Not fatal if GECOS failed — reconciler will retry on next cycle
  const gecosCmd = getCommand("update-gecos");
  const gecosArgs = [vmName, datum.subscriber, "--nft-id", String(actualTokenId)];
  for (let attempt = 1; attempt <= 4; attempt++) {
    if (attempt > 1) {
      console.log(`[INFO] Waiting for guest agent (attempt ${attempt}/4)...`);
      await new Promise((r) => setTimeout(r, 15_000));
    }
    const gecosResult = spawnSync(gecosCmd, gecosArgs, { timeout: 30_000, cwd: STATE_DIR });
    if (gecosResult.status === 0) {
      console.log(`[OK] GECOS updated for ${vmName}`);
      break;
    }
    if (attempt === 4) {
      const errMsg = gecosResult.stderr ? gecosResult.stderr.toString().trim() : "";
      console.error(`[WARN] update-gecos failed for ${vmName} after ${attempt} attempts${errMsg ? ": " + errMsg : ""}`);
    }
  }

  // Step 9: Mark NFT minted in database
  markNftMinted(vmName, actualTokenId);

  console.log("==========================================\n");
}

// ── Handler: subscription extended ───────────────────────────────────────────

/**
 * Handle a beacon UTXO that changed to a new UTXO ref (spend-and-recreate).
 *
 * The new datum carries an updated expiry timestamp and amountRemaining.
 * We calculate additional days from the delta between old and new expiry,
 * update the VM database, and resume the VM if it was suspended.
 */
export async function handleSubscriptionExtended(
  old: TrackedSubscription,
  updated: TrackedSubscription,
): Promise<void> {
  const { datum: newDatum, beaconName } = updated;

  console.log("\n========== SUBSCRIPTION EXTENDED ==========");
  console.log(`Beacon:         ${beaconName}`);
  console.log(`Old UTXO:       ${old.utxoRef}`);
  console.log(`New UTXO:       ${updated.utxoRef}`);
  console.log(`Old expiry (POSIX ms): ${old.datum.expiry}`);
  console.log(`New expiry (POSIX ms): ${newDatum.expiry}`);
  console.log(`Old amount:      ${old.datum.amountRemaining}`);
  console.log(`New amount:      ${newDatum.amountRemaining}`);
  console.log(`Subscriber:      ${newDatum.subscriber}`);
  console.log("-------------------------------------------");

  const additionalDays = calculateAdditionalDays(old.datum.expiry, newDatum.expiry);
  console.log(`Additional days: ${additionalDays}`);

  // Resolve beacon → vm_name (read-only, no race). Then call the CLI's
  // extend-expiry, which performs the suspended-status check inside the
  // same lockfile as the extend itself — closing the TOCTOU race the
  // previous combined Python script had between reading status and
  // calling extend_expiry.
  const vmName = lookupVmName(beaconName, newDatum.subscriber);
  if (!vmName) {
    console.warn(`[WARN] VM not found for beacon ${beaconName} / subscriber ${newDatum.subscriber}`);
    console.log("===========================================\n");
    return;
  }

  const extendResult = spawnSync(
    "blockhost-vmdb",
    ["extend-expiry", vmName, String(additionalDays)],
    { timeout: PYTHON_TIMEOUT_MS, encoding: "utf8" },
  );
  if (extendResult.status !== 0) {
    const errMsg = (extendResult.stderr ?? "").toString().trim();
    console.error(`[ERROR] Failed to extend expiry for ${vmName}${errMsg ? ": " + errMsg : ""}`);
    console.log("===========================================\n");
    return;
  }

  const stdout = (extendResult.stdout ?? "").toString();
  const firstLine = stdout.split("\n")[0]?.trim() ?? "";
  if (firstLine) console.log(`[OK] ${firstLine}`);
  const needsResume = stdout.includes("NEEDS_RESUME");

  // Resume VM if the CLI reports it was suspended at extend time.
  if (needsResume) {
    console.log(`Resuming suspended VM: ${vmName}`);
    const resumeResult = await runCommand(getCommand("resume"), [vmName]);
    if (resumeResult.code === 0) {
      console.log(`[OK] Successfully resumed VM: ${vmName}`);
      if (resumeResult.stdout.trim()) {
        console.log(resumeResult.stdout.trim());
      }
    } else {
      console.error(`[WARN] Failed to resume VM ${vmName}`);
      console.error(`[WARN] ${(resumeResult.stderr || resumeResult.stdout).trim()}`);
      console.error("[WARN] Operator may need to manually resume the VM");
    }
  }

  console.log("===========================================\n");
}

// ── Handler: subscription removed ────────────────────────────────────────────

/**
 * Handle a beacon UTXO that has disappeared (beacon burned).
 *
 * This covers both ServiceCollect (server collected funds) and SubscriberCancel.
 * In both cases we destroy the VM — for now there is no distinction between the
 * two redeemers at this layer (the datum is gone with the UTXO).
 */
export async function handleSubscriptionRemoved(sub: TrackedSubscription): Promise<void> {
  const { datum, beaconName, utxoRef } = sub;

  console.log("\n========== SUBSCRIPTION REMOVED ==========");
  console.log(`Beacon:     ${beaconName}`);
  console.log(`UTXO:       ${utxoRef}`);
  console.log(`Plan ID:    ${datum.planId}`);
  console.log(`Subscriber: ${datum.subscriber}`);
  console.log("------------------------------------------");

  // Look up the VM name by beacon name (or subscriber fallback) then destroy
  const vmName = lookupVmName(beaconName, datum.subscriber);
  if (!vmName) {
    console.warn(`[WARN] VM not found for beacon ${beaconName} — nothing to destroy`);
    console.log("==========================================\n");
    return;
  }
  // Release per-VM network resources before destroy so the active plugin can
  // reverse guest-side state (e.g. revert /etc/hosts, stop a hidden service)
  // while the VM is still running. Best-effort — leftover host-side resources
  // are worse than a redundant cleanup, so we always proceed to destroy.
  networkHookCleanup(vmName);

  console.log(`Destroying VM: ${vmName}`);

  const { success, output } = await destroyVm(vmName);

  if (success) {
    console.log(`[OK] ${output}`);
  } else {
    console.error(`[ERROR] Failed to destroy VM ${vmName}: ${output}`);
  }

  console.log("==========================================\n");
}
