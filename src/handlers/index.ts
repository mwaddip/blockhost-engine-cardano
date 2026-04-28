/**
 * Subscription event handlers — provision, extend, and destroy VMs.
 *
 * Adapts the OPNet handler pipeline for Cardano's beacon-based detection model.
 * Input is TrackedSubscription (from the beacon scanner), not a contract event.
 *
 * Pipeline for new subscriptions (8 steps):
 *   1. Decrypt userEncrypted from datum (ECIES with server key)
 *   2. Call provisioner create with --owner-wallet and --expiry-days
 *   3. Parse JSON summary from provisioner stdout, resolve host via network hook
 *   4. Encrypt connection details with user signature (SHAKE256 + AES-GCM)
 *   5. Call blockhost-mint-nft with --owner-wallet and --user-encrypted
 *   6. Parse token ID from mint stdout
 *   7. Call provisioner update-gecos with VM name, wallet, NFT token ID
 *   8. Mark NFT minted in database (Python subprocess)
 *
 * The engine is network-mode-agnostic: step 3's network hook call returns
 * an IPv6 (broker), static IP (manual), or .onion (onion) as appropriate.
 */

import { spawn, spawnSync } from "child_process";
import * as fs from "node:fs";
import type { TrackedSubscription } from "../monitor/scanner.js";
import { eciesDecrypt, symmetricEncrypt, loadServerPrivateKey } from "../crypto.js";
import { getCommand } from "../provisioner.js";
import { STATE_DIR, VMS_JSON_PATH, CONFIG_DIR, PYTHON_TIMEOUT_MS } from "../paths.js";

// ── Constants ─────────────────────────────────────────────────────────────────
const SSH_PORT = 22;
const NEXT_VM_ID_FILE = `${STATE_DIR}/next-vm-id`;
const NETWORK_MODE_PATH = `${CONFIG_DIR}/network-mode`;

// ── Network mode ──────────────────────────────────────────────────────────────

/**
 * Read the active network mode from /etc/blockhost/network-mode.
 * Valid values: "broker" | "manual" | "onion". Defaults to "broker" when
 * the file is absent or contains an unrecognized value.
 */
function readNetworkMode(): string {
  try {
    const raw = fs.readFileSync(NETWORK_MODE_PATH, "utf8").trim();
    if (raw === "broker" || raw === "manual" || raw === "onion") return raw;
    console.warn(`[WARN] Invalid network mode "${raw}" in ${NETWORK_MODE_PATH} — defaulting to broker`);
  } catch {
    // File absent — backwards compatibility: broker
  }
  return "broker";
}

/** Active network mode, resolved once at module startup. */
const NETWORK_MODE = readNetworkMode();

// ── Network hook (Python bridge) ──────────────────────────────────────────────

/**
 * Resolve the subscriber-facing connection endpoint for a VM.
 *
 * Calls blockhost.network_hook.get_connection_endpoint via a Python subprocess.
 *   broker  → IPv6 from broker-allocation.json
 *   manual  → static IP from config
 *   onion   → .onion address (creates hidden service, pushes into VM)
 *
 * Returns the resolved host on success, or null on failure.
 */
function getConnectionEndpoint(vmName: string, bridgeIp: string, mode: string): string | null {
  const script = `
import os
from blockhost.network_hook import get_connection_endpoint
print(get_connection_endpoint(os.environ['VM_NAME'], os.environ['BRIDGE_IP'], os.environ['NETWORK_MODE']))
`;
  const result = spawnSync("python3", ["-c", script], {
    cwd: STATE_DIR,
    timeout: PYTHON_TIMEOUT_MS,
    env: { ...process.env, VM_NAME: vmName, BRIDGE_IP: bridgeIp, NETWORK_MODE: mode },
    encoding: "utf8",
  });
  if (result.status !== 0) {
    const errMsg = (result.stderr ?? "").toString().trim();
    console.error(`[ERROR] network_hook.get_connection_endpoint failed: ${errMsg || `exit ${String(result.status)}`}`);
    return null;
  }
  const host = (result.stdout ?? "").toString().trim();
  return host.length > 0 ? host : null;
}

/**
 * Release network resources allocated for a VM (onion hidden service, etc.).
 * Best-effort — logs a warning on failure but does not throw.
 */
function networkHookCleanup(vmName: string, mode: string): void {
  const script = `
import os
from blockhost.network_hook import cleanup
cleanup(os.environ['VM_NAME'], os.environ['NETWORK_MODE'])
`;
  const result = spawnSync("python3", ["-c", script], {
    cwd: STATE_DIR,
    timeout: PYTHON_TIMEOUT_MS,
    env: { ...process.env, VM_NAME: vmName, NETWORK_MODE: mode },
    encoding: "utf8",
  });
  if (result.status !== 0) {
    const errMsg = (result.stderr ?? "").toString().trim();
    console.warn(`[WARN] network_hook.cleanup failed for ${vmName}: ${errMsg || `exit ${String(result.status)}`}`);
  }
}

// ── VM ID counter ─────────────────────────────────────────────────────────────

/**
 * Read the next VM ID from disk, increment, and persist.
 * Starts at 1 if the file does not exist.
 * File contains a plain decimal integer (no trailing newline required).
 */
async function allocateVmId(): Promise<number> {
  fs.mkdirSync(STATE_DIR, { recursive: true });
  const lockPath = NEXT_VM_ID_FILE + ".lock";

  // Acquire exclusive lock via O_EXCL
  let lockFd = -1;
  for (let i = 0; i < 50; i++) {
    try {
      lockFd = fs.openSync(lockPath, fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_WRONLY);
      break;
    } catch {
      if (i === 49) {
        // Stale lock from crashed process — force acquire
        try { fs.unlinkSync(lockPath); } catch {}
        try {
          lockFd = fs.openSync(lockPath, fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_WRONLY);
        } catch { /* give up */ }
        break;
      }
      await new Promise((r) => setTimeout(r, 100));
    }
  }

  try {
    let current = 1;
    try {
      const raw = fs.readFileSync(NEXT_VM_ID_FILE, "utf8").trim();
      const parsed = parseInt(raw, 10);
      if (!isNaN(parsed) && parsed > 0) current = parsed;
    } catch {
      // File does not exist — start at 1
    }

    fs.writeFileSync(NEXT_VM_ID_FILE, String(current + 1), "utf8");
    return current;
  } finally {
    if (lockFd >= 0) try { fs.closeSync(lockFd); } catch {}
    try { fs.unlinkSync(lockPath); } catch {}
  }
}

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
 * Mark an NFT as minted in the VM database (synchronous Python subprocess).
 */
function markNftMinted(vmName: string, nftTokenId: number): void {
  const script = `
import os
from blockhost.vm_db import get_database
db = get_database()
db.set_nft_minted(os.environ['VM_NAME'], int(os.environ['NFT_TOKEN_ID']))
`;
  const result = spawnSync("python3", ["-c", script], {
    cwd: STATE_DIR,
    timeout: PYTHON_TIMEOUT_MS,
    env: { ...process.env, VM_NAME: vmName, NFT_TOKEN_ID: String(nftTokenId) },
  });
  if (result.status !== 0) {
    const errMsg = result.stderr ? result.stderr.toString().trim() : "";
    console.error(
      `[WARN] Failed to mark NFT ${nftTokenId} as minted in database${errMsg ? ": " + errMsg : ""}`,
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

  const vmId = await allocateVmId();
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
    if (userSignature) {
      console.log("User signature decrypted successfully");
    } else {
      console.warn("[WARN] Could not decrypt user signature, proceeding without encrypted connection details");
    }
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

  // Save beacon name to vms.json so the scanner can skip it on restart
  try {
    const dbPath = VMS_JSON_PATH;
    if (fs.existsSync(dbPath)) {
      const db = JSON.parse(fs.readFileSync(dbPath, "utf8"));
      if (db.vms?.[vmName]) {
        db.vms[vmName].beacon_name = beaconName;
        db.vms[vmName].utxo_ref = utxoRef;
        fs.writeFileSync(dbPath, JSON.stringify(db, null, 2));
      }
    }
  } catch {
    // Non-fatal — scanner will re-detect but provisioner will skip existing VM
  }

  // Step 3: Parse JSON summary from provisioner stdout
  const summary = parseVmSummary(createResult.stdout);
  if (!summary) {
    console.log("[INFO] No JSON summary from provisioner");
    console.log(createResult.stdout);
    console.log("==========================================\n");
    return;
  }

  console.log(`[INFO] VM summary: ip=${summary.ip}, vmid=${summary.vmid}`);

  // Resolve subscriber-facing host via the network hook.
  //   broker → IPv6 from broker-allocation.json
  //   manual → static IP from config
  //   onion  → .onion (hidden service created + pushed into VM)
  const hookHost = getConnectionEndpoint(vmName, summary.ip, NETWORK_MODE);
  const host = hookHost ?? summary.ip;
  if (!hookHost) {
    console.warn(`[WARN] Network hook returned no host for ${vmName} (mode=${NETWORK_MODE}); falling back to bridge IP`);
  } else {
    console.log(`[INFO] Connection endpoint (${NETWORK_MODE}): ${host}`);
  }

  // Step 4: Encrypt connection details with user signature
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

  // Step 5: Mint NFT
  // The subscriber field is a payment key hash — mint script needs a bech32 address.
  // Build an enterprise address (key hash only, no staking) from the payment credential.
  const { bech32 } = await import("bech32");
  const { loadNetworkConfig } = await import("../fund-manager/web3-config.js");
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

  // Step 6: Parse token ID from mint stdout
  const actualTokenId = parseMintOutput(mintResult.stdout);
  if (actualTokenId === null) {
    console.error(`[WARN] Could not parse token ID from mint output: ${mintResult.stdout.trim()}`);
    console.log("==========================================\n");
    return;
  }

  console.log(`[OK] NFT minted for ${vmName} (token #${actualTokenId})`);

  // Step 7: Update GECOS with actual token ID
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

  // Step 8: Mark NFT minted in database
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

  // We need to find the VM name associated with this beacon.
  // The beacon name is the on-chain handle; the VM name is stored in the DB.
  // We query by subscriber address since that's what we have.
  // Use Python to update expiry and check if VM needs resuming.
  const script = `
import os
from blockhost.vm_db import get_database

beacon_name = os.environ['BEACON_NAME']
subscriber = os.environ['SUBSCRIBER']
additional_days = int(os.environ['ADDITIONAL_DAYS'])
db = get_database()
vm = db.get_vm_by_beacon(beacon_name) or db.get_vm_by_owner(subscriber)
if vm:
    old_status = vm.get('status', 'unknown')
    db.extend_expiry(vm['vm_name'], additional_days)
    print(f"Extended {vm['vm_name']} expiry by {additional_days} days")
    if old_status == 'suspended':
        print("NEEDS_RESUME")
    print(f"VM_NAME={vm['vm_name']}")
else:
    print(f"VM not found for beacon {beacon_name} / subscriber {subscriber}")
`;

  const proc = spawn("python3", ["-c", script], {
    cwd: STATE_DIR,
    env: {
      ...process.env,
      BEACON_NAME: beaconName,
      SUBSCRIBER: newDatum.subscriber,
      ADDITIONAL_DAYS: String(additionalDays),
    },
  });

  let output = "";
  proc.stdout.on("data", (data: Buffer) => { output += data.toString(); });
  proc.stderr.on("data", (data: Buffer) => { output += data.toString(); });

  const { needsResume, vmName } = await new Promise<{ needsResume: boolean; vmName: string | null }>(
    (resolve) => {
      proc.on("close", (code) => {
        if (code === 0) {
          const lines = output.trim().split("\n");
          console.log(`[OK] ${lines[0] ?? ""}`);
          const vmNameLine = lines.find((l) => l.startsWith("VM_NAME="));
          const parsedVmName = vmNameLine ? vmNameLine.slice("VM_NAME=".length) : null;
          resolve({ needsResume: output.includes("NEEDS_RESUME"), vmName: parsedVmName });
        } else {
          console.error(`[ERROR] Failed to extend expiry: ${output}`);
          resolve({ needsResume: false, vmName: null });
        }
      });
    },
  );

  // Resume VM if it was suspended
  if (needsResume && vmName) {
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
  const script = `
import os, sys
from blockhost.vm_db import get_database

beacon_name = os.environ['BEACON_NAME']
subscriber = os.environ['SUBSCRIBER']
db = get_database()
vm = db.get_vm_by_beacon(beacon_name) or db.get_vm_by_owner(subscriber)
if vm:
    print(vm['vm_name'])
else:
    sys.exit(1)
`;

  const lookupResult = spawnSync("python3", ["-c", script], {
    cwd: STATE_DIR,
    timeout: PYTHON_TIMEOUT_MS,
    env: { ...process.env, BEACON_NAME: beaconName, SUBSCRIBER: datum.subscriber },
  });

  if (lookupResult.status !== 0) {
    console.warn(`[WARN] VM not found for beacon ${beaconName} — nothing to destroy`);
    console.log("==========================================\n");
    return;
  }

  const vmName = lookupResult.stdout.toString().trim();
  console.log(`Destroying VM: ${vmName}`);

  const { success, output } = await destroyVm(vmName);

  if (success) {
    console.log(`[OK] ${output}`);
  } else {
    console.error(`[ERROR] Failed to destroy VM ${vmName}: ${output}`);
  }

  // Release network resources (onion hidden service, etc.) regardless of
  // destroy success — leftover services are worse than a redundant cleanup.
  networkHookCleanup(vmName, NETWORK_MODE);

  console.log("==========================================\n");
}
