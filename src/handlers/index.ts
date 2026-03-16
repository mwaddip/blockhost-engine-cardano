/**
 * Subscription event handlers — provision, extend, and destroy VMs.
 *
 * Adapts the OPNet handler pipeline for Cardano's beacon-based detection model.
 * Input is TrackedSubscription (from the beacon scanner), not a contract event.
 *
 * Pipeline for new subscriptions (8 steps):
 *   1. Decrypt userEncrypted from datum (ECIES with server key)
 *   2. Call provisioner create with --owner-wallet and --expiry-days
 *   3. Parse JSON summary from provisioner stdout
 *   4. Encrypt connection details with user signature (SHAKE256 + AES-GCM)
 *   5. Call blockhost-mint-nft with --owner-wallet and --user-encrypted
 *   6. Parse token ID from mint stdout
 *   7. Call provisioner update-gecos with VM name, wallet, NFT token ID
 *   8. Mark NFT minted in database (Python subprocess)
 */

import { spawn, spawnSync } from "child_process";
import * as fs from "node:fs";
import type { TrackedSubscription } from "../monitor/scanner.js";
import { eciesDecrypt, symmetricEncrypt, loadServerPrivateKey } from "../crypto.js";
import { getCommand } from "../provisioner.js";
import { isValidAddress } from "../cardano/address.js";

// ── Constants ─────────────────────────────────────────────────────────────────

const WORKING_DIR = "/var/lib/blockhost";
const SSH_PORT = 22;
const NEXT_VM_ID_FILE = "/var/lib/blockhost/next-vm-id";

// ── VM ID counter ─────────────────────────────────────────────────────────────

/**
 * Read the next VM ID from disk, increment, and persist.
 * Starts at 1 if the file does not exist.
 * File contains a plain decimal integer (no trailing newline required).
 */
function allocateVmId(): number {
  let current = 1;
  try {
    const raw = fs.readFileSync(NEXT_VM_ID_FILE, "utf8").trim();
    const parsed = parseInt(raw, 10);
    if (!isNaN(parsed) && parsed > 0) {
      current = parsed;
    }
  } catch {
    // File does not exist — start at 1
  }

  const next = current + 1;
  try {
    fs.mkdirSync(WORKING_DIR, { recursive: true });
    fs.writeFileSync(NEXT_VM_ID_FILE, String(next), "utf8");
  } catch (err) {
    console.error(`[WARN] Could not persist next-vm-id: ${err}`);
  }

  return current;
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
    const proc = spawn(command, args, { cwd: WORKING_DIR });
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
function markNftMinted(nftTokenId: number, ownerWallet: string): void {
  const script = `
import os
from blockhost.vm_db import get_database
db = get_database()
db.mark_nft_minted(int(os.environ['NFT_TOKEN_ID']), os.environ['OWNER_WALLET'])
`;
  const result = spawnSync("python3", ["-c", script], {
    cwd: WORKING_DIR,
    timeout: 10_000,
    env: { ...process.env, NFT_TOKEN_ID: String(nftTokenId), OWNER_WALLET: ownerWallet },
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

  // Validate bech32 subscriber address before using in subprocess args
  if (!isValidAddress(datum.subscriber)) {
    console.error(
      `[ERROR] Invalid subscriber address for beacon ${beaconName}: ${datum.subscriber}`,
    );
    return;
  }

  const vmId = allocateVmId();
  const vmName = formatVmName(vmId);
  const expiryDays = calculateExpiryDays(datum.expiry);

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

  // Step 3: Parse JSON summary from provisioner stdout
  const summary = parseVmSummary(createResult.stdout);
  if (!summary) {
    console.log("[INFO] No JSON summary from provisioner");
    console.log(createResult.stdout);
    console.log("==========================================\n");
    return;
  }

  console.log(`[INFO] VM summary: ip=${summary.ip}, vmid=${summary.vmid}`);

  // Step 4: Encrypt connection details with user signature
  let userEncryptedOut = "";

  if (userSignature) {
    const hostname = summary.ipv6 ?? summary.ip;
    const encrypted = encryptConnectionDetails(userSignature, hostname, summary.username);
    if (encrypted) {
      userEncryptedOut = encrypted;
      console.log("[OK] Connection details encrypted");
    } else {
      console.warn("[WARN] Failed to encrypt connection details, minting without user data");
    }
  }

  // Step 5: Mint NFT
  const mintArgs: string[] = ["--owner-wallet", datum.subscriber];
  if (userEncryptedOut) {
    mintArgs.push("--user-encrypted", userEncryptedOut);
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
  const gecosCmd = getCommand("update-gecos");
  const gecosArgs = [vmName, datum.subscriber, "--nft-id", String(actualTokenId)];
  const gecosResult = spawnSync(gecosCmd, gecosArgs, { timeout: 30_000, cwd: WORKING_DIR });
  if (gecosResult.status !== 0) {
    const errMsg = gecosResult.stderr ? gecosResult.stderr.toString().trim() : "";
    console.error(`[WARN] update-gecos failed for ${vmName}${errMsg ? ": " + errMsg : ""}`);
    // Not fatal — reconciler will retry
  } else {
    console.log(`[OK] GECOS updated for ${vmName}`);
  }

  // Step 8: Mark NFT minted in database
  markNftMinted(actualTokenId, datum.subscriber);

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
    cwd: WORKING_DIR,
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
    cwd: WORKING_DIR,
    timeout: 10_000,
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

  console.log("==========================================\n");
}
