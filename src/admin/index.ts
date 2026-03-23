/**
 * Admin command dispatcher — HMAC-authenticated Cardano metadata protocol.
 *
 * Protocol:
 *   Transaction metadata label: 7368 (hex for "sh")
 *   Metadata value: hex string of message_bytes + hmac_suffix(16 bytes)
 *   message = "{nonce} {command text}" (UTF-8)
 *   hmac_suffix = HMAC-SHA256(shared_key, message_bytes)[:16]
 *
 * Shared key stored during initial admin setup in blockhost.yaml under
 * admin.shared_key.
 *
 * Detection:
 *   1. Query recent transactions from admin address via Blockfrost
 *   2. For each tx, fetch /txs/{hash}/metadata
 *   3. Look for label 7368 — parse its value as the command payload
 *   4. Decrypt with shared key, validate HMAC, check nonce, dispatch
 */

import { hmac } from "@noble/hashes/hmac";
import { sha256 } from "@noble/hashes/sha2";
import type { BlockFrostAPI } from "../cardano/provider.js";
import type {
  AdminCommand,
  AdminConfig,
  CommandResult,
  CommandDatabase,
  KnockParams,
  KnockActionConfig,
} from "./types.js";
import { loadCommandDatabase } from "./config.js";
import { isNonceUsed, markNonceUsed, pruneOldNonces, loadNonces } from "./nonces.js";
import { executeKnock, closeAllKnocks } from "./handlers/knock.js";
import { hexToBytes } from "../crypto.js";

/** Metadata label used for admin commands (7368 = hex for "sh") */
const ADMIN_METADATA_LABEL = 7368;

/**
 * Constant-time comparison of two Uint8Arrays.
 */
function timingSafeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= (a[i] ?? 0) ^ (b[i] ?? 0);
  }
  return diff === 0;
}

// ── Action Handlers ──────────────────────────────────────────────────────────

const ACTION_HANDLERS: Record<
  string,
  (
    params: Record<string, unknown>,
    config: Record<string, unknown>,
    txHash: string,
  ) => Promise<CommandResult>
> = {
  knock: async (params, config, txHash) =>
    executeKnock(
      params as unknown as KnockParams,
      config as unknown as KnockActionConfig,
      txHash,
    ),
};

// ── Metadata Parsing ─────────────────────────────────────────────────────────

/**
 * Parse and verify a metadata payload as an HMAC-authenticated admin command.
 *
 * @param payload   - Raw command bytes from metadata value
 * @param sharedKey - 32-byte shared key (hex, no prefix)
 * @returns Parsed command or null if HMAC verification fails
 */
export function parseMetadataCommand(
  payload: Uint8Array,
  sharedKey: string,
): AdminCommand | null {
  // Minimum: 1 (nonce) + 1 (space) + 1 (command) + 16 (hmac) = 19 bytes
  if (payload.length < 19) return null;

  const message = payload.slice(0, payload.length - 16);
  const hmacSuffix = payload.slice(payload.length - 16);

  // Verify HMAC-SHA256 truncated to 16 bytes (128-bit)
  const keyBytes = hexToBytes(sharedKey);
  const expectedHmac = hmac(sha256, keyBytes, message).slice(0, 16);

  if (!timingSafeEqual(hmacSuffix, expectedHmac)) {
    return null; // HMAC mismatch — not an admin command
  }

  // Parse message: "{nonce} {command}"
  const messageStr = new TextDecoder().decode(message);
  const spaceIdx = messageStr.indexOf(" ");
  if (spaceIdx < 1) return null;

  const nonce = messageStr.slice(0, spaceIdx);
  const command = messageStr.slice(spaceIdx + 1).trim();

  if (!nonce || !command) return null;

  return { command, nonce };
}

// ── Validation & Dispatch ────────────────────────────────────────────────────

/**
 * Validate command nonce (anti-replay)
 */
export function validateCommand(cmd: AdminCommand): { valid: boolean; reason?: string } {
  if (isNonceUsed(cmd.nonce)) {
    return { valid: false, reason: `Nonce already used (replay attack prevented)` };
  }
  return { valid: true };
}

/**
 * Dispatch a validated command to its handler
 */
export async function dispatchCommand(
  cmd: AdminCommand,
  txHash: string,
  commandDb: CommandDatabase,
): Promise<CommandResult> {
  const cmdDef = commandDb.commands[cmd.command];
  if (!cmdDef) {
    return { success: false, message: `Unknown command: ${cmd.command}` };
  }

  const handler = ACTION_HANDLERS[cmdDef.action];
  if (!handler) {
    return { success: false, message: `Unknown action type: ${cmdDef.action}` };
  }

  console.log(`[ADMIN] Dispatching action '${cmdDef.action}' for command '${cmd.command}'`);
  return handler(cmdDef.params, cmdDef.params, txHash);
}

// ── Blockfrost metadata shape ─────────────────────────────────────────────────

interface BlockfrostTxMeta {
  label: string;
  json_metadata: unknown;
}

interface BlockfrostAddrTx {
  tx_hash: string;
}

// ── Block Processing ──────────────────────────────────────────────────────────

/**
 * Process admin commands from transaction metadata.
 *
 * Queries recent transactions from the admin address via Blockfrost and
 * checks each for metadata under label 7368.  The metadata value is
 * treated as a hex-encoded HMAC-authenticated command payload.
 *
 * We scan up to 20 recent transactions on each call.  Because we track
 * nonces (monotonically increasing block-heights) any command that was
 * already executed will be rejected on replay.
 */
export async function processAdminCommands(
  client: BlockFrostAPI,
  adminConfig: AdminConfig,
): Promise<void> {
  const commandDb = loadCommandDatabase();
  if (!commandDb) return;

  pruneOldNonces(adminConfig.max_command_age);

  let recentTxs: BlockfrostAddrTx[];
  try {
    const raw = await client.addressesTransactions(adminConfig.wallet_address, {
      count: 20,
      order: "desc",
    });
    recentTxs = raw as BlockfrostAddrTx[];
  } catch (err: unknown) {
    if (isBlockfrost404(err)) {
      // Admin address has no transactions yet — nothing to do
      return;
    }
    console.error(`[ADMIN] Error querying admin address transactions: ${err}`);
    return;
  }

  for (const tx of recentTxs) {
    try {
      await processTransaction(client, tx.tx_hash, adminConfig, commandDb);
    } catch (err) {
      console.error(`[ADMIN] Error processing tx ${tx.tx_hash}: ${err}`);
    }
  }
}

/**
 * Process a single transaction for potential admin metadata commands.
 */
async function processTransaction(
  client: BlockFrostAPI,
  txHash: string,
  adminConfig: AdminConfig,
  commandDb: CommandDatabase,
): Promise<void> {
  let metaList: BlockfrostTxMeta[];
  try {
    const raw = await client.txsMetadata(txHash);
    metaList = raw as BlockfrostTxMeta[];
  } catch (err: unknown) {
    if (isBlockfrost404(err)) return; // No metadata
    throw err;
  }

  for (const entry of metaList) {
    // Check for our admin command label
    if (Number(entry.label) !== ADMIN_METADATA_LABEL) continue;

    // Metadata value must be a hex string
    const metaValue = entry.json_metadata;
    if (typeof metaValue !== "string") continue;

    // Decode hex payload
    const hexStr = metaValue.startsWith("0x") ? metaValue.slice(2) : metaValue;
    if (!/^[0-9a-fA-F]+$/.test(hexStr) || hexStr.length % 2 !== 0) {
      console.warn(`[ADMIN] Invalid hex in metadata for tx ${txHash}`);
      continue;
    }

    const payload = hexToBytes(hexStr);
    const cmd = parseMetadataCommand(payload, adminConfig.shared_key);
    if (!cmd) continue; // HMAC failed — not an admin command (or wrong key)

    console.log(`[ADMIN] Verified admin command from tx: ${txHash}`);

    const validation = validateCommand(cmd);
    if (!validation.valid) {
      console.warn(`[ADMIN] Command validation failed: ${validation.reason} (tx: ${txHash})`);
      continue;
    }

    markNonceUsed(cmd.nonce);
    console.log(`[ADMIN] Executing command '${cmd.command}' from tx: ${txHash}`);

    const result = await dispatchCommand(cmd, txHash, commandDb);
    if (result.success) {
      console.log(`[ADMIN] Command succeeded: ${result.message}`);
    } else {
      console.error(`[ADMIN] Command failed: ${result.message}`);
    }
  }
}

// ── Lifecycle ─────────────────────────────────────────────────────────────────

/**
 * Initialize admin command system
 */
export function initAdminCommands(): void {
  loadNonces();
  console.log(`[ADMIN] Admin command system initialized (HMAC metadata label ${ADMIN_METADATA_LABEL})`);
}

/**
 * Cleanup on shutdown
 */
export async function shutdownAdminCommands(): Promise<void> {
  await closeAllKnocks();
  console.log(`[ADMIN] Admin command system shutdown`);
}

// ── Utility ───────────────────────────────────────────────────────────────────

function isBlockfrost404(err: unknown): boolean {
  return (
    typeof err === "object" &&
    err !== null &&
    "status_code" in err &&
    (err as { status_code: number }).status_code === 404
  );
}

// Re-export only what external consumers need
export { loadAdminConfig } from "./config.js";
export type { AdminConfig } from "./types.js";
