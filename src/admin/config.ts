/**
 * Admin configuration loading and validation (Cardano)
 *
 * Loads HMAC shared key for transaction metadata command authentication.
 * Validates wallet addresses as Cardano bech32 format.
 */

import * as fs from "fs";
import * as yaml from "js-yaml";
import type { AdminConfig, CommandDatabase } from "./types.js";
import { isValidAddress } from "../cardano/address.js";

const CONFIG_DIR = process.env["BLOCKHOST_CONFIG_DIR"] ?? "/etc/blockhost";
const BLOCKHOST_CONFIG_FILE = `${CONFIG_DIR}/blockhost.yaml`;
const ADMIN_COMMANDS_FILE = `${CONFIG_DIR}/admin-commands.json`;

const HEX32_RE = /^[0-9a-fA-F]{64}$/;

/**
 * Load admin configuration from blockhost.yaml
 * Returns null if admin commands are not configured
 */
export function loadAdminConfig(): AdminConfig | null {
  try {
    if (!fs.existsSync(BLOCKHOST_CONFIG_FILE)) {
      return null;
    }

    const config = yaml.load(
      fs.readFileSync(BLOCKHOST_CONFIG_FILE, "utf8"),
    ) as Record<string, unknown>;
    const admin = config.admin as Record<string, unknown> | undefined;

    if (!admin || !admin.wallet_address || !admin.shared_key) {
      return null;
    }

    const walletAddress = admin.wallet_address as string;
    const sharedKey = admin.shared_key as string;

    // Validate wallet address format (Cardano bech32: addr1... or addr_test1...)
    if (!isValidAddress(walletAddress)) {
      console.error(`[ADMIN] Invalid admin wallet address: ${walletAddress}`);
      return null;
    }

    // Validate shared key is 32-byte hex (may have 0x prefix)
    const rawKey = sharedKey.startsWith("0x") ? sharedKey.slice(2) : sharedKey;
    if (!HEX32_RE.test(rawKey)) {
      console.error(`[ADMIN] Invalid admin shared_key (expected 32-byte hex)`);
      return null;
    }

    return {
      wallet_address: walletAddress,
      shared_key: rawKey,
      credential_nft_id: admin.credential_nft_id as string | undefined,
      max_command_age: (admin.max_command_age as number) || 300,
    };
  } catch (err) {
    console.error(`[ADMIN] Error loading admin config: ${err}`);
    return null;
  }
}

/**
 * Load command database from admin-commands.json
 */
export function loadCommandDatabase(): CommandDatabase | null {
  try {
    if (!fs.existsSync(ADMIN_COMMANDS_FILE)) {
      console.warn(`[ADMIN] Command database not found: ${ADMIN_COMMANDS_FILE}`);
      return null;
    }

    const data = fs.readFileSync(ADMIN_COMMANDS_FILE, "utf8");
    const db = JSON.parse(data) as CommandDatabase;

    if (!db.commands || typeof db.commands !== "object") {
      console.error(`[ADMIN] Invalid command database structure`);
      return null;
    }

    return db;
  } catch (err) {
    console.error(`[ADMIN] Error loading command database: ${err}`);
    return null;
  }
}
