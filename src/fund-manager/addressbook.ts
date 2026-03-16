/**
 * Addressbook loading, saving, and resolution utilities (Cardano).
 *
 * Addresses are stored as bech32 Cardano addresses (addr1... or addr_test1...).
 * Unlike OPNet, no RPC resolution is needed — bech32 addresses are self-contained.
 */

import * as fs from "fs";
import type { Addressbook } from "./types.js";
import { isValidAddress, normalizeAddress } from "../cardano/address.js";
import {
  generateWallet as rootAgentGenerateWallet,
  addressbookSave,
} from "../root-agent/client.js";

const CONFIG_DIR = process.env["BLOCKHOST_CONFIG_DIR"] ?? "/etc/blockhost";
const ADDRESSBOOK_PATH = `${CONFIG_DIR}/addressbook.json`;
const HOT_KEY_PATH = `${CONFIG_DIR}/hot.key`;

/**
 * Load addressbook from /etc/blockhost/addressbook.json.
 * Validates all entries have valid bech32 Cardano addresses.
 * Returns empty object if file does not exist.
 */
export function loadAddressbook(): Addressbook {
  try {
    if (!fs.existsSync(ADDRESSBOOK_PATH)) {
      console.error(`[FUND] Addressbook not found: ${ADDRESSBOOK_PATH}`);
      return {};
    }

    const data = fs.readFileSync(ADDRESSBOOK_PATH, "utf8");
    const book = JSON.parse(data) as Addressbook;

    for (const [role, entry] of Object.entries(book)) {
      if (!isValidAddress(entry.address)) {
        console.error(
          `[FUND] Invalid address for role '${role}': ${entry.address}`,
        );
        delete book[role];
      }
    }

    return book;
  } catch (err) {
    console.error(`[FUND] Error loading addressbook: ${err}`);
    return {};
  }
}

/**
 * Save addressbook via root agent.
 */
export async function saveAddressbook(book: Addressbook): Promise<void> {
  try {
    await addressbookSave(book as unknown as Record<string, unknown>);
  } catch (err) {
    console.error(`[FUND] Error saving addressbook: ${err}`);
  }
}

/**
 * Resolve a role name or bech32 address to a bech32 address string.
 *
 * If identifier is already a valid bech32 address, returns it normalized
 * (lowercase). Otherwise looks up the role in the addressbook.
 *
 * Returns null if neither is found/valid.
 */
export function resolveRole(
  identifier: string,
  book: Addressbook,
): string | null {
  // Direct bech32 address — normalize and return
  if (isValidAddress(identifier)) {
    return normalizeAddress(identifier);
  }

  // Role lookup
  const entry = book[identifier];
  if (!entry) {
    console.error(`[FUND] Role '${identifier}' not found in addressbook`);
    return null;
  }

  return entry.address;
}

/**
 * Ensure the hot wallet exists in the addressbook.
 * Generates one via root agent if missing.
 *
 * On Cardano, the root agent generates a BIP39 mnemonic and derives the
 * first CIP-1852 address, saving the mnemonic to /etc/blockhost/hot.key.
 */
export async function ensureHotWallet(book: Addressbook): Promise<Addressbook> {
  if (book["hot"]) {
    return book;
  }

  console.log("[FUND] Generating hot wallet via root agent...");
  const { address } = await rootAgentGenerateWallet("hot");

  book["hot"] = {
    address,
    keyfile: HOT_KEY_PATH,
  };

  await saveAddressbook(book);
  console.log(`[FUND] Generated hot wallet: ${address}`);
  return book;
}
