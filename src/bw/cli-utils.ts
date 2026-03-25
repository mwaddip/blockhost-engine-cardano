/**
 * CLI utilities: addressbook loading, token/address resolution, wallet loading.
 *
 * Cardano-specific: token = { policyId, assetName }, ADA = { "", "" }.
 */

import * as fs from "fs";
import * as yaml from "js-yaml";
import { isValidAddress, getProvider } from "cmttk";
import type { CardanoProvider } from "cmttk";
import type { AssetId } from "../cardano/types.js";
import { loadNetworkConfig } from "../fund-manager/web3-config.js";
import type { Addressbook, AddressbookEntry } from "../fund-manager/types.js";

const CONFIG_DIR = process.env["BLOCKHOST_CONFIG_DIR"] ?? "/etc/blockhost";
const ADDRESSBOOK_PATH = `${CONFIG_DIR}/addressbook.json`;

// ── Addressbook ────────────────────────────────────────────────────────────────

/**
 * Read /etc/blockhost/addressbook.json.
 *
 * Returns an empty object if the file does not exist.
 */
export function loadAddressbook(): Addressbook {
  if (!fs.existsSync(ADDRESSBOOK_PATH)) {
    return {};
  }

  const raw = fs.readFileSync(ADDRESSBOOK_PATH, "utf8");
  return JSON.parse(raw) as Addressbook;
}

// ── Address resolution ────────────────────────────────────────────────────────

/**
 * Resolve an addressbook role to its bech32 address.
 *
 * If roleOrAddress is already a valid bech32 address it is returned as-is.
 * Throws if the role is not found in the book and the value is not an address.
 */
export function resolveAddress(
  roleOrAddress: string,
  book: Addressbook,
): string {
  if (isValidAddress(roleOrAddress)) {
    return roleOrAddress;
  }

  const entry: AddressbookEntry | undefined = book[roleOrAddress];
  if (!entry) {
    throw new Error(
      `Unknown role '${roleOrAddress}': not in addressbook and not a valid address`,
    );
  }

  return entry.address;
}

// ── Token resolution ──────────────────────────────────────────────────────────

/**
 * Resolve a token shortcut to a Cardano AssetId.
 *
 *   "ada"               → { policyId: "", assetName: "" }
 *   "stable"            → reads payment token from web3-defaults.yaml (not yet wired)
 *   "policyId.assetName" → literal parse
 *   "policyId"          → { policyId, assetName: "" }  (ADA-equivalent policy — unusual)
 *
 * The "stable" path reads `payment_token` from the config yaml.
 * Format in yaml:  payment_token: "policyId.assetName" or "policyId"
 */
export function resolveToken(tokenOrShortcut: string): AssetId {
  const lower = tokenOrShortcut.toLowerCase();

  if (lower === "ada" || lower === "lovelace" || lower === "") {
    return { policyId: "", assetName: "" };
  }

  if (lower === "stable" || lower === "stablecoin") {
    return resolveStableToken();
  }

  // Explicit "policyId.assetName" or "policyId" (bare policy)
  if (tokenOrShortcut.includes(".")) {
    const dot = tokenOrShortcut.indexOf(".");
    const policyId = tokenOrShortcut.slice(0, dot);
    const assetName = tokenOrShortcut.slice(dot + 1);
    return { policyId, assetName };
  }

  // Bare 56-char policy ID — treat assetName as empty (unusual but accepted)
  if (/^[0-9a-fA-F]{56}$/.test(tokenOrShortcut)) {
    return { policyId: tokenOrShortcut, assetName: "" };
  }

  throw new Error(
    `Unknown token: '${tokenOrShortcut}'. Use 'ada', 'stable', or 'policyId.assetName'.`,
  );
}

/** Load the payment token from web3-defaults.yaml (payment_token field). */
function resolveStableToken(): AssetId {
  const CONFIG_PATH = `${CONFIG_DIR}/web3-defaults.yaml`;

  if (!fs.existsSync(CONFIG_PATH)) {
    throw new Error(`Config not found: ${CONFIG_PATH}`);
  }

  const raw = yaml.load(fs.readFileSync(CONFIG_PATH, "utf8")) as
    | Record<string, unknown>
    | null;
  const bc = raw?.["blockchain"] as Record<string, unknown> | undefined;
  const pt = bc?.["payment_token"] as string | undefined;

  if (!pt) {
    throw new Error(
      "blockchain.payment_token not set in web3-defaults.yaml — cannot resolve 'stable'",
    );
  }

  return resolveToken(pt); // recurse with the literal value
}

// ── Wallet loading ────────────────────────────────────────────────────────────

/**
 * Load the BIP39 mnemonic from the keyfile for a given addressbook role,
 * then derive a Cardano wallet (CIP-1852).
 *
 * Throws if the role has no keyfile or if the mnemonic is invalid.
 */
// ── Provider client ──────────────────────────────────────────────────────────

/**
 * Get a CardanoProvider configured from web3-defaults.yaml.
 */
export function getProviderClient(): CardanoProvider {
  const { blockfrostProjectId, koiosUrl, network } = loadNetworkConfig();
  return getProvider(network, blockfrostProjectId || undefined, koiosUrl || undefined);
}

// ── Formatting helpers ────────────────────────────────────────────────────────

/**
 * Format a lovelace amount as a human-readable ADA string.
 *
 * Example: 1_500_000n → "1.500000 ADA"
 */
export function formatAda(lovelace: bigint): string {
  const whole = lovelace / 1_000_000n;
  const frac = lovelace % 1_000_000n;
  const fracStr = frac.toString().padStart(6, "0");
  return `${whole}.${fracStr} ADA`;
}

/**
 * Format a native token amount.
 *
 * @param amount   Raw token units (BigInt)
 * @param decimals Token decimal places (default 0 — most Cardano tokens are indivisible)
 * @param symbol   Token symbol string
 */
export function formatToken(amount: bigint, decimals = 0, symbol = ""): string {
  if (decimals === 0) {
    return `${amount.toString()} ${symbol}`.trim();
  }
  const factor = BigInt(10 ** decimals);
  const whole = amount / factor;
  const frac = amount % factor;
  const fracStr = frac.toString().padStart(decimals, "0");
  return `${whole}.${fracStr} ${symbol}`.trim();
}
