/**
 * bw --debug --cleanup <address>
 *
 * Debug utility — sweep all ADA from every signing wallet to a target address.
 *
 * Requires --debug flag as a safety guard.
 *
 * TODO: Depends on full MeshJS tx building to sweep UTXOs.
 */

import type { Addressbook } from "../../fund-manager/types.js";
import { isValidAddress } from "../../cardano/address.js";

/**
 * CLI handler (called when --debug --cleanup flags are set).
 *
 * @param targetAddress  Destination bech32 address from positional args
 * @param book           Addressbook
 */
export async function cleanupCommand(
  targetAddress: string,
  book: Addressbook,
): Promise<void> {
  if (!isValidAddress(targetAddress)) {
    console.error(`Invalid target address: ${targetAddress}`);
    process.exit(1);
  }

  const signingRoles = Object.entries(book)
    .filter(([, entry]) => Boolean(entry.keyfile))
    .map(([role]) => role);

  if (signingRoles.length === 0) {
    console.log("No signing wallets found in addressbook.");
    return;
  }

  console.log(`[TODO] Sweep ADA from ${signingRoles.join(", ")} to ${targetAddress}`);
  console.log("TODO: --cleanup not yet implemented.");
  console.log(
    "      Requires MeshJS tx building to sweep all UTXOs from signing wallets.",
  );
}
