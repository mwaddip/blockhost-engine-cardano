/**
 * ab add <name> <address> — Add new entry to addressbook
 *
 * Accepts Cardano bech32 addresses (addr1... or addr_test1...).
 */

import { loadAddressbook } from "../../bw/cli-utils.js";
import { addressbookSave } from "../../root-agent/client.js";
import { isValidAddress } from "../../cardano/address.js";
import { IMMUTABLE_ROLES } from "../index.js";

export async function addCommand(args: string[]): Promise<void> {
  if (args.length !== 2) {
    console.error("Usage: ab add <name> <address>");
    process.exit(1);
  }

  const [name, rawAddress] = args;
  if (!name || !rawAddress) {
    console.error("Usage: ab add <name> <address>");
    process.exit(1);
  }

  if (!/^[a-zA-Z0-9_]{1,32}$/.test(name)) {
    console.error(
      `Error: role name must be 1-32 alphanumeric/underscore characters.`,
    );
    process.exit(1);
  }

  if (IMMUTABLE_ROLES.has(name)) {
    console.error(
      `Error: '${name}' is a reserved system role and cannot be modified.`,
    );
    process.exit(1);
  }

  if (!isValidAddress(rawAddress)) {
    console.error(
      `Error: '${rawAddress}' is not a valid Cardano address (expected addr1... or addr_test1...).`,
    );
    process.exit(1);
  }

  const book = loadAddressbook();

  if (book[name]) {
    console.error(
      `Error: '${name}' already exists. Use 'ab up ${name} <address>' to update.`,
    );
    process.exit(1);
  }

  book[name] = { address: rawAddress };
  await addressbookSave(book as Record<string, unknown>);
  console.log(`Added '${name}' → ${rawAddress}`);
}
