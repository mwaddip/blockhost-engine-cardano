/**
 * ab del <name> — Delete entry from addressbook
 */

import { loadAddressbook } from "../../bw/cli-utils.js";
import { addressbookSave } from "../../root-agent/client.js";
import { assertMutableRole } from "../index.js";

export async function delCommand(args: string[]): Promise<void> {
  if (args.length !== 1) {
    console.error("Usage: ab del <name>");
    process.exit(1);
  }

  const [name] = args;
  if (!name) {
    console.error("Usage: ab del <name>");
    process.exit(1);
  }

  assertMutableRole(name);

  const book = loadAddressbook();

  if (!book[name]) {
    console.error(`Error: '${name}' not found in addressbook.`);
    process.exit(1);
  }

  delete book[name];
  await addressbookSave(book as Record<string, unknown>);
  console.log(`Deleted '${name}' from addressbook.`);
}
