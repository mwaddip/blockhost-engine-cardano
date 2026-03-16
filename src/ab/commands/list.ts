/**
 * ab list — Show all addressbook entries
 */

import { loadAddressbook } from "../../bw/cli-utils.js";

export function listCommand(): void {
  const book = loadAddressbook();
  const entries = Object.entries(book);

  if (entries.length === 0) {
    console.log("Addressbook is empty.");
    return;
  }

  for (const [name, entry] of entries) {
    const keyInfo = entry.keyfile ? ` (keyfile: ${entry.keyfile})` : "";
    console.log(`  ${name.padEnd(12)} ${entry.address}${keyInfo}`);
  }
}
