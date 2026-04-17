/**
 * ab --init <admin-addr> <server-addr> [dev-addr] [broker-addr] <server-keyfile>
 *
 * Bootstrap the addressbook with initial required entries.
 * dev and broker are optional — the keyfile (last arg, not an address) marks the end.
 * Fails if addressbook already has entries (safety — only for fresh bootstrap).
 *
 * Addresses: Cardano bech32 (addr1... or addr_test1...).
 *
 * Arg counts:
 *   3: admin, server, keyfile
 *   4: admin, server, dev, keyfile
 *   5: admin, server, dev, broker, keyfile
 */

import * as fs from "fs";
import { loadAddressbook } from "../../bw/cli-utils.js";
import { addressbookSave } from "../../root-agent/client.js";
import { isValidAddress } from "@mwaddip/cmttk";
import type { Addressbook } from "../../fund-manager/types.js";

export async function initCommand(args: string[]): Promise<void> {
  if (args.length < 3 || args.length > 5) {
    console.error(
      "Usage: ab --init <admin-addr> <server-addr> [dev-addr] [broker-addr] <server-keyfile>",
    );
    console.error(
      "  dev and broker are optional; keyfile is always last",
    );
    console.error(
      "  addresses: Cardano bech32 (addr1... or addr_test1...)",
    );
    process.exit(1);
  }

  const serverKeyfile = args[args.length - 1];
  const addresses = args.slice(0, -1);

  if (!serverKeyfile) {
    console.error("Error: missing server keyfile argument");
    process.exit(1);
  }

  if (!fs.existsSync(serverKeyfile)) {
    console.error(
      `Error: server keyfile not found: ${serverKeyfile}`,
    );
    process.exit(1);
  }

  const adminRaw = addresses[0] ?? "";
  const serverRaw = addresses[1] ?? "";
  const devRaw = addresses.length >= 3 ? (addresses[2] ?? "") : null;
  const brokerRaw = addresses.length >= 4 ? (addresses[3] ?? "") : null;

  if (!isValidAddress(adminRaw)) {
    console.error(
      `Error: invalid admin address: ${adminRaw || "(missing)"}`,
    );
    process.exit(1);
  }
  if (!isValidAddress(serverRaw)) {
    console.error(
      `Error: invalid server address: ${serverRaw || "(missing)"}`,
    );
    process.exit(1);
  }
  if (devRaw !== null && !isValidAddress(devRaw)) {
    console.error(`Error: invalid dev address: ${devRaw}`);
    process.exit(1);
  }
  if (brokerRaw !== null && !isValidAddress(brokerRaw)) {
    console.error(`Error: invalid broker address: ${brokerRaw}`);
    process.exit(1);
  }

  const existing = loadAddressbook();
  if (Object.keys(existing).length > 0) {
    console.error(
      "Error: addressbook already has entries. --init is only for fresh bootstrap.",
    );
    process.exit(1);
  }

  const book: Addressbook = {
    admin: { address: adminRaw },
    server: { address: serverRaw, keyfile: serverKeyfile },
  };

  if (devRaw !== null) {
    book["dev"] = { address: devRaw };
  }

  if (brokerRaw !== null) {
    book["broker"] = { address: brokerRaw };
  }

  await addressbookSave(book as Record<string, unknown>);
  console.log("Addressbook initialized:");
  console.log(`  admin  → ${adminRaw}`);
  console.log(`  server → ${serverRaw} (keyfile: ${serverKeyfile})`);
  if (devRaw !== null) console.log(`  dev    → ${devRaw}`);
  if (brokerRaw !== null) console.log(`  broker → ${brokerRaw}`);
}
