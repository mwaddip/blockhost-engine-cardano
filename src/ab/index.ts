#!/usr/bin/env node
/**
 * ab (addressbook) CLI — manage wallet entries in /etc/blockhost/addressbook.json
 *
 * Usage:
 *   ab add <name> <addr1...>   Add new entry
 *   ab del <name>              Delete entry
 *   ab up <name> <addr1...>    Update entry's address
 *   ab new <name>              Generate new wallet, save key, add to addressbook
 *   ab list                    Show all entries
 *
 * Reserved roles (immutable): server, admin, hot, dev, broker
 */

import { addCommand } from "./commands/add.js";
import { delCommand } from "./commands/del.js";
import { upCommand } from "./commands/up.js";
import { newCommand } from "./commands/new.js";
import { listCommand } from "./commands/list.js";
import { initCommand } from "./commands/init.js";

export const IMMUTABLE_ROLES = new Set([
  "server",
  "admin",
  "hot",
  "dev",
  "broker",
]);

function printUsage(): void {
  console.log("ab (addressbook) — manage wallet entries in addressbook.json");
  console.log("");
  console.log("Usage:");
  console.log("  ab add <name> <addr1...>    Add new entry");
  console.log("  ab del <name>              Delete entry");
  console.log("  ab up <name> <addr1...>    Update entry's address");
  console.log(
    "  ab new <name>              Generate new wallet and add to addressbook",
  );
  console.log("  ab list                    Show all entries");
  console.log(
    "  ab --init <admin> <server> [dev] [broker] <keyfile>",
  );
  console.log(
    "                             Bootstrap addressbook (fresh install only)",
  );
  console.log("");
  console.log(
    "Reserved roles (immutable): server, admin, hot, dev, broker",
  );
}

async function main(): Promise<void> {
  const argv = process.argv.slice(2);

  if (
    argv.length === 0 ||
    argv[0] === "--help" ||
    argv[0] === "-h"
  ) {
    printUsage();
    process.exit(0);
  }

  if (argv[0] === "--init") {
    await initCommand(argv.slice(1));
    return;
  }

  const [command, ...args] = argv;

  switch (command) {
    case "add":
      await addCommand(args);
      break;
    case "del":
      await delCommand(args);
      break;
    case "up":
      await upCommand(args);
      break;
    case "new":
      await newCommand(args);
      break;
    case "list":
      listCommand();
      break;
    default:
      console.error(`Unknown command: ${command}`);
      printUsage();
      process.exit(1);
  }
}

main().catch((err: Error) => {
  console.error(`Error: ${err.message}`);
  process.exit(1);
});
