#!/usr/bin/env node
/**
 * bw (blockwallet) CLI — scriptable wallet operations for blockhost (Cardano)
 *
 * Usage:
 *   bw send <amount> <token> <from> <to>
 *   bw balance <role> [token]
 *   bw split <amount> <token> <ratios> <from> <to1> <to2> ...
 *   bw withdraw <to>
 *   bw swap <amount> <from-token> ada <wallet>
 *   bw who <identifier>
 *   bw config stable [policyId.assetName]
 *   bw plan create <name> <price>
 *   bw set encrypt <nft_id> <data>
 *
 * Debug:
 *   bw --debug --cleanup <address>   Sweep all ADA from signing wallets to <address>
 *
 * Configuration:
 *   All config read from /etc/blockhost/web3-defaults.yaml
 *   Addressbook from /etc/blockhost/addressbook.json
 */

import { loadAddressbook } from "./cli-utils.js";
import { sendCommand } from "./commands/send.js";
import { balanceCommand } from "./commands/balance.js";
import { splitCommand } from "./commands/split.js";
import { withdrawCommand } from "./commands/withdraw.js";
import { swapCommand } from "./commands/swap.js";
import { cleanupCommand } from "./commands/cleanup.js";
import { whoCommand } from "./commands/who.js";
import { configCommand } from "./commands/config.js";
import { planCommand } from "./commands/plan.js";
import { setCommand } from "./commands/set.js";

function printUsage(): void {
  console.log("bw (blockwallet) — scriptable wallet operations for blockhost (Cardano)");
  console.log("");
  console.log("Usage:");
  console.log("  bw send <amount> <token> <from> <to>      Send ADA or tokens");
  console.log("  bw balance <role> [token]                  Show balances");
  console.log(
    "  bw split <amount> <token> <ratios> <from> <to1> <to2> ...",
  );
  console.log("                                             Split tokens by ratio");
  console.log("  bw withdraw <to>                           Collect subscription UTXOs");
  console.log(
    "  bw swap <amount> <from-token> ada <wallet>  Swap tokens via DEX",
  );
  console.log("  bw who <identifier>                        Query NFT holder");
  console.log("  bw config stable [policyId.assetName]      Get/set payment token");
  console.log("  bw plan create <name> <price>              Create subscription plan");
  console.log("  bw set encrypt <nft_id> <data>             Update NFT encrypted data");
  console.log("");
  console.log("Debug:");
  console.log("  bw --debug --cleanup <address>             Sweep ADA to address");
  console.log("");
  console.log("Token shortcuts: ada, stable, or policyId.assetName");
  console.log("Roles: admin, server, hot, dev, broker (from addressbook.json)");
}

async function main(): Promise<void> {
  const argv = process.argv.slice(2);
  const flags = new Set(argv.filter((a) => a.startsWith("--")));
  const positional = argv.filter((a) => !a.startsWith("--"));

  if (flags.has("--help") || flags.has("-h") || argv.length === 0) {
    printUsage();
    process.exit(0);
  }

  // 'who' reads its own config (web3-defaults.yaml), no addressbook needed
  if (positional[0] === "who") {
    await whoCommand(positional.slice(1));
    return;
  }

  const book = loadAddressbook();
  if (Object.keys(book).length === 0) {
    console.error(
      "Error: addressbook is empty or missing. Run the installer wizard first.",
    );
    process.exit(1);
  }

  // --debug --cleanup <address>: sweep testnet ADA back to a single address
  if (flags.has("--cleanup")) {
    if (!flags.has("--debug")) {
      console.error("Error: --cleanup requires --debug flag");
      process.exit(1);
    }
    const targetAddress = positional[0];
    if (!targetAddress) {
      console.error("Usage: bw --debug --cleanup <address>");
      process.exit(1);
    }
    await cleanupCommand(targetAddress, book);
    return;
  }

  const [command, ...args] = positional;

  if (!command) {
    printUsage();
    process.exit(0);
  }

  switch (command) {
    case "send":
      await sendCommand(args, book);
      break;

    case "balance":
      await balanceCommand(args, book);
      break;

    case "split":
      await splitCommand(args, book);
      break;

    case "withdraw":
      await withdrawCommand(args, book);
      break;

    case "swap":
      await swapCommand(args, book);
      break;

    case "config":
      await configCommand(args, book);
      break;

    case "plan":
      await planCommand(args, book);
      break;

    case "set":
      await setCommand(args, book);
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
