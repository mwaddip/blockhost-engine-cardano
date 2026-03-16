/**
 * bw config stable [policyId.assetName]
 *
 * Read or set the payment token configuration.
 *
 * Read path: print current payment_token from web3-defaults.yaml.
 * Write path: TODO — update payment_token in yaml or on-chain reference UTXO.
 */

import * as fs from "fs";
import * as yaml from "js-yaml";
import type { Addressbook } from "../../fund-manager/types.js";

const CONFIG_DIR = process.env["BLOCKHOST_CONFIG_DIR"] ?? "/etc/blockhost";
const WEB3_DEFAULTS_PATH = `${CONFIG_DIR}/web3-defaults.yaml`;

/**
 * CLI handler
 */
export async function configCommand(
  args: string[],
  _book: Addressbook,
): Promise<void> {
  const [subCommand, ...rest] = args;

  if (subCommand === "stable") {
    await configStableCommand(rest);
    return;
  }

  console.error("Usage: bw config stable [policyId.assetName]");
  process.exit(1);
}

async function configStableCommand(args: string[]): Promise<void> {
  if (args.length === 0) {
    // Read current payment token
    if (!fs.existsSync(WEB3_DEFAULTS_PATH)) {
      console.error(`Config not found: ${WEB3_DEFAULTS_PATH}`);
      process.exit(1);
    }

    const raw = yaml.load(
      fs.readFileSync(WEB3_DEFAULTS_PATH, "utf8"),
    ) as Record<string, unknown> | null;

    const bc = raw?.["blockchain"] as Record<string, unknown> | undefined;
    const pt = bc?.["payment_token"] as string | undefined;

    if (!pt) {
      console.log("No payment token configured (blockchain.payment_token not set).");
    } else {
      console.log(`Payment token: ${pt}`);
    }
    return;
  }

  // Write path — update payment token
  const [newToken] = args;
  if (!newToken) {
    console.error("Usage: bw config stable <policyId.assetName>");
    process.exit(1);
  }

  console.log(`[TODO] Set payment token to: ${newToken}`);
  console.log("TODO: write path not yet implemented.");
  console.log(
    "      Update blockchain.payment_token in web3-defaults.yaml or the on-chain config UTXO.",
  );
}
