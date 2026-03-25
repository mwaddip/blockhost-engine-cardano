#!/usr/bin/env node
/**
 * is (identity predicate) CLI — yes/no identity questions via exit code
 *
 * Usage:
 *   is <wallet> <nft_id>         Does wallet hold NFT token ID?
 *   is contract <address>        Does an address have UTXOs? (rough "is active" check)
 *
 * Exit: 0 = yes, 1 = no
 *
 * Arguments are order-independent, disambiguated by type:
 *   Address: Cardano bech32 (addr1... or addr_test1...)
 *   NFT ID: integer
 *   "contract": literal keyword
 *
 * Config from web3-defaults.yaml (blockfrost_project_id, network, nft_policy_id).
 */

import { isValidAddress, getProvider } from "cmttk";
import { loadWeb3Config } from "../fund-manager/web3-config.js";
import { findNftHolder } from "../nft/reference.js";

function isNftId(arg: string): boolean {
  return /^\d+$/.test(arg);
}

function printUsage(): void {
  console.error("is — identity predicate (exit 0 = yes, 1 = no)");
  console.error("");
  console.error("Usage:");
  console.error(
    "  is <wallet> <nft_id>       Does wallet hold NFT token?",
  );
  console.error(
    "  is contract <address>      Does an address have UTXOs on-chain?",
  );
}

async function main(): Promise<void> {
  const argv = process.argv.slice(2);

  if (
    argv.length === 0 ||
    argv.includes("--help") ||
    argv.includes("-h")
  ) {
    printUsage();
    process.exit(argv.length === 0 ? 1 : 0);
  }

  // Form: is contract <address>
  if (argv.includes("contract")) {
    const other = argv.filter((a) => a !== "contract");
    if (other.length !== 1 || !other[0] || !isValidAddress(other[0])) {
      console.error("Usage: is contract <address>");
      process.exit(1);
    }
    const address = other[0];
    const { blockfrostProjectId, koiosUrl, network } = loadWeb3Config();
    const provider = getProvider(network, blockfrostProjectId || undefined, koiosUrl || undefined);
    try {
      const utxos = await provider.fetchUtxos(address);
      process.exit(utxos.length > 0 ? 0 : 1);
    } catch {
      process.exit(1);
    }
  }

  if (argv.length !== 2) {
    printUsage();
    process.exit(1);
  }

  const [arg1, arg2] = argv;
  if (!arg1 || !arg2) {
    printUsage();
    process.exit(1);
  }

  // Form: is <wallet> <nft_id>  (order-independent)
  let walletAddr: string | null = null;
  let nftId: string | null = null;
  if (isValidAddress(arg1) && isNftId(arg2)) {
    walletAddr = arg1;
    nftId = arg2;
  } else if (isValidAddress(arg2) && isNftId(arg1)) {
    walletAddr = arg2;
    nftId = arg1;
  }

  if (walletAddr && nftId) {
    const { blockfrostProjectId, koiosUrl, network, nftPolicyId } = loadWeb3Config();
    const provider = getProvider(network, blockfrostProjectId || undefined, koiosUrl || undefined);

    try {
      const holder = await findNftHolder(provider, nftPolicyId, parseInt(nftId, 10));
      process.exit(holder !== null && holder.toLowerCase() === walletAddr.toLowerCase() ? 0 : 1);
    } catch {
      process.exit(1);
    }
  }

  console.error("Error: could not parse arguments. See 'is --help'.");
  process.exit(1);
}

main().catch((err: Error) => {
  console.error(`Error: ${err.message}`);
  process.exit(1);
});
