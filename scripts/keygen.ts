#!/usr/bin/env -S npx tsx
/**
 * keygen — Generate a Cardano wallet for BlockHost provisioning.
 *
 * Generates a BIP39 mnemonic (24 words) and derives a CIP-1852 Cardano wallet.
 * Called by the root agent's wallet generation action via subprocess.
 *
 * Usage:
 *   keygen [--network preprod|mainnet|preview]
 *
 * stdout: JSON object:
 *   {
 *     "mnemonic":       "word1 word2 ... word24",
 *     "address":        "addr_test1...",
 *     "paymentKeyHash": "<56-char hex>",
 *     "stakeKeyHash":   "<56-char hex>",
 *     "network":        "preprod"
 *   }
 *
 * Exit: 0 = success, 1 = failure
 */

import { generateMnemonic } from "bip39";
import { deriveWallet } from "../src/cardano/wallet.js";
import type { CardanoNetwork } from "../src/cardano/types.js";

function resolveNetwork(name: string): CardanoNetwork {
  switch (name.toLowerCase()) {
    case "mainnet": return "mainnet";
    case "preview": return "preview";
    default:        return "preprod";
  }
}

function die(msg: string): never {
  process.stderr.write(`keygen: ${msg}\n`);
  process.exit(1);
}

// ── Parse args ────────────────────────────────────────────────────────────────

const argv = process.argv.slice(2);
let networkArg = "preprod";

for (let i = 0; i < argv.length; i++) {
  const arg = argv[i];
  if (arg === "--network") {
    networkArg = argv[++i] ?? "";
    if (!networkArg) die("--network requires a value (preprod|mainnet|preview)");
  } else {
    die(`unknown argument: ${arg}\nUsage: keygen [--network preprod|mainnet|preview]`);
  }
}

const network = resolveNetwork(networkArg);

// ── Generate + derive ─────────────────────────────────────────────────────────

async function main(): Promise<void> {
  // generateMnemonic() returns 12 words by default (128-bit entropy).
  // Use 256-bit entropy for 24 words — standard for Cardano wallets.
  const mnemonic = generateMnemonic(256);
  const wallet   = await deriveWallet(mnemonic, network);

  const output = {
    mnemonic,
    address:        wallet.address,
    paymentKeyHash: wallet.paymentKeyHash,
    stakeKeyHash:   wallet.stakeKeyHash,
    network,
  };

  process.stdout.write(JSON.stringify(output) + "\n");
}

main().catch((err: unknown) => {
  die(String(err instanceof Error ? err.message : err));
});
