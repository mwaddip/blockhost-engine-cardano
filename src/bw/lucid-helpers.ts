/**
 * Shared Lucid Evolution initialization helpers.
 *
 * All bw CLI commands that build transactions should use initLucid() or
 * initLucidWithWallet() rather than constructing providers directly.
 */

import { Lucid, Blockfrost, Koios } from "@lucid-evolution/lucid";
import type { LucidEvolution } from "@lucid-evolution/lucid";
import { loadNetworkConfig } from "../fund-manager/web3-config.js";
import type { Addressbook } from "../fund-manager/types.js";
import * as fs from "fs";

/** Map our lowercase network names to Lucid's expected format */
function lucidNetwork(network: string): "Mainnet" | "Preprod" | "Preview" {
  if (network === "mainnet") return "Mainnet";
  if (network === "preview") return "Preview";
  return "Preprod";
}

/** Initialize Lucid with the configured provider (Blockfrost or Koios) */
export async function initLucid(): Promise<LucidEvolution> {
  const { blockfrostProjectId, network } = loadNetworkConfig();

  let provider;
  if (blockfrostProjectId) {
    const baseUrl =
      network === "mainnet"
        ? "https://cardano-mainnet.blockfrost.io/api/v0"
        : network === "preview"
          ? "https://cardano-preview.blockfrost.io/api/v0"
          : "https://cardano-preprod.blockfrost.io/api/v0";
    provider = new Blockfrost(baseUrl, blockfrostProjectId);
  } else {
    const koiosUrl =
      network === "mainnet"
        ? "https://api.koios.rest/api/v1"
        : network === "preview"
          ? "https://preview.koios.rest/api/v1"
          : "https://preprod.koios.rest/api/v1";
    provider = new Koios(koiosUrl);
  }

  return Lucid(provider, lucidNetwork(network));
}

/** Initialize Lucid and load a wallet from an addressbook role's keyfile */
export async function initLucidWithWallet(
  role: string,
  book: Addressbook,
): Promise<LucidEvolution> {
  const entry = book[role];
  if (!entry) throw new Error(`Role '${role}' not found in addressbook`);
  if (!entry.keyfile)
    throw new Error(`Role '${role}' has no keyfile — cannot sign`);

  const mnemonic = fs.readFileSync(entry.keyfile, "utf8").trim();
  const lucid = await initLucid();
  lucid.selectWallet.fromSeed(mnemonic);
  return lucid;
}
