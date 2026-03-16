/**
 * Cardano web3 config loader — reads blockchain settings from web3-defaults.yaml.
 */

import * as fs from "fs";
import * as yaml from "js-yaml";
import type { CardanoNetwork } from "../cardano/types.js";

const CONFIG_DIR = process.env["BLOCKHOST_CONFIG_DIR"] ?? "/etc/blockhost";
const WEB3_DEFAULTS_PATH = `${CONFIG_DIR}/web3-defaults.yaml`;

const POLICY_ID_RE = /^[0-9a-fA-F]{56}$/;

export interface Web3Config {
  readonly blockfrostProjectId: string;
  readonly network: CardanoNetwork;
  readonly nftPolicyId: string;
  readonly subscriptionValidatorHash: string;
  readonly beaconPolicyId: string;
  readonly subscriptionValidatorAddress: string;
}

interface RawBlockchain {
  readonly blockfrost_project_id?: string;
  readonly network?: string;
  readonly nft_policy_id?: string;
  readonly subscription_validator_hash?: string;
  readonly beacon_policy_id?: string;
  readonly subscription_validator_address?: string;
}

interface RawYaml {
  readonly blockchain?: RawBlockchain;
}

function requirePolicyId(value: unknown, label: string): string {
  if (typeof value !== "string" || !POLICY_ID_RE.test(value)) {
    throw new Error(`${label}: expected 56 hex chars, got '${String(value)}'`);
  }
  return value;
}

function parseNetwork(value: unknown): CardanoNetwork {
  const v = String(value).toLowerCase();
  if (v === "mainnet" || v === "preprod" || v === "preview") return v;
  return "preprod"; // default
}

export function loadWeb3Config(): Web3Config {
  if (!fs.existsSync(WEB3_DEFAULTS_PATH)) {
    throw new Error(`Config not found: ${WEB3_DEFAULTS_PATH}`);
  }

  const raw = yaml.load(fs.readFileSync(WEB3_DEFAULTS_PATH, "utf8")) as RawYaml;
  const bc = raw.blockchain;
  if (!bc) throw new Error('Missing "blockchain" section in web3-defaults.yaml');

  if (!bc.blockfrost_project_id) {
    throw new Error("blockchain.blockfrost_project_id not set in web3-defaults.yaml");
  }

  return {
    blockfrostProjectId: bc.blockfrost_project_id,
    network: parseNetwork(bc.network),
    nftPolicyId: requirePolicyId(bc.nft_policy_id, "blockchain.nft_policy_id"),
    subscriptionValidatorHash: requirePolicyId(
      bc.subscription_validator_hash,
      "blockchain.subscription_validator_hash",
    ),
    beaconPolicyId: requirePolicyId(bc.beacon_policy_id, "blockchain.beacon_policy_id"),
    subscriptionValidatorAddress: bc.subscription_validator_address ?? "",
  };
}

export function loadNetworkConfig(): {
  readonly blockfrostProjectId: string;
  readonly network: CardanoNetwork;
} {
  if (!fs.existsSync(WEB3_DEFAULTS_PATH)) {
    throw new Error(`Config not found: ${WEB3_DEFAULTS_PATH}`);
  }

  const raw = yaml.load(fs.readFileSync(WEB3_DEFAULTS_PATH, "utf8")) as RawYaml;
  const bc = raw.blockchain;
  if (!bc?.blockfrost_project_id) {
    throw new Error("blockchain.blockfrost_project_id not set in web3-defaults.yaml");
  }

  return {
    blockfrostProjectId: bc.blockfrost_project_id,
    network: parseNetwork(bc.network),
  };
}
