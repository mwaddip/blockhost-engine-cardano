#!/usr/bin/env -S npx tsx
/**
 * blockhost-mint-nft — Mint a CIP-68 access credential NFT on Cardano.
 *
 * Called by the provisioner after VM creation to issue an NFT that
 * carries the encrypted connection details for the subscriber.
 *
 * Usage:
 *   blockhost-mint-nft --owner-wallet <bech32>
 *   blockhost-mint-nft --owner-wallet <bech32> --user-encrypted <hex>
 *   blockhost-mint-nft --owner-wallet <bech32> --user-encrypted <hex> --dry-run
 *
 * Config:
 *   Reads blockchain settings from /etc/blockhost/web3-defaults.yaml
 *   Reads deployer mnemonic from DEPLOYER_MNEMONIC env var or /etc/blockhost/deployer.key
 *   Reads/writes token counter from /var/lib/blockhost/next-nft-id
 *
 * stdout: token ID (integer) on success
 * stderr: progress / error messages
 * Exit: 0 = success, 1 = failure
 */

import * as fs from "node:fs";
import * as path from "node:path";
import * as yaml from "js-yaml";
import {
  Lucid, Blockfrost, Koios,
  applyParamsToScript, mintingPolicyToId, getAddressDetails,
  Data, Constr,
} from "@lucid-evolution/lucid";
import type { Network } from "@lucid-evolution/lucid";
import { userTokenAssetName, referenceTokenAssetName } from "../src/nft/mint.js";
import type { CardanoNetwork } from "../src/cardano/types.js";

// ── Constants ─────────────────────────────────────────────────────────────────

const CONFIG_DIR  = process.env["BLOCKHOST_CONFIG_DIR"] ?? "/etc/blockhost";
const STATE_DIR   = process.env["BLOCKHOST_STATE_DIR"]  ?? "/var/lib/blockhost";
const KEY_PATH    = `${CONFIG_DIR}/deployer.key`;
const COUNTER_PATH = `${STATE_DIR}/next-nft-id`;

// ── Types ─────────────────────────────────────────────────────────────────────

interface Args {
  ownerWallet:   string;
  userEncrypted: string;
  dryRun:        boolean;
}

interface Web3Yaml {
  blockchain?: {
    blockfrost_project_id?: string;
    network?: string;
    nft_policy_id?: string;
    subscription_validator_address?: string;
    subscription_validator_hash?: string;
  };
}

interface Web3Config {
  blockfrostProjectId: string;
  network: CardanoNetwork;
  nftPolicyId: string;
  referenceScriptAddress: string;
}

/** Plutus blueprint JSON structure (only the fields we need). */
interface PlutusBlueprint {
  validators: Array<{
    title: string;
    compiledCode: string;
    hash: string;
    parameters?: Array<{ title: string }>;
  }>;
}

// ── Argument parsing ──────────────────────────────────────────────────────────

function parseArgs(): Args {
  const argv = process.argv.slice(2);
  let ownerWallet   = "";
  let userEncrypted = "";
  let dryRun        = false;

  for (let i = 0; i < argv.length; i++) {
    switch (argv[i]) {
      case "--owner-wallet":
        ownerWallet = argv[++i] ?? "";
        break;
      case "--user-encrypted":
        userEncrypted = argv[++i] ?? "";
        break;
      case "--dry-run":
        dryRun = true;
        break;
      default:
        process.stderr.write(`blockhost-mint-nft: unknown argument: ${argv[i]}\n`);
        process.exit(1);
    }
  }

  if (!ownerWallet) {
    process.stderr.write(
      "blockhost-mint-nft: --owner-wallet is required\n" +
      "Usage: blockhost-mint-nft --owner-wallet <bech32> [--user-encrypted <hex>] [--dry-run]\n",
    );
    process.exit(1);
  }

  // Basic bech32 sanity — addr1... (mainnet) or addr_test1... (testnet)
  if (!/^addr(_test)?1[a-z0-9]+$/.test(ownerWallet)) {
    process.stderr.write(
      "blockhost-mint-nft: --owner-wallet must be a bech32 Cardano address (addr1... or addr_test1...)\n",
    );
    process.exit(1);
  }

  if (userEncrypted && !/^[0-9a-fA-F]+$/.test(userEncrypted)) {
    process.stderr.write("blockhost-mint-nft: --user-encrypted must be a hex string\n");
    process.exit(1);
  }

  return { ownerWallet, userEncrypted, dryRun };
}

// ── Config loading ────────────────────────────────────────────────────────────

function loadConfig(): Web3Config {
  const cfgPath = `${CONFIG_DIR}/web3-defaults.yaml`;
  if (!fs.existsSync(cfgPath)) {
    process.stderr.write(`blockhost-mint-nft: config not found: ${cfgPath}\n`);
    process.exit(1);
  }

  const raw = yaml.load(fs.readFileSync(cfgPath, "utf8")) as Web3Yaml;
  const bc  = raw.blockchain;

  if (!bc?.blockfrost_project_id) {
    process.stderr.write("blockhost-mint-nft: blockchain.blockfrost_project_id not set\n");
    process.exit(1);
  }
  if (!bc.nft_policy_id || !/^[0-9a-fA-F]{56}$/.test(bc.nft_policy_id)) {
    process.stderr.write("blockhost-mint-nft: blockchain.nft_policy_id not set or invalid (need 56 hex chars)\n");
    process.exit(1);
  }

  const networkRaw = (bc.network ?? "preprod").toLowerCase();
  const network: CardanoNetwork =
    networkRaw === "mainnet" ? "mainnet" :
    networkRaw === "preview"  ? "preview"  : "preprod";

  return {
    blockfrostProjectId: bc.blockfrost_project_id,
    network,
    nftPolicyId: bc.nft_policy_id,
    referenceScriptAddress: bc.subscription_validator_address ?? "",
  };
}

// ── Mnemonic loading ──────────────────────────────────────────────────────────

function loadMnemonic(): string {
  const fromEnv = process.env["DEPLOYER_MNEMONIC"];
  if (fromEnv) return fromEnv.trim();

  if (!fs.existsSync(KEY_PATH)) {
    process.stderr.write(
      `blockhost-mint-nft: set DEPLOYER_MNEMONIC or create ${KEY_PATH}\n`,
    );
    process.exit(1);
  }
  return fs.readFileSync(KEY_PATH, "utf8").trim();
}

// ── Token ID counter ──────────────────────────────────────────────────────────

/**
 * Read, increment, and write back the NFT token ID counter.
 * Returns the allocated token ID (the value *before* incrementing).
 *
 * The counter file contains a single decimal integer.
 * If it does not exist, we start at 1.
 */
function allocateTokenId(): number {
  // Ensure state directory exists.
  if (!fs.existsSync(STATE_DIR)) {
    fs.mkdirSync(STATE_DIR, { recursive: true });
  }

  let current = 1;
  if (fs.existsSync(COUNTER_PATH)) {
    const raw = fs.readFileSync(COUNTER_PATH, "utf8").trim();
    const parsed = parseInt(raw, 10);
    if (!isNaN(parsed) && parsed > 0) {
      current = parsed;
    }
  }

  // Write next value immediately so a crash does not re-use this ID.
  fs.writeFileSync(COUNTER_PATH, String(current + 1), { encoding: "utf8" });
  return current;
}

// ── Blueprint loading ──────────────────────────────────────────────────────

/**
 * Load the NFT minting policy compiled code from plutus.json blueprint.
 * Looks for the validator titled "nft.nft.mint".
 */
function loadNftCompiledCode(): string {
  // Resolve plutus.json relative to this script (scripts/ -> project root)
  const blueprintPath = path.resolve(
    path.dirname(new URL(import.meta.url).pathname),
    "..",
    "plutus.json",
  );

  if (!fs.existsSync(blueprintPath)) {
    process.stderr.write(`blockhost-mint-nft: blueprint not found: ${blueprintPath}\n`);
    process.exit(1);
  }

  const blueprint = JSON.parse(fs.readFileSync(blueprintPath, "utf8")) as PlutusBlueprint;
  const nftValidator = blueprint.validators.find((v) => v.title === "nft.nft.mint");

  if (!nftValidator) {
    process.stderr.write("blockhost-mint-nft: nft.nft.mint validator not found in plutus.json\n");
    process.exit(1);
  }

  return nftValidator.compiledCode;
}

// ── Lucid network mapping ──────────────────────────────────────────────────

function toLucidNetwork(network: CardanoNetwork): Network {
  switch (network) {
    case "mainnet": return "Mainnet";
    case "preview": return "Preview";
    case "preprod": return "Preprod";
  }
}

function blockfrostUrl(network: CardanoNetwork): string {
  switch (network) {
    case "mainnet": return "https://cardano-mainnet.blockfrost.io/api/v0";
    case "preprod": return "https://cardano-preprod.blockfrost.io/api/v0";
    case "preview": return "https://cardano-preview.blockfrost.io/api/v0";
  }
}

function koiosUrl(network: CardanoNetwork): string {
  switch (network) {
    case "mainnet": return "https://api.koios.rest/api/v1";
    case "preview": return "https://preview.koios.rest/api/v1";
    case "preprod": return "https://preprod.koios.rest/api/v1";
  }
}

// ── Main ──────────────────────────────────────────────────────────────────────

async function main(): Promise<void> {
  const { ownerWallet, userEncrypted, dryRun } = parseArgs();
  const cfg      = loadConfig();
  const mnemonic = loadMnemonic();

  // ── Initialise Lucid with provider and wallet from seed ──────────────────

  process.stderr.write("Initialising Lucid Evolution...\n");

  const provider = cfg.blockfrostProjectId
    ? new Blockfrost(blockfrostUrl(cfg.network), cfg.blockfrostProjectId)
    : new Koios(koiosUrl(cfg.network));

  const lucid = await Lucid(provider, toLucidNetwork(cfg.network));
  lucid.selectWallet.fromSeed(mnemonic);

  const deployerAddress = await lucid.wallet().address();
  process.stderr.write(`Deployer address: ${deployerAddress}\n`);

  // Extract deployer's payment key hash (needed as the server_key_hash parameter)
  const addressDetails = getAddressDetails(deployerAddress);
  const serverKeyHash = addressDetails.paymentCredential?.hash;
  if (!serverKeyHash) {
    process.stderr.write("blockhost-mint-nft: could not extract payment key hash from deployer address\n");
    process.exit(1);
  }
  process.stderr.write(`Server key hash:  ${serverKeyHash}\n`);

  // ── Load NFT validator and apply server_key_hash parameter ───────────────

  const nftCompiledCode = loadNftCompiledCode();
  const appliedScript = applyParamsToScript(nftCompiledCode, [serverKeyHash]);
  const mintingPolicy = { type: "PlutusV3" as const, script: appliedScript };
  const policyId = mintingPolicyToId(mintingPolicy);
  process.stderr.write(`Computed policy ID: ${policyId}\n`);

  // Warn if the computed policy ID does not match the config value
  if (policyId !== cfg.nftPolicyId) {
    process.stderr.write(
      `WARNING: computed policy ID (${policyId}) differs from config nft_policy_id (${cfg.nftPolicyId})\n` +
      `Using computed value — the config value may need updating.\n`,
    );
  }

  // ── Allocate token ID and compute CIP-68 asset names ─────────────────────

  const tokenId = allocateTokenId();
  process.stderr.write(`Allocated token ID: ${tokenId}\n`);

  const userAssetName = userTokenAssetName(tokenId);       // (222) user token
  const refAssetName  = referenceTokenAssetName(tokenId);  // (100) reference token

  process.stderr.write(`User token asset:      ${policyId}${userAssetName}\n`);
  process.stderr.write(`Reference token asset: ${policyId}${refAssetName}\n`);
  process.stderr.write(`Owner wallet:          ${ownerWallet}\n`);
  process.stderr.write(`User encrypted:        ${userEncrypted || "(none)"}\n`);
  process.stderr.write(`Network:               ${cfg.network}\n`);

  if (dryRun) {
    process.stderr.write("[DRY RUN] Would build and submit mint transaction — not broadcasting\n");
    process.stderr.write("[DRY RUN] Transaction details:\n");
    process.stderr.write(`  Mint: 1x ${policyId}${userAssetName} → ${ownerWallet}\n`);
    process.stderr.write(`  Mint: 1x ${policyId}${refAssetName} → ${deployerAddress}\n`);
    if (userEncrypted) {
      process.stderr.write(`  Inline datum (reference token): { userEncrypted: "${userEncrypted}" }\n`);
    }
    process.stderr.write(`  Signed by: ${deployerAddress}\n`);
    // Print token ID to stdout — pipeline reads this
    process.stdout.write(`${tokenId}\n`);
    return;
  }

  // ── Build CIP-68 mint transaction ────────────────────────────────────────

  process.stderr.write("Building mint transaction...\n");

  // MintNft redeemer = constructor index 0, no fields
  const mintRedeemer = Data.to(new Constr(0, []));

  // CIP-68 reference datum: Constr 0 with userEncrypted bytes
  // If no userEncrypted provided, use empty bytestring
  const userEncryptedBytes = userEncrypted || "";
  const referenceDatum = Data.to(new Constr(0, [userEncryptedBytes]));

  // Reference token destination: deployer's own address (holds the CIP-68 reference NFT)
  const refTokenAddress = deployerAddress;

  const tx = lucid.newTx()
    .mintAssets(
      {
        [policyId + userAssetName]: 1n,
        [policyId + refAssetName]: 1n,
      },
      mintRedeemer,
    )
    .attach.MintingPolicy(mintingPolicy)
    .pay.ToAddress(ownerWallet, { [policyId + userAssetName]: 1n })
    .pay.ToAddressWithData(
      refTokenAddress,
      { kind: "inline", value: referenceDatum },
      { [policyId + refAssetName]: 1n },
    )
    .addSignerKey(serverKeyHash);

  process.stderr.write("Completing transaction (coin selection, fee calculation)...\n");
  const completed = await tx.complete();

  process.stderr.write("Signing transaction...\n");
  const signed = completed.sign.withWallet();

  process.stderr.write("Submitting transaction...\n");
  const txHash = await signed.submit();

  process.stderr.write(`Transaction submitted: ${txHash}\n`);
  process.stderr.write("Waiting for confirmation...\n");

  const confirmed = await lucid.awaitTx(txHash);
  if (confirmed) {
    process.stderr.write(`Transaction confirmed on-chain: ${txHash}\n`);
  } else {
    process.stderr.write(`WARNING: awaitTx returned false for ${txHash} — tx may still be pending\n`);
  }

  // Print token ID to stdout — pipeline reads this
  process.stdout.write(`${tokenId}\n`);
}

main().catch((err: unknown) => {
  process.stderr.write(`blockhost-mint-nft: ${String(err instanceof Error ? err.message : err)}\n`);
  process.exit(1);
});
