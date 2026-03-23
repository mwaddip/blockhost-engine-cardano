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
 * Uses the minimal tx toolkit (src/cardano/) — no Lucid.
 *
 * stdout: token ID (integer) on success
 * stderr: progress / error messages
 * Exit: 0 = success, 1 = failure
 */

import * as fs from "node:fs";
import * as path from "node:path";
import * as yaml from "js-yaml";
import { blake2b } from "@noble/hashes/blake2b";
import { deriveWallet } from "cmttk";
import { getProvider } from "cmttk";
import { getPaymentKeyHash } from "cmttk";
import { Constr, Data } from "cmttk";
import { buildAndSubmitScriptTx } from "cmttk";
import { hexToBytes, bytesToHex } from "cmttk";
import { userTokenAssetName, referenceTokenAssetName } from "../src/nft/mint.js";
import type { CardanoNetwork } from "../src/cardano/types.js";
import type { Assets } from "cmttk";

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
  };
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

  if (!/^addr(_test)?1[a-z0-9]+$/.test(ownerWallet)) {
    process.stderr.write(
      "blockhost-mint-nft: --owner-wallet must be a bech32 Cardano address\n",
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

function loadConfig() {
  const cfgPath = `${CONFIG_DIR}/web3-defaults.yaml`;
  if (!fs.existsSync(cfgPath)) {
    process.stderr.write(`blockhost-mint-nft: config not found: ${cfgPath}\n`);
    process.exit(1);
  }

  const raw = yaml.load(fs.readFileSync(cfgPath, "utf8")) as Web3Yaml;
  const bc  = raw.blockchain;

  const networkRaw = (bc?.network ?? "preprod").toLowerCase();
  const network: CardanoNetwork =
    networkRaw === "mainnet" ? "mainnet" :
    networkRaw === "preview"  ? "preview"  : "preprod";

  return {
    blockfrostProjectId: bc?.blockfrost_project_id ?? "",
    network,
    nftPolicyId: bc?.nft_policy_id ?? "",
  };
}

// ── Mnemonic loading ──────────────────────────────────────────────────────────

function loadMnemonic(): string {
  const fromEnv = process.env["DEPLOYER_MNEMONIC"];
  if (fromEnv) return fromEnv.trim();

  if (!fs.existsSync(KEY_PATH)) {
    process.stderr.write(`blockhost-mint-nft: set DEPLOYER_MNEMONIC or create ${KEY_PATH}\n`);
    process.exit(1);
  }
  return fs.readFileSync(KEY_PATH, "utf8").trim();
}

// ── Token ID counter ──────────────────────────────────────────────────────────

function allocateTokenId(): number {
  if (!fs.existsSync(STATE_DIR)) {
    fs.mkdirSync(STATE_DIR, { recursive: true });
  }

  let current = 1;
  if (fs.existsSync(COUNTER_PATH)) {
    const raw = fs.readFileSync(COUNTER_PATH, "utf8").trim();
    const parsed = parseInt(raw, 10);
    if (!isNaN(parsed) && parsed > 0) current = parsed;
  }

  fs.writeFileSync(COUNTER_PATH, String(current + 1), { encoding: "utf8" });
  return current;
}

// ── Blueprint loading ──────────────────────────────────────────────────────

function loadNftCompiledCode(): string {
  const blueprintPath = path.resolve(
    path.dirname(new URL(import.meta.url).pathname),
    "..",
    "plutus.json",
  );

  if (!fs.existsSync(blueprintPath)) {
    // Try config dir
    const configPath = `${CONFIG_DIR}/plutus.json`;
    if (!fs.existsSync(configPath)) {
      process.stderr.write(`blockhost-mint-nft: plutus.json not found\n`);
      process.exit(1);
    }
    const bp = JSON.parse(fs.readFileSync(configPath, "utf8")) as {
      validators: Array<{ title: string; compiledCode: string }>;
    };
    const v = bp.validators.find((v) => v.title === "nft.nft.mint");
    if (!v) { process.stderr.write("blockhost-mint-nft: nft.nft.mint not found\n"); process.exit(1); }
    return v.compiledCode;
  }

  const bp = JSON.parse(fs.readFileSync(blueprintPath, "utf8")) as {
    validators: Array<{ title: string; compiledCode: string }>;
  };
  const v = bp.validators.find((v) => v.title === "nft.nft.mint");
  if (!v) { process.stderr.write("blockhost-mint-nft: nft.nft.mint not found\n"); process.exit(1); }
  return v.compiledCode;
}

// ── Script hash computation ────────────────────────────────────────────────

/** Compute policy ID = blake2b_224(0x03 ++ compiledCode_bytes) */
function computePolicyId(compiledCode: string): string {
  const scriptBytes = hexToBytes(compiledCode);
  const prefixed = new Uint8Array(1 + scriptBytes.length);
  prefixed[0] = 0x03; // PlutusV3
  prefixed.set(scriptBytes, 1);
  return bytesToHex(blake2b(prefixed, { dkLen: 28 }));
}

// ── Main ──────────────────────────────────────────────────────────────────────

async function main(): Promise<void> {
  const { ownerWallet, userEncrypted, dryRun } = parseArgs();
  const cfg      = loadConfig();
  const mnemonic = loadMnemonic();

  process.stderr.write("Deriving wallet...\n");
  const wallet = await deriveWallet(mnemonic, cfg.network);
  const provider = getProvider(cfg.network, cfg.blockfrostProjectId);
  const deployerAddress = wallet.address;
  const serverKeyHash = getPaymentKeyHash(deployerAddress);

  if (!serverKeyHash) {
    process.stderr.write("blockhost-mint-nft: could not extract payment key hash\n");
    process.exit(1);
  }

  process.stderr.write(`Deployer address: ${deployerAddress}\n`);
  process.stderr.write(`Server key hash:  ${serverKeyHash}\n`);

  // The NFT policy in plutus.json should already have server_key_hash applied
  // (via aiken blueprint apply). Verify the computed policy ID matches config.
  const nftCompiledCode = loadNftCompiledCode();
  const policyId = computePolicyId(nftCompiledCode);
  process.stderr.write(`Computed policy ID: ${policyId}\n`);

  if (cfg.nftPolicyId && policyId !== cfg.nftPolicyId) {
    process.stderr.write(
      `WARNING: computed policy ID (${policyId}) differs from config (${cfg.nftPolicyId})\n`,
    );
  }

  // Allocate token ID and compute CIP-68 asset names
  const tokenId = allocateTokenId();
  const userAssetName = userTokenAssetName(tokenId);
  const refAssetName  = referenceTokenAssetName(tokenId);

  process.stderr.write(`Token ID: ${tokenId}\n`);
  process.stderr.write(`User token:      ${policyId}${userAssetName}\n`);
  process.stderr.write(`Reference token: ${policyId}${refAssetName}\n`);

  if (dryRun) {
    process.stderr.write("[DRY RUN] Would mint — not broadcasting\n");
    process.stdout.write(`${tokenId}\n`);
    return;
  }

  // Build CIP-68 mint transaction
  process.stderr.write("Building mint transaction...\n");

  const mintRedeemer = Data.to(new Constr(0, [])); // MintNft
  const referenceDatum = Data.to(new Constr(0, [userEncrypted || ""]));

  const nowMs = Date.now();

  const txHash = await buildAndSubmitScriptTx({
    provider,
    walletAddress: deployerAddress,
    scriptInputs: [],
    outputs: [
      // User token (222) → owner
      {
        address: ownerWallet,
        assets: { lovelace: 2_000_000n, [policyId + userAssetName]: 1n },
      },
      // Reference token (100) → deployer with inline datum
      {
        address: deployerAddress,
        assets: { lovelace: 2_000_000n, [policyId + refAssetName]: 1n },
        datumCbor: referenceDatum,
      },
    ],
    mints: [{
      policyId,
      assets: {
        [userAssetName]: 1n,
        [refAssetName]: 1n,
      },
      redeemerCbor: mintRedeemer,
      scriptCbor: nftCompiledCode,
    }],
    validFrom: nowMs - 120_000,
    validTo: nowMs + 600_000,
    network: cfg.network,
    requiredSigners: [serverKeyHash],
    signingKey: new Uint8Array([...wallet.paymentKey]),
  });

  process.stderr.write(`Transaction submitted: ${txHash}\n`);
  process.stdout.write(`${tokenId}\n`);
}

main().catch((err: unknown) => {
  process.stderr.write(`blockhost-mint-nft: ${String(err instanceof Error ? err.message : err)}\n`);
  process.exit(1);
});
