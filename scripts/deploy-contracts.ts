#!/usr/bin/env -S npx tsx
/**
 * blockhost-deploy-contracts — Deploy Cardano validators as reference scripts.
 *
 * Reads the Aiken blueprint (plutus.json), deploys each validator as a
 * reference script UTXO on-chain, and prints key=value pairs to stdout.
 *
 * Usage:
 *   blockhost-deploy-contracts          # deploy all validators
 *   blockhost-deploy-contracts sub      # subscription validator only
 *   blockhost-deploy-contracts beacon   # beacon minting policy only
 *   blockhost-deploy-contracts nft      # NFT minting policy only
 *
 * Environment:
 *   CARDANO_NETWORK       Network (preprod/preview/mainnet, default: preprod)
 *   BLOCKHOST_CONFIG_DIR  Config directory (default: /etc/blockhost)
 *   BLUEPRINT_PATH        Override path to plutus.json
 *
 * Reads deployer mnemonic from $BLOCKHOST_CONFIG_DIR/deployer.key.
 *
 * stdout: key=value pairs (subscription_validator_hash=XXX, etc.)
 * stderr: progress messages
 * Exit: 0 = success, 1 = failure
 */

import * as fs from "node:fs";
import * as path from "node:path";
import {
  deriveWallet,
  getProvider,
  getPaymentKeyHash,
  applyParamsToScript,
  parseKoiosUtxos,
  selectUtxos,
  addressToHex,
  calculateFee,
  buildOutputCbor,
  hexToBytes,
  bytesToHex,
  cborUint,
  cborBytes,
  cborArray,
  cborMap,
  cborTag,
} from "cmttk";
import type { CardanoNetwork } from "../src/cardano/types.js";
import { blake2b } from "@noble/hashes/blake2b";
import { PrivateKey } from "noble-bip32ed25519";

// ── Config ──────────────────────────────────────────────────────────────────

const CONFIG_DIR = process.env["BLOCKHOST_CONFIG_DIR"] ?? "/etc/blockhost";
const NETWORK = (process.env["CARDANO_NETWORK"] ?? "preprod") as CardanoNetwork;
const MODE = process.argv[2] ?? "all";

interface Validator {
  title: string;
  compiledCode: string;
  hash: string;
  parameters?: unknown[];
}

const TARGETS = [
  { pattern: "subscription.subscription.spend", key: "subscription_validator_hash", label: "Subscription validator" },
  { pattern: "beacon.beacon.mint", key: "beacon_policy_id", label: "Beacon minting policy" },
  { pattern: "nft.nft.mint", key: "nft_policy_id", label: "NFT minting policy" },
  { pattern: "reference_store.reference_store.spend", key: "reference_store_hash", label: "Reference store" },
];

// ── Blueprint resolution ────────────────────────────────────────────────────

function findBlueprint(): string {
  if (process.env["BLUEPRINT_PATH"]) return process.env["BLUEPRINT_PATH"];

  const candidates = [
    "/usr/share/blockhost/contracts/plutus.json",
    `${CONFIG_DIR}/plutus.json`,
    "plutus.json",
  ];

  // In dev mode, also check relative to script location
  try {
    const scriptDir = path.dirname(new URL(import.meta.url).pathname);
    if (scriptDir) candidates.unshift(path.resolve(scriptDir, "..", "plutus.json"));
  } catch { /* bundled — import.meta.url not available */ }

  for (const p of candidates) {
    if (fs.existsSync(p)) return p;
  }

  process.stderr.write(`blockhost-deploy-contracts: blueprint not found. Searched:\n`);
  for (const p of candidates) process.stderr.write(`  ${p}\n`);
  process.exit(1);
}

// ── Main ────────────────────────────────────────────────────────────────────

async function main(): Promise<void> {
  if (!["all", "sub", "beacon", "nft"].includes(MODE)) {
    process.stderr.write("Usage: blockhost-deploy-contracts [all|sub|beacon|nft]\n");
    process.exit(1);
  }

  const blueprintPath = findBlueprint();
  process.stderr.write(`Blueprint: ${blueprintPath}\n`);
  process.stderr.write(`Network:   ${NETWORK}\n`);

  const blueprint = JSON.parse(fs.readFileSync(blueprintPath, "utf8")) as { validators: Validator[] };

  // Load deployer wallet
  const keyPath = `${CONFIG_DIR}/deployer.key`;
  if (!fs.existsSync(keyPath)) {
    process.stderr.write(`blockhost-deploy-contracts: deployer key not found: ${keyPath}\n`);
    process.exit(1);
  }
  const mnemonic = fs.readFileSync(keyPath, "utf8").trim();
  const wallet = await deriveWallet(mnemonic, NETWORK);
  const koiosUrl = process.env["KOIOS_URL"] ?? "";
  const provider = getProvider(NETWORK, undefined, koiosUrl || undefined);

  const serverKeyHash = getPaymentKeyHash(wallet.address);
  if (!serverKeyHash) {
    process.stderr.write("blockhost-deploy-contracts: could not extract payment key hash\n");
    process.exit(1);
  }
  process.stderr.write(`Deployer:  ${wallet.address.slice(0, 30)}...\n`);
  process.stderr.write(`Key hash:  ${serverKeyHash}\n\n`);

  /** Compute script hash: blake2b_224(0x03 ++ compiledCode_bytes) */
  function computeHash(compiledCode: string): string {
    const bytes = hexToBytes(compiledCode);
    const prefixed = new Uint8Array(1 + bytes.length);
    prefixed[0] = 0x03;
    prefixed.set(bytes, 1);
    return bytesToHex(blake2b(prefixed, { dkLen: 28 }));
  }

  // ── Apply parameters ──────────────────────────────────────────────────────
  // Dependency order: subscription first (2 params) → beacon gets sub hash → NFT gets key hash

  const subValidator = blueprint.validators.find(v => v.title === "subscription.subscription.spend");
  const beaconValidator = blueprint.validators.find(v => v.title === "beacon.beacon.mint");
  const nftValidator = blueprint.validators.find(v => v.title === "nft.nft.mint");

  // Apply params to subscription: server_key_hash + service_address_key_hash (same key for both)
  let subCode = subValidator?.compiledCode ?? "";
  if (subValidator?.parameters?.length) {
    subCode = applyParamsToScript(subCode, [serverKeyHash, serverKeyHash]);
  }
  const subHash = subCode ? computeHash(subCode) : "";

  // Apply subscription_validator_hash to beacon
  let beaconCode = beaconValidator?.compiledCode ?? "";
  if (beaconValidator?.parameters?.length) {
    beaconCode = applyParamsToScript(beaconCode, [subHash]);
  }
  const beaconHash = beaconCode ? computeHash(beaconCode) : "";

  // Apply server_key_hash to NFT
  let nftCode = nftValidator?.compiledCode ?? "";
  if (nftValidator?.parameters?.length) {
    nftCode = applyParamsToScript(nftCode, [serverKeyHash]);
  }
  const nftHash = nftCode ? computeHash(nftCode) : "";

  // Apply server_key_hash to reference store
  const refStoreValidator = blueprint.validators.find(v => v.title === "reference_store.reference_store.spend");
  let refStoreCode = refStoreValidator?.compiledCode ?? "";
  if (refStoreValidator?.parameters?.length) {
    refStoreCode = applyParamsToScript(refStoreCode, [serverKeyHash]);
  }
  const refStoreHash = refStoreCode ? computeHash(refStoreCode) : "";

  // Map of parameterized codes by title
  const parameterized: Record<string, { code: string; hash: string }> = {
    "subscription.subscription.spend": { code: subCode, hash: subHash },
    "beacon.beacon.mint": { code: beaconCode, hash: beaconHash },
    "nft.nft.mint": { code: nftCode, hash: nftHash },
    "reference_store.reference_store.spend": { code: refStoreCode, hash: refStoreHash },
  };

  process.stderr.write(`Parameterized hashes:\n`);
  process.stderr.write(`  Subscription: ${subHash}\n`);
  process.stderr.write(`  Beacon:       ${beaconHash}\n`);
  process.stderr.write(`  NFT:          ${nftHash}\n`);
  process.stderr.write(`  Ref store:    ${refStoreHash}\n\n`);

  // ── Deploy ────────────────────────────────────────────────────────────────

  const targets = MODE === "all"
    ? TARGETS
    : TARGETS.filter(t => t.key.startsWith(MODE === "sub" ? "subscription" : MODE));

  for (const target of targets) {
    const p = parameterized[target.pattern];
    if (!p || !p.code) {
      process.stderr.write(`${target.label}: not found in blueprint, skipping\n`);
      continue;
    }

    process.stderr.write(`Deploying ${target.label}...\n`);
    process.stderr.write(`  Hash: ${p.hash}\n`);

    const scriptBytes = hexToBytes(p.code);
    process.stderr.write(`  Size: ${scriptBytes.length} bytes\n`);

    // Build reference script output
    // Field 3 = #6.24(bytes .cbor [3, cborBytes(script)])
    const innerScript = cborArray([cborUint(3n), cborBytes(scriptBytes)]);
    const refScript = cborTag(24, cborBytes(innerScript));

    const fromAddrHex = addressToHex(wallet.address);

    // Send reference script to an enterprise address (payment key only, no staking).
    // This keeps ref script UTXOs separate from the deployer's spendable base address,
    // preventing coin selection from accidentally spending them in future transactions.
    const paymentKeyHash = fromAddrHex.slice(2, 58); // skip header byte, take 28 bytes
    const enterpriseHeader = NETWORK === "mainnet" ? "61" : "60";
    const refScriptAddrHex = enterpriseHeader + paymentKeyHash;

    const minUtxo = BigInt(Math.max(2_000_000, Math.ceil((160 + 60 + scriptBytes.length) * 4310 * 1.15)));

    const refOutput = cborMap([
      [cborUint(0n), cborBytes(hexToBytes(refScriptAddrHex))],
      [cborUint(1n), cborUint(minUtxo)],
      [cborUint(3n), refScript],
    ]);

    // Fetch UTXOs, protocol params, tip
    const [rawUtxos, pp, tip] = await Promise.all([
      provider.fetchUtxos(wallet.address),
      provider.fetchProtocolParams(),
      provider.fetchTip(),
    ]);
    const utxos = parseKoiosUtxos(rawUtxos);
    const ttl = BigInt(tip.slot + 900);
    const maxFee = 500000n;

    const { selected, inputTotal } = selectUtxos(utxos, { lovelace: minUtxo + maxFee });

    const sorted = [...selected].sort((a, b) =>
      a.txHash < b.txHash ? -1 : a.txHash > b.txHash ? 1 : a.index - b.index
    );

    const inputsCbor = cborTag(258, cborArray(
      sorted.map(u => cborArray([cborBytes(hexToBytes(u.txHash)), cborUint(BigInt(u.index))]))
    ));

    // Carry forward tokens in change
    const changeTokens: [string, bigint][] = [];
    for (const [unit, qty] of Object.entries(inputTotal)) {
      if (unit !== "lovelace" && qty > 0n) changeTokens.push([unit, qty]);
    }

    const kL = wallet.paymentKey.slice(0, 32);
    const kR = wallet.paymentKey.slice(32, 64);

    function buildBody(fee: bigint): Uint8Array {
      const changeLv = inputTotal.lovelace - minUtxo - fee;
      const outs = [refOutput];
      if (changeLv > 0n || changeTokens.length > 0) {
        const clv = changeLv < 1_000_000n ? 1_000_000n : changeLv;
        outs.push(buildOutputCbor(fromAddrHex, clv, changeTokens.length > 0 ? changeTokens : undefined));
      }
      return cborMap([
        [cborUint(0n), inputsCbor],
        [cborUint(1n), cborArray(outs)],
        [cborUint(2n), cborUint(fee)],
        [cborUint(3n), cborUint(ttl)],
      ]);
    }

    function signTx(body: Uint8Array): Uint8Array {
      const h = blake2b(body, { dkLen: 32 });
      const pk = new PrivateKey(kL, kR);
      const sig = pk.sign(h);
      const pub = pk.toPublicKey().toBytes();
      const ws = cborMap([[cborUint(0n), cborArray([cborArray([cborBytes(pub), cborBytes(sig)])])]]);
      return cborArray([body, ws, new Uint8Array([0xf5]), new Uint8Array([0xf6])]);
    }

    // Fee calculation + submit with retry
    let currentFee = maxFee;
    // Pre-calculate fee from tx size
    for (let i = 0; i < 5; i++) {
      const tx = signTx(buildBody(currentFee));
      const neededFee = calculateFee(tx.length, pp);
      if (neededFee <= currentFee) break;
      currentFee = neededFee;
    }

    let deployed = false;
    for (let attempt = 0; attempt < 3; attempt++) {
      try {
        const tx = signTx(buildBody(currentFee));
        const txHash = await provider.submitTx(bytesToHex(tx));
        process.stderr.write(`  Deployed: ${txHash}#0\n`);
        deployed = true;
        break;
      } catch (err: unknown) {
        const msg = err instanceof Error ? err.message : String(err);
        if (msg.includes("already been included") || msg.includes("BadInputsUTxO")) {
          process.stderr.write(`  Already deployed (skipping)\n`);
          deployed = true;
          break;
        }
        if (msg.includes("FeeTooSmall")) {
          // Extract needed fee from error and retry
          const match = msg.match(/Coin (\d+)\) \(Coin (\d+)\)/);
          if (match) {
            currentFee = BigInt(match[1]!) + 1000n; // use the min fee + margin
            process.stderr.write(`  Fee too low, retrying with ${currentFee}...\n`);
            continue;
          }
        }
        process.stderr.write(`  Failed: ${msg.slice(0, 300)}\n`);
        break;
      }
    }
    // Always emit the hash — deterministic from compiledCode regardless of deployment
    process.stdout.write(`${target.key}=${p.hash}\n`);
    if (!deployed) {
      process.stderr.write(`  WARNING: could not deploy on-chain, but hash is correct\n`);
    }

    // Wait between deploys for UTXO indexing
    if (targets.indexOf(target) < targets.length - 1) {
      process.stderr.write("  Waiting 25s for chain indexing...\n");
      await new Promise(r => setTimeout(r, 25000));
    }
  }

  // Emit parameterized beacon script CBOR for signup page
  if (beaconCode) {
    process.stdout.write(`beacon_script_cbor=${beaconCode}\n`);
  }

  process.stderr.write("\nDone.\n");
}

main().catch((err: unknown) => {
  process.stderr.write(`blockhost-deploy-contracts: ${String(err instanceof Error ? err.message : err)}\n`);
  process.exit(1);
});
