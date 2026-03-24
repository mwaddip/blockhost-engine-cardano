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
  const provider = getProvider(NETWORK);

  process.stderr.write(`Deployer:  ${wallet.address.slice(0, 30)}...\n\n`);

  const targets = MODE === "all"
    ? TARGETS
    : TARGETS.filter(t => t.key.startsWith(MODE === "sub" ? "subscription" : MODE));

  for (const target of targets) {
    const validator = blueprint.validators.find(v => v.title === target.pattern);
    if (!validator) {
      process.stderr.write(`${target.label}: not found in blueprint, skipping\n`);
      continue;
    }

    if (validator.parameters && validator.parameters.length > 0) {
      process.stderr.write(`${target.label}: has ${validator.parameters.length} unapplied parameter(s) — run 'aiken blueprint apply' first\n`);
      process.exit(1);
    }

    process.stderr.write(`Deploying ${target.label}...\n`);
    process.stderr.write(`  Hash: ${validator.hash}\n`);

    const scriptBytes = hexToBytes(validator.compiledCode);
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
    process.stdout.write(`${target.key}=${validator.hash}\n`);
    if (!deployed) {
      process.stderr.write(`  WARNING: could not deploy on-chain, but hash is correct\n`);
    }

    // Wait between deploys for UTXO indexing
    if (targets.indexOf(target) < targets.length - 1) {
      process.stderr.write("  Waiting 25s for chain indexing...\n");
      await new Promise(r => setTimeout(r, 25000));
    }
  }

  process.stderr.write("\nDone.\n");
}

main().catch((err: unknown) => {
  process.stderr.write(`blockhost-deploy-contracts: ${String(err instanceof Error ? err.message : err)}\n`);
  process.exit(1);
});
