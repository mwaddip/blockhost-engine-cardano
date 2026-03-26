#!/usr/bin/env -S npx tsx
/**
 * bhcrypt — crypto CLI for blockhost-engine-cardano.
 *
 * Subcommand interface backed by src/crypto.ts (native @noble/* crypto).
 *
 * Subcommands:
 *   encrypt-symmetric   --signature <hex> --plaintext <text>
 *   decrypt-symmetric   --signature <hex> --ciphertext <hex>
 *   decrypt             --private-key-file <path> --ciphertext <hex>
 *   generate-keypair    [--output <path>] [--show-pubkey]
 *   derive-pubkey       --private-key-file <path>
 *   keygen              [--network preprod|mainnet]
 *   validate-mnemonic   [--network preprod|mainnet]  (reads MNEMONIC env var)
 */

import { eciesDecrypt, symmetricEncrypt, symmetricDecrypt } from "./crypto.js";
import type { CardanoNetwork } from "./cardano/types.js";
import { secp256k1 } from "@noble/curves/secp256k1";
import { bytesToHex } from "@noble/hashes/utils";
import { randomBytes } from "node:crypto";
import * as fs from "node:fs";
import { generateMnemonic, validateMnemonic } from "@scure/bip39";
import { wordlist as english } from "@scure/bip39/wordlists/english.js";
import { deriveWallet } from "cmttk";

function parseArgs(args: string[]): { command: string; flags: Record<string, string> } {
  const command = args[0] ?? "";
  const flags: Record<string, string> = {};
  for (let i = 1; i < args.length; i++) {
    const arg = args[i];
    if (arg !== undefined && arg.startsWith("--") && i + 1 < args.length) {
      const key = arg.slice(2);
      const val = args[++i];
      if (val !== undefined) flags[key] = val;
    }
  }
  return { command, flags };
}

function die(msg: string): never {
  process.stderr.write(`bhcrypt: ${msg}\n`);
  process.exit(1);
}

function requireFlags(flags: Record<string, string>, ...keys: string[]): void {
  for (const k of keys) {
    if (!flags[k]) die(`missing --${k}`);
  }
}

function requireHex(value: string, label: string): void {
  const clean = value.startsWith("0x") ? value.slice(2) : value;
  if (!/^[0-9a-fA-F]*$/.test(clean) || clean.length === 0 || clean.length % 2 !== 0) {
    die(`${label}: invalid hex string`);
  }
}

function resolveNetwork(name: string): CardanoNetwork {
  if (name === "mainnet") return "mainnet";
  if (name === "preview") return "preview";
  return "preprod"; // default
}

const { command, flags } = parseArgs(process.argv.slice(2));

/** Derive a Cardano wallet address from mnemonic using noble-bip32ed25519. */
async function deriveAddress(
  mnemonic: string,
  network: CardanoNetwork,
): Promise<{ address: string; paymentKeyHash: string; stakeKeyHash: string }> {
  const wallet = await deriveWallet(mnemonic, network);
  return {
    address: wallet.address,
    paymentKeyHash: wallet.paymentKeyHash,
    stakeKeyHash: wallet.stakeKeyHash,
  };
}

async function main(): Promise<void> {
  switch (command) {
    case "encrypt-symmetric": {
      requireFlags(flags, "signature", "plaintext");
      requireHex(flags["signature"]!, "--signature");
      const result = symmetricEncrypt(flags["signature"]!, flags["plaintext"]!);
      process.stdout.write(result + "\n");
      break;
    }

    case "decrypt-symmetric": {
      requireFlags(flags, "signature", "ciphertext");
      requireHex(flags["signature"]!, "--signature");
      requireHex(flags["ciphertext"]!, "--ciphertext");
      const result = symmetricDecrypt(flags["signature"]!, flags["ciphertext"]!);
      process.stdout.write(result + "\n");
      break;
    }

    case "decrypt": {
      requireFlags(flags, "private-key-file", "ciphertext");
      requireHex(flags["ciphertext"]!, "--ciphertext");
      const keyHex = fs.readFileSync(flags["private-key-file"]!, "utf8").trim().replace(/^0x/, "");
      requireHex(keyHex, "private key file");
      const result = eciesDecrypt(keyHex, flags["ciphertext"]!);
      process.stdout.write(result + "\n");
      break;
    }

    case "generate-keypair": {
      // Generate secp256k1 keypair for server ECIES key (server.key format).
      const privBytes = randomBytes(32);
      const privHex = bytesToHex(privBytes);
      const pubBytes = secp256k1.getPublicKey(privBytes, false);
      const pubHex = bytesToHex(pubBytes);

      if (flags["output"]) {
        fs.writeFileSync(flags["output"], privHex + "\n", { mode: 0o600 });
        if (flags["show-pubkey"] !== undefined) {
          process.stdout.write(`${pubHex}\n`);
        } else {
          process.stdout.write(`Key written to ${flags["output"]}\n`);
          process.stdout.write(`Public key: ${pubHex}\n`);
        }
      } else {
        process.stdout.write(`${privHex}\n`);
        process.stdout.write(`${pubHex}\n`);
      }
      break;
    }

    case "derive-pubkey": {
      requireFlags(flags, "private-key-file");
      const keyHex = fs.readFileSync(flags["private-key-file"]!, "utf8").trim().replace(/^0x/, "");
      requireHex(keyHex, "private key file");
      const pubBytes = secp256k1.getPublicKey(
        Uint8Array.from(Buffer.from(keyHex, "hex")),
        false,
      );
      const pubHex = bytesToHex(pubBytes);
      process.stdout.write(`${pubHex}\n`);
      break;
    }

    case "keygen": {
      // Generate BIP39 mnemonic + derive Cardano wallet via Lucid.
      const net = resolveNetwork(flags["network"] ?? "preprod");
      const mnemonic = generateMnemonic(english, 256); // 24 words
      const info = await deriveAddress(mnemonic, net);
      process.stdout.write(
        JSON.stringify({
          mnemonic,
          ...info,
          network: net,
        }) + "\n",
      );
      break;
    }

    case "validate-mnemonic": {
      const mnemonic = process.env["MNEMONIC"];
      if (!mnemonic) die("MNEMONIC environment variable not set");
      if (!validateMnemonic(mnemonic, english)) die("invalid mnemonic phrase");
      const net = resolveNetwork(flags["network"] ?? "preprod");
      const info = await deriveAddress(mnemonic, net);
      process.stdout.write(
        JSON.stringify({
          ...info,
          network: net,
        }) + "\n",
      );
      break;
    }

    default:
      die(
        `unknown command: ${command || "(none)"}\n` +
        "Usage: bhcrypt <command> [--flags]\n" +
        "Commands: encrypt-symmetric, decrypt-symmetric, decrypt,\n" +
        "          generate-keypair, derive-pubkey,\n" +
        "          keygen, validate-mnemonic",
      );
  }
}

main().catch((err: Error) => die(err.message));
