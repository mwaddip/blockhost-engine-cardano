/**
 * bw --debug --cleanup <address>
 *
 * Debug utility — sweep all ADA from every signing wallet to a target address.
 * Requires --debug flag as a safety guard.
 *
 * Uses the minimal tx toolkit (src/cardano/) — no Lucid.
 */

import type { Addressbook } from "../../fund-manager/types.js";
import { isValidAddress } from "@mwaddip/cmttk";
import { getProvider } from "@mwaddip/cmttk";
import { loadNetworkConfig } from "../../fund-manager/web3-config.js";
import { deriveWallet } from "@mwaddip/cmttk";
import { parseKoiosUtxos, buildAndSubmitTransfer } from "@mwaddip/cmttk";
import * as fs from "fs";

export async function cleanupCommand(
  targetAddress: string,
  book: Addressbook,
): Promise<void> {
  if (!isValidAddress(targetAddress)) {
    console.error(`Invalid target address: ${targetAddress}`);
    process.exit(1);
  }

  const signingRoles = Object.entries(book)
    .filter(([, entry]) => Boolean(entry.keyfile))
    .map(([role]) => role);

  if (signingRoles.length === 0) {
    console.log("No signing wallets found in addressbook.");
    return;
  }

  const { network, blockfrostProjectId, koiosUrl } = loadNetworkConfig();
  const provider = getProvider(network, blockfrostProjectId || undefined, koiosUrl || undefined);

  console.error(`Sweeping ADA from ${signingRoles.length} wallet(s) to ${targetAddress}`);

  for (const role of signingRoles) {
    try {
      const entry = book[role]!;
      const mnemonic = fs.readFileSync(entry.keyfile!, "utf8").trim();
      const wallet = await deriveWallet(mnemonic, network);

      if (wallet.address === targetAddress) {
        console.error(`  ${role}: is the target address, skipping`);
        continue;
      }

      const rawUtxos = await provider.fetchUtxos(wallet.address);
      const utxos = parseKoiosUtxos(rawUtxos);

      if (utxos.length === 0) {
        console.error(`  ${role} (${wallet.address.slice(0, 25)}...): no UTXOs, skipping`);
        continue;
      }

      let totalLovelace = 0n;
      for (const u of utxos) totalLovelace += u.lovelace;

      if (totalLovelace <= 1_000_000n) {
        console.error(`  ${role}: only ${totalLovelace.toString()} lovelace, skipping (below dust)`);
        continue;
      }

      // Send everything minus fee buffer
      const sendAmount = totalLovelace - 300_000n;
      if (sendAmount <= 0n) {
        console.error(`  ${role}: balance too low after fee estimate, skipping`);
        continue;
      }

      console.error(`  ${role}: sweeping ${totalLovelace.toString()} lovelace (${utxos.length} UTXOs)`);

      const txHash = await buildAndSubmitTransfer({
        provider,
        fromAddress: wallet.address,
        toAddress: targetAddress,
        assets: { lovelace: sendAmount },
        signingKey: new Uint8Array([...wallet.paymentKey]),
      });
      console.log(`${role}: ${txHash}`);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      console.error(`  ${role}: failed — ${msg}`);
    }
  }
}
