/**
 * bw --debug --cleanup <address>
 *
 * Debug utility — sweep all ADA from every signing wallet to a target address.
 * Requires --debug flag as a safety guard.
 *
 * For each role with a keyfile, builds a transaction that sends all UTXOs
 * to the target address (leaving nothing behind except the tx fee).
 *
 * Uses Lucid Evolution for transaction building and submission.
 */

import type { Addressbook } from "../../fund-manager/types.js";
import { isValidAddress } from "../../cardano/address.js";
import { initLucidWithWallet } from "../lucid-helpers.js";

/**
 * CLI handler (called when --debug --cleanup flags are set).
 *
 * @param targetAddress  Destination bech32 address from positional args
 * @param book           Addressbook
 */
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

  console.error(
    `Sweeping ADA from ${signingRoles.length} wallet(s) to ${targetAddress}`,
  );

  for (const role of signingRoles) {
    try {
      const lucid = await initLucidWithWallet(role, book);
      const walletAddr = await lucid.wallet().address();

      // Check UTXOs at this wallet
      const utxos = await lucid.utxosAt(walletAddr);
      if (utxos.length === 0) {
        console.error(`  ${role} (${walletAddr.slice(0, 25)}...): no UTXOs, skipping`);
        continue;
      }

      // Calculate total lovelace
      let totalLovelace = 0n;
      for (const utxo of utxos) {
        totalLovelace += utxo.assets["lovelace"] ?? 0n;
      }

      if (totalLovelace <= 1_000_000n) {
        console.error(
          `  ${role}: only ${totalLovelace.toString()} lovelace, skipping (below dust)`,
        );
        continue;
      }

      console.error(
        `  ${role}: sweeping ${totalLovelace.toString()} lovelace (${utxos.length} UTXOs)`,
      );

      // Build a transaction sending everything to the target
      // By not specifying outputs and using complete() with change address = target,
      // Lucid will send all available funds (minus fee) to the change address.
      // However, Lucid doesn't have a direct "send all" — so we approximate:
      // send a large amount and let complete() figure out the rest via coin selection.

      // Strategy: just pay a nominal amount and set changeAddress to targetAddress
      // But Lucid Evolution doesn't expose changeAddress in complete().
      // Better strategy: pay max minus estimated fee to target.

      // Simplest approach: pay everything minus ~0.3 ADA fee buffer
      const sendAmount = totalLovelace - 300_000n;
      if (sendAmount <= 0n) {
        console.error(`  ${role}: balance too low after fee estimate, skipping`);
        continue;
      }

      const tx = lucid.newTx().pay.ToAddress(targetAddress, {
        lovelace: sendAmount,
      });

      // Also send along any native tokens in the UTXOs
      const nativeTokens: Record<string, bigint> = {};
      for (const utxo of utxos) {
        for (const [unit, qty] of Object.entries(utxo.assets)) {
          if (unit !== "lovelace") {
            nativeTokens[unit] = (nativeTokens[unit] ?? 0n) + qty;
          }
        }
      }

      // If there are native tokens, add them to the output
      if (Object.keys(nativeTokens).length > 0) {
        // Send native tokens in a separate output with min ADA
        const tokenOutput = { lovelace: 2_000_000n, ...nativeTokens };
        // Reduce the ADA send amount to account for the min UTXO
        const adjustedSend = sendAmount - 2_000_000n;
        if (adjustedSend > 0n) {
          const txWithTokens = lucid
            .newTx()
            .pay.ToAddress(targetAddress, { lovelace: adjustedSend })
            .pay.ToAddress(targetAddress, tokenOutput);

          try {
            const completed = await txWithTokens.complete();
            const signed = await completed.sign.withWallet().complete();
            const txHash = await signed.submit();
            console.log(`${role}: ${txHash}`);
            continue;
          } catch {
            // Fall through to ADA-only sweep
          }
        }
      }

      try {
        const completed = await tx.complete();
        const signed = await completed.sign.withWallet().complete();
        const txHash = await signed.submit();
        console.log(`${role}: ${txHash}`);
      } catch (err: unknown) {
        const msg = err instanceof Error ? err.message : String(err);
        console.error(`  ${role}: failed — ${msg}`);
      }
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      console.error(`  ${role}: error — ${msg}`);
    }
  }
}
