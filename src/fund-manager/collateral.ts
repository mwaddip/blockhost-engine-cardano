/**
 * Collateral management for Plutus script execution.
 *
 * Cardano requires an ADA-only UTxO as collateral for any Plutus
 * validator interaction (minting, collecting, cancelling).  If the
 * deployer wallet has no clean ADA-only UTxOs (e.g. after multiple
 * deployments that leave token-bearing change), script transactions
 * will fail.
 *
 * ensureCollateral() checks the deployer wallet and, if needed,
 * sends a small amount of ADA to itself to create a clean UTxO.
 */

import { getProvider, parseKoiosUtxos, buildAndSubmitTransfer, deriveWallet } from "cmttk";
import { loadNetworkConfig } from "./web3-config.js";
import type { Addressbook } from "./types.js";
import * as fs from "fs";

/** Minimum ADA (lovelace) for a usable collateral UTxO. */
const COLLATERAL_LOVELACE = 5_000_000n; // 5 ADA

/**
 * Ensure the deployer wallet has at least one ADA-only UTxO suitable
 * for Plutus collateral.  If none exists, sends COLLATERAL_LOVELACE
 * from the deployer to itself to create one.
 */
export async function ensureCollateral(book: Addressbook): Promise<void> {
  const serverEntry = book["server"];
  if (!serverEntry?.address || !serverEntry?.keyfile) {
    return;
  }

  const { network, blockfrostProjectId } = loadNetworkConfig();
  const provider = getProvider(network, blockfrostProjectId || undefined);

  const rawUtxos = await provider.fetchUtxos(serverEntry.address);
  const utxos = parseKoiosUtxos(rawUtxos);

  // A valid collateral UTxO: ADA-only (no native tokens) and >= 5 ADA
  const hasCollateral = utxos.some(
    (u) => Object.keys(u.tokens).length === 0 && u.lovelace >= COLLATERAL_LOVELACE,
  );

  if (hasCollateral) return;

  console.log("[FUND] No suitable collateral UTxO found — creating one");

  const mnemonic = fs.readFileSync(serverEntry.keyfile, "utf8").trim();
  const wallet = await deriveWallet(mnemonic, network);

  const txHash = await buildAndSubmitTransfer({
    provider,
    fromAddress: wallet.address,
    toAddress: wallet.address,
    assets: { lovelace: COLLATERAL_LOVELACE },
    signingKey: new Uint8Array([...wallet.paymentKey]),
  });
  console.log(`[FUND] Collateral UTxO created: ${txHash}`);
}
