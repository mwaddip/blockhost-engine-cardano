/**
 * Batch subscription UTXO collection (Cardano).
 *
 * On Cardano, "withdrawing from the contract" means building a transaction
 * that consumes multiple mature subscription UTXOs with a ServiceCollect
 * redeemer.  The service address receives the collected ADA.
 *
 * This is stubbed pending script-spending tx builder integration — the
 * structure is correct so the fund-manager orchestration can call it
 * unconditionally once the tx building lands.
 *
 * When implemented the steps will be:
 *   1. Query Koios for subscription UTXOs at the validator address
 *   2. Filter UTXOs where expiry timestamp has passed (collectable by service)
 *   3. Batch into groups of ~15 UTXOs (Cardano tx size limits)
 *   4. For each batch: build a tx consuming those UTXOs with ServiceCollect
 *      redeemer, signed by the server key, sent to the hot wallet
 *   5. Submit each batch tx via the provider
 */

import type { Utxo } from "cmttk";
import { getProvider, parseKoiosUtxos } from "cmttk";
import type { Addressbook, FundManagerConfig } from "./types.js";
import { loadNetworkConfig } from "./web3-config.js";
import { resolveRole } from "./addressbook.js";
import { formatAda } from "../bw/cli-utils.js";

/** Maximum UTXOs per collection transaction (Cardano size constraint). */
const MAX_UTXOS_PER_BATCH = 15;

/**
 * Run the fund cycle withdrawal step.
 *
 * Identifies mature subscription UTXOs at the validator address and
 * batch-collects them to the hot wallet.
 *
 * @param book              Addressbook (must contain "server" with keyfile and "hot")
 * @param config            Fund manager configuration
 * @param validatorAddress  Bech32 address of the subscription validator script
 * @param beaconPolicyId    Policy ID of the beacon token
 */
export async function runFundCycle(
  book: Addressbook,
  config: FundManagerConfig,
  validatorAddress: string,
  beaconPolicyId: string,
): Promise<void> {
  console.log("[FUND] Running fund cycle...");

  if (!book["server"]?.keyfile) {
    console.error("[FUND] Cannot collect: server wallet has no keyfile");
    return;
  }

  const hotAddress = resolveRole("hot", book);
  if (!hotAddress) {
    console.error("[FUND] Cannot collect: hot wallet not configured");
    return;
  }

  // Step 1: Identify subscription UTXOs via Koios
  const { network, blockfrostProjectId } = loadNetworkConfig();
  const provider = getProvider(network, blockfrostProjectId || undefined);

  let utxos: Utxo[];
  try {
    const raw = await provider.fetchUtxos(validatorAddress);
    utxos = parseKoiosUtxos(raw);
  } catch (err) {
    console.error(`[FUND] Failed to query validator UTXOs: ${err}`);
    return;
  }

  if (utxos.length === 0) {
    console.log("[FUND] No UTXOs at validator address, skipping collection");
    return;
  }

  // Filter for UTXOs that carry a beacon token (subscription UTXOs)
  const subscriptionUtxos = utxos.filter((u) =>
    Object.keys(u.tokens).some((unit) => unit.startsWith(beaconPolicyId)),
  );

  if (subscriptionUtxos.length === 0) {
    console.log("[FUND] No beacon UTXOs found, skipping collection");
    return;
  }

  // Calculate total collectable ADA (for logging only at this stage)
  const totalLovelace = subscriptionUtxos.reduce(
    (acc, u) => acc + u.lovelace,
    0n,
  );

  console.log(
    `[FUND] Found ${subscriptionUtxos.length} subscription UTXOs ` +
    `(${formatAda(totalLovelace)} total)`,
  );

  // Check against minimum withdrawal threshold
  if (totalLovelace < config.min_withdrawal_lovelace) {
    console.log(
      `[FUND] Skipping collection: ${formatAda(totalLovelace)} below threshold ` +
      `(min: ${formatAda(config.min_withdrawal_lovelace)})`,
    );
    return;
  }

  // Step 2: Batch into groups and log intent
  const batches: Utxo[][] = [];
  for (let i = 0; i < subscriptionUtxos.length; i += MAX_UTXOS_PER_BATCH) {
    batches.push(subscriptionUtxos.slice(i, i + MAX_UTXOS_PER_BATCH));
  }

  console.log(
    `[FUND] Would build ${batches.length} collection tx(s) of up to ` +
    `${MAX_UTXOS_PER_BATCH} UTXOs each -> hot wallet ${hotAddress}`,
  );

  for (let i = 0; i < batches.length; i++) {
    const batch = batches[i]!;
    const batchLovelace = batch.reduce((acc, u) => acc + u.lovelace, 0n);
    console.log(
      `[FUND]   Batch ${i + 1}/${batches.length}: ` +
      `${batch.length} UTXOs, ${formatAda(batchLovelace)}`,
    );
  }

  // Step 3: Build and submit batch transactions
  // TODO: requires buildAndSubmitScriptTx with ServiceCollect redeemer
  console.log(
    "[FUND] TODO: batch collection tx building requires script-spending integration.",
  );

  console.log("[FUND] Fund cycle collection complete (tx building not yet implemented)");
}
