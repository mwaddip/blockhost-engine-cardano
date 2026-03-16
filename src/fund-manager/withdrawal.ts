/**
 * Batch subscription UTXO collection (Cardano).
 *
 * On Cardano, "withdrawing from the contract" means building a transaction
 * that consumes multiple mature subscription UTXOs with a ServiceCollect
 * redeemer.  The service address receives the collected ADA.
 *
 * This is stubbed pending MeshJS integration — the structure is correct so
 * the fund-manager orchestration can call it unconditionally once the tx
 * building lands.
 *
 * When implemented the steps will be:
 *   1. Query Blockfrost for subscription UTXOs at the validator address
 *   2. Filter UTXOs where expiry timestamp has passed (collectable by service)
 *   3. Batch into groups of ~15 UTXOs (Cardano tx size limits)
 *   4. For each batch: build a tx consuming those UTXOs with ServiceCollect
 *      redeemer, signed by the server key, sent to the hot wallet
 *   5. Submit each batch tx to Blockfrost
 */

import type { BlockFrostAPI } from "@blockfrost/blockfrost-js";
import type { Addressbook, FundManagerConfig } from "./types.js";
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
 * @param book         Addressbook (must contain "server" with keyfile and "hot")
 * @param config       Fund manager configuration
 * @param client       Blockfrost API client
 * @param validatorAddress  Bech32 address of the subscription validator script
 * @param beaconPolicyId    Policy ID of the beacon token
 */
export async function runFundCycle(
  book: Addressbook,
  config: FundManagerConfig,
  client: BlockFrostAPI,
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

  // Step 1: Identify mature subscription UTXOs
  let utxos: Array<{ tx_hash: string; tx_index: number; amount: Array<{ unit: string; quantity: string }> }>;
  try {
    utxos = await client.addressesUtxos(validatorAddress);
  } catch (err: unknown) {
    if (isNotFound(err)) {
      console.log("[FUND] No UTXOs at validator address, skipping collection");
      return;
    }
    throw err;
  }

  if (utxos.length === 0) {
    console.log("[FUND] No UTXOs at validator address, skipping collection");
    return;
  }

  // Filter for UTXOs that carry a beacon token (subscription UTXOs)
  const subscriptionUtxos = utxos.filter((u) =>
    u.amount.some((a) => a.unit.startsWith(beaconPolicyId)),
  );

  if (subscriptionUtxos.length === 0) {
    console.log("[FUND] No beacon UTXOs found, skipping collection");
    return;
  }

  // Calculate total collectable ADA (for logging only at this stage)
  const totalLovelace = subscriptionUtxos.reduce((acc, u) => {
    const lovelaceEntry = u.amount.find((a) => a.unit === "lovelace");
    return acc + BigInt(lovelaceEntry?.quantity ?? "0");
  }, 0n);

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
  const batches: typeof subscriptionUtxos[] = [];
  for (let i = 0; i < subscriptionUtxos.length; i += MAX_UTXOS_PER_BATCH) {
    batches.push(subscriptionUtxos.slice(i, i + MAX_UTXOS_PER_BATCH));
  }

  console.log(
    `[FUND] Would build ${batches.length} collection tx(s) of up to ` +
    `${MAX_UTXOS_PER_BATCH} UTXOs each -> hot wallet ${hotAddress}`,
  );

  for (let i = 0; i < batches.length; i++) {
    const batch = batches[i]!;
    const batchLovelace = batch.reduce((acc, u) => {
      const entry = u.amount.find((a) => a.unit === "lovelace");
      return acc + BigInt(entry?.quantity ?? "0");
    }, 0n);
    console.log(
      `[FUND]   Batch ${i + 1}/${batches.length}: ` +
      `${batch.length} UTXOs, ${formatAda(batchLovelace)}`,
    );
  }

  // Step 3: Build and submit batch transactions (TODO: MeshJS)
  console.log(
    "[FUND] TODO: batch collection tx building requires MeshJS integration.",
  );
  console.log(
    "       Implement once MeshJS TxBuilder is wired and testnet wallet is funded.",
  );

  console.log("[FUND] Fund cycle collection complete (tx building not yet implemented)");
}

// ── Utility ───────────────────────────────────────────────────────────────────

function isNotFound(err: unknown): boolean {
  return (
    typeof err === "object" &&
    err !== null &&
    "status_code" in err &&
    (err as { status_code: number }).status_code === 404
  );
}
