/**
 * bw withdraw <to>
 *
 * Batch-collect mature subscription UTXOs from the validator script.
 *
 * Queries subscription UTXOs at the validator address, identifies those
 * that are claimable (enough slots have elapsed since last_collected_slot),
 * and builds a single transaction that:
 *   - Spends each claimable UTXO with ServiceCollect redeemer
 *   - Creates continuing outputs with updated datums (reduced amount_remaining)
 *   - Burns beacon tokens for fully consumed subscriptions
 *   - Sends collected funds to the specified recipient
 *
 * Uses Lucid Evolution for transaction building and submission.
 * Core function executeWithdraw() is used by fund-manager.
 */

import { Constr, Data } from "@lucid-evolution/lucid";
import type { UTxO } from "@lucid-evolution/lucid";
import type { Addressbook } from "../../fund-manager/types.js";
import type { SubscriptionDatum } from "../../cardano/types.js";
import { resolveAddress } from "../cli-utils.js";
import { initLucidWithWallet } from "../lucid-helpers.js";
import { loadWeb3Config } from "../../fund-manager/web3-config.js";
import * as fs from "fs";

const CONFIG_DIR = process.env["BLOCKHOST_CONFIG_DIR"] ?? "/etc/blockhost";
const PLUTUS_JSON_PATH = `${CONFIG_DIR}/plutus.json`;
const MAX_BATCH = 15; // max UTXOs per transaction to stay within limits

// ── Datum codec ──────────────────────────────────────────────────────────────

/**
 * Decode a SubscriptionDatum from CBOR (inline datum).
 * Aiken Constr(0, [plan_id, expiry_slot, subscriber_key_hash, amount_remaining,
 *   rate_per_interval, interval_slots, last_collected_slot,
 *   Constr(0, [policy_id, asset_name]), beacon_policy_id, user_encrypted])
 */
function decodeSubscriptionDatum(cborHex: string): SubscriptionDatum | null {
  try {
    const d = Data.from(cborHex) as Constr<
      bigint | string | Constr<string>
    >;
    if (!(d instanceof Constr) || d.index !== 0 || d.fields.length < 10) {
      return null;
    }
    const f = d.fields;
    const paymentAssetConstr = f[7] as Constr<string>;
    return {
      planId: Number(f[0] as bigint),
      expiry: f[1] as bigint,
      subscriber: f[2] as string,
      amountRemaining: f[3] as bigint,
      ratePerInterval: f[4] as bigint,
      intervalMs: f[5] as bigint,
      lastCollected: f[6] as bigint,
      paymentAsset: {
        policyId: paymentAssetConstr.fields[0] as string,
        assetName: paymentAssetConstr.fields[1] as string,
      },
      beaconId: f[8] as string,
      userEncrypted: f[9] as string,
    };
  } catch {
    return null;
  }
}

/**
 * Encode a SubscriptionDatum back to CBOR hex for the continuing output.
 */
function encodeSubscriptionDatum(datum: SubscriptionDatum): string {
  const d = new Constr(0, [
    BigInt(datum.planId),
    datum.expiry,
    datum.subscriber,
    datum.amountRemaining,
    datum.ratePerInterval,
    datum.intervalMs,
    datum.lastCollected,
    new Constr(0, [datum.paymentAsset.policyId, datum.paymentAsset.assetName]),
    datum.beaconId,
    datum.userEncrypted,
  ]);
  return Data.to(d);
}

// ── Claimability logic ───────────────────────────────────────────────────────

interface ClaimableInfo {
  utxo: UTxO;
  datum: SubscriptionDatum;
  /** Number of full intervals elapsed since last collection */
  intervals: bigint;
  /** Amount to collect this cycle */
  collectAmount: bigint;
  /** Whether this collection fully exhausts the subscription */
  fullyConsumed: boolean;
}

/**
 * Analyze a subscription UTXO for claimability.
 * @param validFromMs POSIX ms that will be used as tx validFrom (= what the validator sees as tx_lower_bound)
 */
function analyzeClaimable(
  utxo: UTxO,
  validFromMs: bigint,
): ClaimableInfo | null {
  if (!utxo.datum) return null;
  const datum = decodeSubscriptionDatum(utxo.datum);
  if (!datum) return null;

  // Skip fully consumed subscriptions (nothing left to collect)
  if (datum.amountRemaining <= 0n) return null;

  // How many full intervals since last collection?
  const elapsed = validFromMs - datum.lastCollected;
  if (elapsed < datum.intervalMs) return null; // not yet claimable

  const intervals = elapsed / datum.intervalMs;
  let collectAmount = intervals * datum.ratePerInterval;

  // Cap at amount remaining
  const fullyConsumed = collectAmount >= datum.amountRemaining;
  if (fullyConsumed) {
    collectAmount = datum.amountRemaining;
  }

  return { utxo, datum, intervals, collectAmount, fullyConsumed };
}

// ── Load validator script ────────────────────────────────────────────────────

interface ValidatorInfo {
  subscriptionCompiledCode: string;
  beaconCompiledCode: string;
}

function loadValidatorScripts(): ValidatorInfo {
  // Try project-local plutus.json first, fall back to config dir
  let plutusPath = "plutus.json";
  if (!fs.existsSync(plutusPath)) {
    plutusPath = PLUTUS_JSON_PATH;
  }
  if (!fs.existsSync(plutusPath)) {
    throw new Error(
      `plutus.json not found — run 'aiken build' or place it at ${PLUTUS_JSON_PATH}`,
    );
  }

  const plutus = JSON.parse(fs.readFileSync(plutusPath, "utf8")) as {
    validators: Array<{ title: string; compiledCode: string }>;
  };

  const sub = plutus.validators.find(
    (v) => v.title === "subscription.subscription.spend",
  );
  const beacon = plutus.validators.find(
    (v) => v.title === "beacon.beacon.mint",
  );

  if (!sub) throw new Error("subscription.subscription.spend not found in plutus.json");
  if (!beacon) throw new Error("beacon.beacon.mint not found in plutus.json");

  return {
    subscriptionCompiledCode: sub.compiledCode,
    beaconCompiledCode: beacon.compiledCode,
  };
}

// ── Core withdraw ────────────────────────────────────────────────────────────

/**
 * Core withdraw operation — used by both CLI and fund-manager.
 *
 * @param toRole  Addressbook role or bech32 address to receive collected funds
 * @param book    Addressbook
 */
export async function executeWithdraw(
  toRole: string,
  book: Addressbook,
): Promise<void> {
  const toAddress = resolveAddress(toRole, book);
  const web3 = loadWeb3Config();

  // Determine which role to sign with — prefer "server", fall back to first with keyfile
  const signingRole =
    book["server"]?.keyfile
      ? "server"
      : Object.entries(book).find(([, e]) => e.keyfile)?.[0];
  if (!signingRole) {
    throw new Error("No signing wallet available in addressbook");
  }

  const lucid = await initLucidWithWallet(signingRole, book);
  const signerAddr = await lucid.wallet().address();

  // Find subscription UTXOs by scanning for beacon tokens.
  // Subscriptions live at CIP-89 addresses (script payment + subscriber staking),
  // so there's no single address to query. Instead we find all UTXOs holding
  // any token under the beacon policy.
  const beaconPolicyId = web3.beaconPolicyId;
  console.error(`Scanning for beacon tokens (policy: ${beaconPolicyId.slice(0, 16)}...)...`);

  // Query for all addresses holding beacon policy tokens via the configured provider
  // Find all addresses holding any token under the beacon policy via Koios
  let beaconAddresses: string[] = [];
  try {
    // Try fetching all assets under the beacon policy
    const koiosUrl = web3.network === "mainnet"
      ? "https://api.koios.rest/api/v1"
      : web3.network === "preview"
        ? "https://preview.koios.rest/api/v1"
        : "https://preprod.koios.rest/api/v1";

    const holders = await fetch(`${koiosUrl}/policy_asset_addresses`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ _asset_policy: beaconPolicyId }),
    }).then(r => r.json() as Promise<Array<{ payment_address: string }>>);

    beaconAddresses = [...new Set((holders || []).map(h => h.payment_address))];
  } catch {
    console.error("Failed to query beacon holders");
    return;
  }

  if (beaconAddresses.length === 0) {
    console.log("No subscription UTXOs found (no beacon tokens on-chain).");
    return;
  }

  console.error(`Found beacons at ${beaconAddresses.length} address(es)`);

  const utxos: UTxO[] = [];
  for (const addr of beaconAddresses) {
    try {
      const addrUtxos = await lucid.utxosAt(addr);
      for (const u of addrUtxos) {
        const hasBeacon = Object.keys(u.assets).some(unit => unit.startsWith(beaconPolicyId));
        if (hasBeacon) utxos.push(u);
      }
    } catch {
      // Address might not have UTXOs anymore
    }
  }
  console.error(`Found ${utxos.length} subscription UTXOs with beacons`);

  if (utxos.length === 0) {
    console.log("No subscription UTXOs found.");
    return;
  }

  // Analyze claimability using a validFrom time 15s in the past.
  // This same value will be used for the tx's validFrom — the validator
  // sees it as tx_lower_bound and uses it for interval calculation.
  const validFromMs = BigInt(Date.now()) - 15_000n;
  const claimable: ClaimableInfo[] = [];

  for (const utxo of utxos) {
    const info = analyzeClaimable(utxo, validFromMs);
    if (info) claimable.push(info);
  }

  if (claimable.length === 0) {
    console.log("No claimable subscription UTXOs at this time.");
    return;
  }

  console.error(
    `${claimable.length} claimable UTXOs (processing up to ${MAX_BATCH})`,
  );

  // Take a batch
  const batch = claimable.slice(0, MAX_BATCH);

  // Load validator scripts and apply parameters
  const scripts = loadValidatorScripts();

  // The blueprint (plutus.json) has params already applied via `aiken blueprint apply`.
  // Use compiledCode directly — do NOT re-apply params.
  const subscriptionValidator = {
    type: "PlutusV3" as const,
    script: scripts.subscriptionCompiledCode,
  };

  const beaconPolicy = {
    type: "PlutusV3" as const,
    script: scripts.beaconCompiledCode,
  };

  // Get server key hash for addSignerKey
  const { getAddressDetails } = await import("@lucid-evolution/lucid");
  const signerDetails = getAddressDetails(signerAddr);
  const serverKeyHash = signerDetails.paymentCredential?.hash;
  if (!serverKeyHash) {
    throw new Error("Could not extract payment key hash from signer address");
  }

  // Build redeemer for ServiceCollect (Constr index 0, no fields)
  const serviceCollectRedeemer = Data.to(new Constr(0, []));
  // CloseSubscription redeemer (Constr index 1, no fields)
  const closeSubRedeemer = Data.to(new Constr(1, []));

  // Build the transaction
  let tx = lucid.newTx();

  // Attach validator and beacon policy scripts
  tx = tx.attach.SpendingValidator(subscriptionValidator);

  let totalCollected = 0n;
  let beaconBurns: Record<string, bigint> = {};
  let hasBeaconBurns = false;

  // Set validity range — validFromMs must match what we used for interval calculations
  tx = tx.validFrom(Number(validFromMs)).validTo(Date.now() + 600_000);

  // Add signer
  tx = tx.addSignerKey(serverKeyHash);

  for (const info of batch) {
    // Spend the script UTXO with ServiceCollect redeemer
    tx = tx.collectFrom([info.utxo], serviceCollectRedeemer);

    totalCollected += info.collectAmount;

    // Always create a continuing output (even for fully consumed subscriptions).
    // The validator's ServiceCollect path requires a continuing output with
    // updated datum. For fully consumed subscriptions, amount_remaining = 0.
    {
      // Create continuing output with updated datum
      const updatedDatum: SubscriptionDatum = {
        ...info.datum,
        amountRemaining: info.datum.amountRemaining - info.collectAmount,
        lastCollected:
          info.datum.lastCollected +
          info.intervals * info.datum.intervalMs,
      };

      const datumCbor = encodeSubscriptionDatum(updatedDatum);

      // The continuing output must have the same payment asset locked
      const isAdaPayment =
        updatedDatum.paymentAsset.policyId === "" &&
        updatedDatum.paymentAsset.assetName === "";

      // Compute continuing output assets — keep beacon token + remaining payment
      const continuingAssets: Record<string, bigint> = {};

      // Copy beacon tokens from input
      for (const [unit, qty] of Object.entries(info.utxo.assets)) {
        if (unit.startsWith(web3.beaconPolicyId)) {
          continuingAssets[unit] = qty;
        }
      }

      if (isAdaPayment) {
        // The lovelace in the continuing output should be reduced by collectAmount
        const inputLovelace = info.utxo.assets["lovelace"] ?? 0n;
        continuingAssets["lovelace"] =
          inputLovelace - info.collectAmount;
      } else {
        // Keep min ADA and reduce the payment token
        continuingAssets["lovelace"] = 2_000_000n;
        const payUnit =
          updatedDatum.paymentAsset.policyId +
          updatedDatum.paymentAsset.assetName;
        const inputTokenAmount = info.utxo.assets[payUnit] ?? 0n;
        continuingAssets[payUnit] = inputTokenAmount - info.collectAmount;
      }

      // Continue to the same CIP-89 address (subscriber's script address)
      tx = tx.pay.ToAddressWithData(
        info.utxo.address,
        { kind: "inline", value: datumCbor },
        continuingAssets,
      );
    }
  }

  // Mint (burn) beacon tokens if any subscriptions are fully consumed
  if (hasBeaconBurns) {
    tx = tx.attach.MintingPolicy(beaconPolicy);
    tx = tx.mintAssets(beaconBurns, closeSubRedeemer);
  }

  // Send collected funds to recipient
  // For simplicity, the collected funds automatically flow to the change address
  // unless the recipient is different from the signer
  if (toAddress !== signerAddr) {
    // Determine what token we collected (use the first batch item's payment asset)
    const firstInfo = batch[0];
    if (firstInfo) {
      const isAdaPayment =
        firstInfo.datum.paymentAsset.policyId === "" &&
        firstInfo.datum.paymentAsset.assetName === "";

      if (isAdaPayment) {
        tx = tx.pay.ToAddress(toAddress, { lovelace: totalCollected });
      } else {
        const payUnit =
          firstInfo.datum.paymentAsset.policyId +
          firstInfo.datum.paymentAsset.assetName;
        tx = tx.pay.ToAddress(toAddress, {
          lovelace: 2_000_000n,
          [payUnit]: totalCollected,
        });
      }
    }
  }

  // Complete, sign, submit
  try {
    const completed = await tx.complete();
    const signed = await completed.sign.withWallet().complete();
    const txHash = await signed.submit();
    console.log(txHash);
    console.error(
      `Collected from ${batch.length} UTXOs, total: ${totalCollected.toString()} base units`,
    );
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    console.error(`Transaction failed: ${msg}`);
    console.error("Claimable UTXOs that were attempted:");
    for (const info of batch) {
      console.error(
        `  ${info.utxo.txHash}#${info.utxo.outputIndex}: ` +
          `collect=${info.collectAmount.toString()} ` +
          `(${info.fullyConsumed ? "fully consumed" : "partial"})`,
      );
    }
    throw new Error(`withdraw transaction failed: ${msg}`);
  }
}

/**
 * CLI handler
 */
export async function withdrawCommand(
  args: string[],
  book: Addressbook,
): Promise<void> {
  if (args.length < 1) {
    console.error("Usage: bw withdraw <to>");
    console.error("  Example: bw withdraw admin");
    process.exit(1);
  }

  const [toRole] = args;
  if (!toRole) {
    console.error("Usage: bw withdraw <to>");
    process.exit(1);
  }

  await executeWithdraw(toRole, book);
}
