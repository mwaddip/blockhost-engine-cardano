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

import { Constr, Data, applyParamsToScript } from "@lucid-evolution/lucid";
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
      expirySlot: f[1] as bigint,
      subscriber: f[2] as string,
      amountRemaining: f[3] as bigint,
      ratePerInterval: f[4] as bigint,
      intervalSlots: f[5] as bigint,
      lastCollectedSlot: f[6] as bigint,
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
    datum.expirySlot,
    datum.subscriber,
    datum.amountRemaining,
    datum.ratePerInterval,
    datum.intervalSlots,
    datum.lastCollectedSlot,
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

function analyzeClaimable(
  utxo: UTxO,
  currentSlot: bigint,
): ClaimableInfo | null {
  if (!utxo.datum) return null;
  const datum = decodeSubscriptionDatum(utxo.datum);
  if (!datum) return null;

  // Expired subscriptions can't be collected via ServiceCollect
  if (currentSlot >= datum.expirySlot) return null;

  // How many full intervals since last collection?
  const elapsed = currentSlot - datum.lastCollectedSlot;
  if (elapsed < datum.intervalSlots) return null; // not yet claimable

  const intervals = elapsed / datum.intervalSlots;
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

  // Build the validator address from config
  const validatorAddr = web3.subscriptionValidatorAddress;
  if (!validatorAddr) {
    throw new Error(
      "blockchain.subscription_validator_address not set in web3-defaults.yaml",
    );
  }

  // Query UTXOs at the validator address
  console.error(`Querying UTXOs at ${validatorAddr.slice(0, 30)}...`);
  const utxos = await lucid.utxosAt(validatorAddr);
  console.error(`Found ${utxos.length} UTXOs at validator address`);

  if (utxos.length === 0) {
    console.log("No subscription UTXOs found.");
    return;
  }

  // Analyze claimability
  const currentSlot = BigInt(lucid.currentSlot());
  const claimable: ClaimableInfo[] = [];

  for (const utxo of utxos) {
    const info = analyzeClaimable(utxo, currentSlot);
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

  // Apply parameters to the subscription validator:
  // subscription.subscription.spend takes (server_key_hash, service_address_key_hash)
  // We need the server's payment key hash from the signer address
  const { getAddressDetails } = await import("@lucid-evolution/lucid");
  const signerDetails = getAddressDetails(signerAddr);
  const serverKeyHash = signerDetails.paymentCredential?.hash;
  if (!serverKeyHash) {
    throw new Error("Could not extract payment key hash from signer address");
  }

  // service_address_key_hash is also the server's key hash (same signer)
  const parameterizedSubscription = applyParamsToScript(
    scripts.subscriptionCompiledCode,
    [serverKeyHash, serverKeyHash],
  );

  const subscriptionValidator = {
    type: "PlutusV3" as const,
    script: parameterizedSubscription,
  };

  // Parameterize beacon policy: beacon.beacon.mint takes (subscription_validator_hash)
  const parameterizedBeacon = applyParamsToScript(
    scripts.beaconCompiledCode,
    [web3.subscriptionValidatorHash],
  );

  const beaconPolicy = {
    type: "PlutusV3" as const,
    script: parameterizedBeacon,
  };

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

  // Set validity range — current slot minus some slack to current slot plus some slack
  const now = Date.now();
  tx = tx.validFrom(now - 60_000).validTo(now + 600_000);

  // Add signer
  tx = tx.addSignerKey(serverKeyHash);

  for (const info of batch) {
    // Spend the script UTXO with ServiceCollect redeemer
    tx = tx.collectFrom([info.utxo], serviceCollectRedeemer);

    totalCollected += info.collectAmount;

    if (info.fullyConsumed) {
      // Burn the beacon token for this subscription
      // Beacon asset name is the UTXO tx hash + output index (or similar)
      // For now, look for beacon tokens in the UTXO's assets
      const beaconPolicyId = web3.beaconPolicyId;
      for (const [unit, qty] of Object.entries(info.utxo.assets)) {
        if (unit.startsWith(beaconPolicyId) && qty > 0n) {
          const existing = beaconBurns[unit] ?? 0n;
          beaconBurns[unit] = existing - qty; // negative = burn
          hasBeaconBurns = true;
        }
      }
      // No continuing output needed — subscription is consumed
    } else {
      // Create continuing output with updated datum
      const updatedDatum: SubscriptionDatum = {
        ...info.datum,
        amountRemaining: info.datum.amountRemaining - info.collectAmount,
        lastCollectedSlot:
          info.datum.lastCollectedSlot +
          info.intervals * info.datum.intervalSlots,
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

      tx = tx.pay.ToAddressWithData(
        validatorAddr,
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
