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
 * Uses the minimal tx toolkit (src/cardano/) — no Lucid.
 * Core function executeWithdraw() is used by fund-manager.
 */

import type { Addressbook } from "../../fund-manager/types.js";
import type { SubscriptionDatum } from "../../cardano/types.js";
import { resolveAddress } from "../cli-utils.js";
import { loadWeb3Config } from "../../fund-manager/web3-config.js";
import { getProvider } from "../../cardano/provider.js";
import { deriveWallet } from "../../cardano/wallet.js";
import { getPaymentKeyHash } from "../../cardano/address.js";
import { Constr, Data } from "../../cardano/data.js";
import {
  parseKoiosUtxos,
  buildAndSubmitScriptTx,
} from "../../cardano/tx.js";
import type { Utxo, ScriptInput, TxOutput, MintEntry, Assets } from "../../cardano/tx.js";
import * as fs from "fs";

const CONFIG_DIR = process.env["BLOCKHOST_CONFIG_DIR"] ?? "/etc/blockhost";
const PLUTUS_JSON_PATH = `${CONFIG_DIR}/plutus.json`;
const MAX_BATCH = 15; // max UTXOs per transaction to stay within limits

// ── Datum codec ──────────────────────────────────────────────────────────────

/**
 * Decode a SubscriptionDatum from CBOR hex (inline datum).
 */
function decodeSubscriptionDatum(cborHex: string): SubscriptionDatum | null {
  try {
    const d = Data.from(cborHex);
    if (!(d instanceof Constr) || d.index !== 0 || d.fields.length < 10) {
      return null;
    }
    const f = d.fields;
    const paymentAssetConstr = f[7] as Constr;
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
 * Encode a SubscriptionDatum to CBOR hex for the continuing output.
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
  utxo: Utxo;
  address: string;
  datum: SubscriptionDatum;
  intervals: bigint;
  collectAmount: bigint;
  fullyConsumed: boolean;
}

/**
 * Analyze a subscription UTXO for claimability.
 */
function analyzeClaimable(
  utxo: Utxo,
  address: string,
  datumCbor: string | undefined,
  validFromMs: bigint,
): ClaimableInfo | null {
  if (!datumCbor) return null;
  const datum = decodeSubscriptionDatum(datumCbor);
  if (!datum) return null;

  if (datum.amountRemaining <= 0n) return null;

  const elapsed = validFromMs - datum.lastCollected;
  if (elapsed < datum.intervalMs) return null;

  const intervals = elapsed / datum.intervalMs;
  let collectAmount = intervals * datum.ratePerInterval;

  const fullyConsumed = collectAmount >= datum.amountRemaining;
  if (fullyConsumed) {
    collectAmount = datum.amountRemaining;
  }

  return { utxo, address, datum, intervals, collectAmount, fullyConsumed };
}

// ── Load validator script ────────────────────────────────────────────────────

interface ValidatorInfo {
  subscriptionCompiledCode: string;
  beaconCompiledCode: string;
}

function loadValidatorScripts(): ValidatorInfo {
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
 */
export async function executeWithdraw(
  toRole: string,
  book: Addressbook,
): Promise<void> {
  const toAddress = resolveAddress(toRole, book);
  const web3 = loadWeb3Config();

  // Determine signing role
  const signingRole =
    book["server"]?.keyfile
      ? "server"
      : Object.entries(book).find(([, e]) => e.keyfile)?.[0];
  if (!signingRole) throw new Error("No signing wallet available in addressbook");

  const signerEntry = book[signingRole]!;
  const mnemonic = fs.readFileSync(signerEntry.keyfile!, "utf8").trim();
  const wallet = await deriveWallet(mnemonic, web3.network);
  const provider = getProvider(web3.network, web3.blockfrostProjectId);

  const serverKeyHash = getPaymentKeyHash(wallet.address);
  if (!serverKeyHash) throw new Error("Could not extract payment key hash from signer address");

  // Find subscription UTXOs by scanning for beacon tokens
  const beaconPolicyId = web3.beaconPolicyId;
  console.error(`Scanning for beacon tokens (policy: ${beaconPolicyId.slice(0, 16)}...)...`);

  let beaconAddresses: string[] = [];
  try {
    const holders = await provider.fetchAssetAddresses(beaconPolicyId);
    beaconAddresses = [...new Set(holders.map(h => h.address))];
  } catch {
    console.error("Failed to query beacon holders");
    return;
  }

  if (beaconAddresses.length === 0) {
    console.log("No subscription UTXOs found (no beacon tokens on-chain).");
    return;
  }
  console.error(`Found beacons at ${beaconAddresses.length} address(es)`);

  // Fetch UTXOs at each beacon address
  const allUtxos: Array<{ utxo: Utxo; address: string; datumCbor?: string }> = [];
  for (const addr of beaconAddresses) {
    try {
      const rawUtxos = await provider.fetchUtxos(addr);
      const parsed = parseKoiosUtxos(rawUtxos);
      for (let i = 0; i < parsed.length; i++) {
        const u = parsed[i]!;
        const hasBeacon = Object.keys(u.tokens).some(unit => unit.startsWith(beaconPolicyId));
        if (hasBeacon) {
          // Extract inline datum from Koios response
          const rawEntry = (rawUtxos as Array<Record<string, unknown>>)[i];
          const inlineDatum = rawEntry?.["inline_datum"] as Record<string, string> | undefined;
          allUtxos.push({
            utxo: u,
            address: addr,
            datumCbor: inlineDatum?.["bytes"] ?? inlineDatum?.["value"] as string | undefined,
          });
        }
      }
    } catch {
      // Address might not have UTXOs anymore
    }
  }
  console.error(`Found ${allUtxos.length} subscription UTXOs with beacons`);

  if (allUtxos.length === 0) {
    console.log("No subscription UTXOs found.");
    return;
  }

  // Analyze claimability
  const validFromMs = BigInt(Date.now()) - 15_000n;
  const claimable: ClaimableInfo[] = [];
  for (const entry of allUtxos) {
    const info = analyzeClaimable(entry.utxo, entry.address, entry.datumCbor, validFromMs);
    if (info) claimable.push(info);
  }

  if (claimable.length === 0) {
    console.log("No claimable subscription UTXOs at this time.");
    return;
  }
  console.error(`${claimable.length} claimable UTXOs (processing up to ${MAX_BATCH})`);

  const batch = claimable.slice(0, MAX_BATCH);
  const scripts = loadValidatorScripts();

  // Build redeemers
  const serviceCollectRedeemer = Data.to(new Constr(0, []));
  const closeSubRedeemer = Data.to(new Constr(1, []));

  // Build script inputs and outputs
  const scriptInputs: ScriptInput[] = [];
  const outputs: TxOutput[] = [];
  let totalCollected = 0n;
  const beaconBurns: Record<string, bigint> = {};
  let hasBeaconBurns = false;

  for (const info of batch) {
    scriptInputs.push({
      utxo: info.utxo,
      address: info.address,
      redeemerCbor: serviceCollectRedeemer,
    });

    totalCollected += info.collectAmount;

    // Continuing output with updated datum
    const updatedDatum: SubscriptionDatum = {
      ...info.datum,
      amountRemaining: info.datum.amountRemaining - info.collectAmount,
      lastCollected: info.datum.lastCollected + info.intervals * info.datum.intervalMs,
    };
    const datumCbor = encodeSubscriptionDatum(updatedDatum);

    const isAdaPayment =
      updatedDatum.paymentAsset.policyId === "" &&
      updatedDatum.paymentAsset.assetName === "";

    const continuingAssets: Assets = { lovelace: 0n };

    // Copy beacon tokens from input
    for (const [unit, qty] of Object.entries(info.utxo.tokens)) {
      if (unit.startsWith(web3.beaconPolicyId)) {
        continuingAssets[unit] = qty;
      }
    }

    if (isAdaPayment) {
      continuingAssets.lovelace = info.utxo.lovelace - info.collectAmount;
    } else {
      continuingAssets.lovelace = 2_000_000n;
      const payUnit = updatedDatum.paymentAsset.policyId + updatedDatum.paymentAsset.assetName;
      const inputTokenAmount = info.utxo.tokens[payUnit] ?? 0n;
      continuingAssets[payUnit] = inputTokenAmount - info.collectAmount;
    }

    outputs.push({
      address: info.address,
      assets: continuingAssets,
      datumCbor,
    });
  }

  // Send collected funds to recipient (if different from signer)
  if (toAddress !== wallet.address) {
    const firstInfo = batch[0];
    if (firstInfo) {
      const isAdaPayment =
        firstInfo.datum.paymentAsset.policyId === "" &&
        firstInfo.datum.paymentAsset.assetName === "";

      if (isAdaPayment) {
        outputs.push({ address: toAddress, assets: { lovelace: totalCollected } });
      } else {
        const payUnit = firstInfo.datum.paymentAsset.policyId + firstInfo.datum.paymentAsset.assetName;
        outputs.push({
          address: toAddress,
          assets: { lovelace: 2_000_000n, [payUnit]: totalCollected },
        });
      }
    }
  }

  // Mint entries (beacon burns for fully consumed subscriptions)
  const mintEntries: MintEntry[] = [];
  if (hasBeaconBurns) {
    mintEntries.push({
      policyId: beaconPolicyId,
      assets: beaconBurns,
      redeemerCbor: closeSubRedeemer,
      scriptCbor: scripts.beaconCompiledCode,
    });
  }

  // Submit
  try {
    const txHash = await buildAndSubmitScriptTx({
      provider,
      walletAddress: wallet.address,
      scriptInputs,
      outputs,
      mints: mintEntries.length > 0 ? mintEntries : undefined,
      spendingScriptCbor: scripts.subscriptionCompiledCode,
      validFrom: Number(validFromMs),
      validTo: Date.now() + 600_000,
      requiredSigners: [serverKeyHash],
      signingKey: new Uint8Array([...wallet.paymentKey]),
    });

    console.log(txHash);
    console.error(`Collected from ${batch.length} UTXOs, total: ${totalCollected.toString()} base units`);
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    console.error(`Transaction failed: ${msg}`);
    console.error("Claimable UTXOs that were attempted:");
    for (const info of batch) {
      console.error(
        `  ${info.utxo.txHash}#${info.utxo.index}: ` +
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
