/**
 * Beacon UTXO scanner — core of subscription change detection.
 *
 * Queries Blockfrost for all UTXOs at the subscription validator address,
 * filters for those carrying a beacon token under the beacon policy, parses
 * their inline datums, and returns a diff against the previously known state.
 */

import { BlockFrostAPI } from "@blockfrost/blockfrost-js";
import type { SubscriptionDatum } from "../cardano/types.js";

// ── Types ────────────────────────────────────────────────────────────────────

/** Represents a known subscription UTXO */
export interface TrackedSubscription {
  /** UTXO tx hash + output index, e.g. "abc123#0" */
  utxoRef: string;
  /** Beacon token asset name (hex), i.e. everything after the 56-char policy ID */
  beaconName: string;
  /** Parsed datum */
  datum: SubscriptionDatum;
  /** Raw UTXO object from Blockfrost (typed as unknown — callers cast as needed) */
  utxo: unknown;
  /** Unix ms timestamp when this UTXO was first observed */
  firstSeen: number;
}

/** What changed between two consecutive scans */
export interface ScanDiff {
  /** New subscription UTXOs — beacon appeared for the first time */
  created: TrackedSubscription[];
  /** UTXOs that disappeared — beacon burned (collected or cancelled) */
  removed: TrackedSubscription[];
  /** Same beacon, different UTXO ref — subscriber extended via spend-and-recreate */
  extended: { old: TrackedSubscription; new: TrackedSubscription }[];
}

// ── Plutus inline datum shapes returned by Blockfrost ────────────────────────
//
// Blockfrost encodes inline datums as JSON-decoded Plutus data, not raw CBOR.
// A constructor term looks like: { "constructor": N, "fields": [...] }
// A primitive integer looks like: { "int": N }
// A primitive bytestring looks like: { "bytes": "hexstring" }

interface PlutusConstr {
  constructor: number;
  fields: PlutusValue[];
}

type PlutusValue =
  | PlutusConstr
  | { int: number | string }
  | { bytes: string }
  | { list: PlutusValue[] }
  | { map: { k: PlutusValue; v: PlutusValue }[] };

// ── In-memory state ──────────────────────────────────────────────────────────

/** Map of beacon name → subscription, representing the last-known chain state */
const knownSubscriptions = new Map<string, TrackedSubscription>();

// ── Blockfrost UTXO shape (partial — only fields we use) ─────────────────────

interface BlockfrostUtxo {
  tx_hash: string;
  tx_index: number;
  amount: { unit: string; quantity: string }[];
  inline_datum: PlutusValue | null;
}

// ── Public API ───────────────────────────────────────────────────────────────

/**
 * Scan for beacon token UTXOs at the subscription validator address.
 *
 * Queries all UTXOs at the address, filters to those carrying a token under
 * `beaconPolicyId`, parses their inline datums, and returns the diff against
 * the known state.  Updates the known state in-place before returning.
 */
export async function scanBeacons(
  client: BlockFrostAPI,
  validatorAddress: string,
  beaconPolicyId: string,
): Promise<ScanDiff> {
  // ── Fetch current UTXOs from Blockfrost ──────────────────────────────────
  let raw: unknown[];
  try {
    raw = await client.addressesUtxosAll(validatorAddress);
  } catch (err: unknown) {
    if (isBlockfrost404(err)) {
      raw = [];
    } else {
      throw err;
    }
  }

  const utxos = raw as BlockfrostUtxo[];

  // ── Build current beacon map ─────────────────────────────────────────────
  const currentBeacons = new Map<string, TrackedSubscription>();

  for (const utxo of utxos) {
    // A Blockfrost UTXO may carry several assets; we care about beacon tokens.
    const beaconAssets = (utxo.amount ?? []).filter(
      (a) => a.unit.startsWith(beaconPolicyId) && a.unit.length > 56,
    );

    if (beaconAssets.length === 0) continue;

    for (const asset of beaconAssets) {
      const beaconName = asset.unit.slice(56); // hex chars after the 56-char policy ID
      const utxoRef = `${utxo.tx_hash}#${utxo.tx_index}`;

      const datum = parseDatumFromUtxo(utxo);
      if (!datum) {
        console.warn(
          `[SCANNER] Skipping beacon ${beaconName} at ${utxoRef}: datum missing or unparseable`,
        );
        continue;
      }

      // If we've already seen this beacon in this scan (edge case: two UTXOs
      // carry the same beacon name), keep the first one we encounter.
      if (!currentBeacons.has(beaconName)) {
        currentBeacons.set(beaconName, {
          utxoRef,
          beaconName,
          datum,
          utxo,
          firstSeen:
            knownSubscriptions.get(beaconName)?.firstSeen ?? Date.now(),
        });
      }
    }
  }

  // ── Compute diff ─────────────────────────────────────────────────────────
  const diff: ScanDiff = { created: [], removed: [], extended: [] };

  for (const [name, current] of currentBeacons) {
    const known = knownSubscriptions.get(name);
    if (!known) {
      // New beacon we haven't seen before
      diff.created.push(current);
    } else if (known.utxoRef !== current.utxoRef) {
      // Same beacon token, different UTXO → subscriber extended (spend+recreate)
      diff.extended.push({ old: known, new: current });
    }
    // Same beacon, same UTXO ref → nothing changed; skip
  }

  for (const [name, known] of knownSubscriptions) {
    if (!currentBeacons.has(name)) {
      diff.removed.push(known);
    }
  }

  // ── Persist new state ────────────────────────────────────────────────────
  knownSubscriptions.clear();
  for (const [name, sub] of currentBeacons) {
    knownSubscriptions.set(name, sub);
  }

  return diff;
}

/** Return a snapshot of the current known subscriptions (used by reconciler) */
export function getKnownSubscriptions(): Map<string, TrackedSubscription> {
  return new Map(knownSubscriptions);
}

// ── Datum parsing ─────────────────────────────────────────────────────────────
//
// Blockfrost returns inline_datum as a JSON-decoded Plutus data tree.
// Our SubscriptionDatum validator is a constructor 0 record with fields in the
// order they appear in the Aiken type definition:
//
//   Constr 0 [
//     planId         : Int          → { int: N }
//     expiry         : Int          → { int: N }  (PosixTime ms)
//     subscriber     : Bytes        → { bytes: hex }  (bech32 payment key hash)
//     amountPaid     : Int          → { int: N }
//     paymentAsset   : Constr 0 [ policyId: Bytes, assetName: Bytes ]
//     beaconId       : Bytes        → { bytes: hex }
//     userEncrypted  : Bytes        → { bytes: hex }
//   ]
//
// If Blockfrost returns inline_datum as null (datum is referenced by hash, not
// inlined), we cannot parse it here and return null to skip the UTXO.

function parseDatumFromUtxo(utxo: BlockfrostUtxo): SubscriptionDatum | null {
  const raw = utxo.inline_datum;
  if (!raw) return null;

  try {
    // Top-level must be constructor 0
    if (!isConstr(raw) || raw.constructor !== 0) return null;

    const f = raw.fields;
    // Expect at least 7 fields
    if (!f || f.length < 7) return null;

    const [f0, f1, f2, f3, f4, f5, f6] = f as [
      PlutusValue, PlutusValue, PlutusValue, PlutusValue,
      PlutusValue, PlutusValue, PlutusValue,
    ];

    const planId = intField(f0);
    if (planId === null) return null;

    const expiry = bigIntField(f1);
    if (expiry === null) return null;

    const subscriber = bytesField(f2);
    if (subscriber === null) return null;

    const amountPaid = bigIntField(f3);
    if (amountPaid === null) return null;

    // paymentAsset is Constr 0 [ policyId: Bytes, assetName: Bytes ]
    if (!isConstr(f4) || f4.constructor !== 0 || f4.fields.length < 2) return null;
    const policyId = bytesField(f4.fields[0] as PlutusValue);
    const assetName = bytesField(f4.fields[1] as PlutusValue);
    if (policyId === null || assetName === null) return null;

    const beaconId = bytesField(f5);
    if (beaconId === null) return null;

    const userEncrypted = bytesField(f6);
    if (userEncrypted === null) return null;

    return {
      planId: Number(planId),
      expiry,
      subscriber,
      amountPaid,
      paymentAsset: { policyId, assetName },
      beaconId,
      userEncrypted,
    };
  } catch {
    return null;
  }
}

// ── Plutus field accessors ────────────────────────────────────────────────────

function isConstr(v: PlutusValue): v is PlutusConstr {
  return typeof v === "object" && v !== null && "constructor" in v;
}

function intField(v: PlutusValue): number | null {
  if (typeof v === "object" && v !== null && "int" in v) {
    const n = Number(v.int);
    return Number.isFinite(n) ? n : null;
  }
  return null;
}

function bigIntField(v: PlutusValue): bigint | null {
  if (typeof v === "object" && v !== null && "int" in v) {
    try {
      return BigInt(v.int);
    } catch {
      return null;
    }
  }
  return null;
}

function bytesField(v: PlutusValue): string | null {
  if (typeof v === "object" && v !== null && "bytes" in v) {
    return typeof v.bytes === "string" ? v.bytes : null;
  }
  return null;
}

// ── Utility ───────────────────────────────────────────────────────────────────

function isBlockfrost404(err: unknown): boolean {
  return (
    typeof err === "object" &&
    err !== null &&
    "status_code" in err &&
    (err as { status_code: number }).status_code === 404
  );
}
