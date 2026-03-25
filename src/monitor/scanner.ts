/**
 * Beacon UTXO scanner — core of subscription change detection.
 *
 * Queries Blockfrost for all UTXOs at the subscription validator address,
 * filters for those carrying a beacon token under the beacon policy, parses
 * their inline datums, and returns a diff against the previously known state.
 */

import { BlockFrostAPI } from "../cardano/provider.js";
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

/** Load known beacon names from vms.json on startup to prevent re-provisioning */
let _stateLoaded = false;
function loadKnownBeacons(): void {
  if (_stateLoaded) return;
  _stateLoaded = true;
  try {
    const dbPath = process.env["BLOCKHOST_STATE_DIR"]
      ? `${process.env["BLOCKHOST_STATE_DIR"]}/vms.json`
      : "/var/lib/blockhost/vms.json";
    const fs = require("fs") as typeof import("fs");
    if (!fs.existsSync(dbPath)) return;
    const db = JSON.parse(fs.readFileSync(dbPath, "utf8"));
    const vms = db.vms ?? {};
    for (const [, vm] of Object.entries(vms)) {
      const entry = vm as Record<string, unknown>;
      const beaconName = entry["beacon_name"] as string | undefined;
      if (beaconName) {
        // Insert a placeholder to mark this beacon as already processed
        knownSubscriptions.set(beaconName, {
          utxoRef: entry["utxo_ref"] as string ?? "restored",
          beaconName,
          datum: {} as any,
          utxo: null,
          firstSeen: 0,
        });
      }
    }
    if (knownSubscriptions.size > 0) {
      console.log(`[SCANNER] Restored ${knownSubscriptions.size} known beacon(s) from vms.json`);
    }
  } catch {
    // vms.json not readable — start fresh
  }
}

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
  _client: BlockFrostAPI,
  _validatorAddress: string,
  beaconPolicyId: string,
  network: string = "preprod",
): Promise<ScanDiff> {
  // Restore known beacons from vms.json on first run
  loadKnownBeacons();

  // ── Fetch current UTXOs by scanning for beacon tokens ──────────────────
  // Subscriptions live at CIP-89 addresses (per-subscriber), so we can't
  // query a single address. Instead, find all addresses holding beacon tokens
  // via Koios, then fetch UTXOs from each.
  const koiosUrl = network === "mainnet"
    ? "https://api.koios.rest/api/v1"
    : network === "preview"
      ? "https://preview.koios.rest/api/v1"
      : "https://preprod.koios.rest/api/v1";

  let holders: Array<{ payment_address: string }> = [];
  try {
    const res = await fetch(`${koiosUrl}/policy_asset_addresses`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ _asset_policy: beaconPolicyId }),
    });
    if (res.ok) {
      holders = (await res.json()) as Array<{ payment_address: string }>;
    }
  } catch {
    // Koios unavailable — return empty diff
    return { created: [], removed: [], extended: [] };
  }

  const uniqueAddresses = [...new Set(holders.map(h => h.payment_address))];

  const utxos: BlockfrostUtxo[] = [];
  for (const addr of uniqueAddresses) {
    try {
      // Use Koios directly (same as holder query) instead of Blockfrost client
      const res = await fetch(`${koiosUrl}/address_utxos`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ _addresses: [addr], _extended: true }),
      });
      if (!res.ok) continue;
      const raw = (await res.json()) as Array<Record<string, unknown>>;

      // Convert Koios format to Blockfrost-like format for downstream compatibility
      for (const u of raw) {
        const assetList = u["asset_list"] as Array<Record<string, string>> | undefined;
        const amount = [{ unit: "lovelace", quantity: String(u["value"] ?? "0") }];
        if (assetList) {
          for (const a of assetList) {
            amount.push({ unit: (a["policy_id"] ?? "") + (a["asset_name"] ?? ""), quantity: a["quantity"] ?? "0" });
          }
        }
        // Koios inline_datum has { bytes, value } — the scanner expects the value part
        const koiosDatum = u["inline_datum"] as Record<string, unknown> | undefined;
        const inlineDatum = koiosDatum?.["value"] as PlutusValue | undefined;
        const bfUtxo: BlockfrostUtxo = {
          tx_hash: u["tx_hash"] as string,
          tx_index: Number(u["tx_index"] ?? 0),
          amount,
          inline_datum: inlineDatum ?? null,
        };
        const hasBeacon = amount.some(
          (a) => a.unit.startsWith(beaconPolicyId) && a.unit.length > 56,
        );
        if (hasBeacon) utxos.push(bfUtxo);
      }
    } catch {
      // Address unavailable — skip
    }
  }

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
//     expiry         : Int          → { int: N }  (POSIX ms)
//     subscriber     : Bytes        → { bytes: hex }  (bech32 payment key hash)
//     amountRemaining: Int          → { int: N }
//     ratePerInterval: Int          → { int: N }
//     intervalMs     : Int          → { int: N }  (POSIX ms)
//     lastCollected  : Int          → { int: N }  (POSIX ms)
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
    // Expect at least 10 fields (updated datum with interval-based collection)
    if (!f || f.length < 10) return null;

    const [f0, f1, f2, f3, f4, f5, f6, f7, f8, f9] = f as [
      PlutusValue, PlutusValue, PlutusValue, PlutusValue, PlutusValue,
      PlutusValue, PlutusValue, PlutusValue, PlutusValue, PlutusValue,
    ];

    const planId = intField(f0);
    if (planId === null) return null;

    const expiry = bigIntField(f1);
    if (expiry === null) return null;

    const subscriber = bytesField(f2);
    if (subscriber === null) return null;

    const amountRemaining = bigIntField(f3);
    if (amountRemaining === null) return null;

    const ratePerInterval = bigIntField(f4);
    if (ratePerInterval === null) return null;

    const intervalMs = bigIntField(f5);
    if (intervalMs === null) return null;

    const lastCollected = bigIntField(f6);
    if (lastCollected === null) return null;

    // paymentAsset is Constr 0 [ policyId: Bytes, assetName: Bytes ]
    if (!isConstr(f7) || f7.constructor !== 0 || f7.fields.length < 2) return null;
    const policyId = bytesField(f7.fields[0] as PlutusValue);
    const assetName = bytesField(f7.fields[1] as PlutusValue);
    if (policyId === null || assetName === null) return null;

    const beaconId = bytesField(f8);
    if (beaconId === null) return null;

    const userEncrypted = bytesField(f9);
    if (userEncrypted === null) return null;

    return {
      planId: Number(planId),
      expiry,
      subscriber,
      amountRemaining,
      ratePerInterval,
      intervalMs,
      lastCollected,
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

