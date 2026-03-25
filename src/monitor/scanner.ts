/**
 * Beacon UTXO scanner — core of subscription change detection.
 *
 * Queries Koios for all UTXOs carrying beacon tokens, parses their inline
 * datums, and returns a diff against the previously known state.
 *
 * Removal is guarded by a two-phase confirmation process:
 *   1. Known beacons are only checked for removal every VERIFY_INTERVAL
 *      (2h prod / 1min testing). Regular 30s scans ignore absent beacons.
 *   2. When a beacon is absent during verification, it enters a pending
 *      removal state.  It must be absent for CONFIRM_COUNT consecutive
 *      checks at CONFIRM_INTERVAL (2min prod / 10s testing) before the
 *      scanner emits a REMOVED event.
 *   3. If the beacon reappears in any scan (including regular discovery
 *      scans between confirmations), the pending removal is cancelled.
 */

import type { CardanoProvider } from "cmttk";
import type { CardanoNetwork } from "../cardano/types.js";
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

// ── Testing mode ─────────────────────────────────────────────────────────────

import * as fs from "fs";
const _testingMode = fs.existsSync("/etc/blockhost/.testing-mode");

// ── Removal confirmation intervals ──────────────────────────────────────────
//
// Known beacons are only checked for removal during periodic verification
// passes, not every poll.  When absent, multiple consecutive confirmations
// are required before the scanner emits REMOVED.

/** How often to check known beacons for removal (2h prod / 1min testing) */
const VERIFY_INTERVAL_MS = _testingMode ? 60_000 : 2 * 60 * 60 * 1000;

/** Minimum gap between consecutive confirmation checks (2min prod / 10s testing) */
const CONFIRM_INTERVAL_MS = _testingMode ? 10_000 : 2 * 60 * 1000;

/** Consecutive absent checks required before emitting REMOVED */
const CONFIRM_COUNT = 3;

// ── In-memory state ──────────────────────────────────────────────────────────

/** Map of beacon name → subscription, representing the last-known chain state */
const knownSubscriptions = new Map<string, TrackedSubscription>();

/** Beacons absent during verification, pending confirmed removal */
const pendingRemovals = new Map<string, {
  firstMissAt: number;
  lastCheckAt: number;
  missCount: number;
}>();

/** Timestamp of last verification pass */
let lastVerifyAt = 0;

/** Load known beacon names from vms.json on startup to prevent re-provisioning */
let _stateLoaded = false;
function loadKnownBeacons(): void {
  if (_stateLoaded) return;
  _stateLoaded = true;
  try {
    const dbPath = process.env["BLOCKHOST_STATE_DIR"]
      ? `${process.env["BLOCKHOST_STATE_DIR"]}/vms.json`
      : "/var/lib/blockhost/vms.json";
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
  provider: CardanoProvider,
  beaconPolicyId: string,
  koiosUrl?: string,
  network?: CardanoNetwork,
): Promise<ScanDiff> {
  // Restore known beacons from vms.json on first run
  loadKnownBeacons();

  // ── Fetch current UTXOs by scanning for beacon tokens ──────────────────
  // Subscriptions live at CIP-89 addresses (per-subscriber), so we can't
  // query a single address. Instead, find all addresses holding beacon tokens
  // via Koios policy_asset_addresses, then fetch UTXOs from each.
  //
  // NOTE: We use a direct fetch for policy_asset_addresses because the
  // cmttk provider only has fetchAssetAddresses (specific asset), not
  // policy-wide discovery. UTxO fetching uses the provider normally.

  const defaultKoiosUrl = network === "mainnet"
    ? "https://api.koios.rest/api/v1"
    : network === "preview"
      ? "https://preview.koios.rest/api/v1"
      : "https://preprod.koios.rest/api/v1";
  const baseUrl = koiosUrl || defaultKoiosUrl;

  let holders: Array<{ payment_address: string }> = [];
  try {
    const res = await fetch(`${baseUrl}/policy_asset_addresses`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ _asset_policy: beaconPolicyId }),
    });
    if (res.ok) {
      holders = (await res.json()) as Array<{ payment_address: string }>;
    }
  } catch {
    return { created: [], removed: [], extended: [] };
  }

  const uniqueAddresses = [...new Set(holders.map(h => h.payment_address))];

  const utxos: BlockfrostUtxo[] = [];
  for (const addr of uniqueAddresses) {
    try {
      const raw = await provider.fetchUtxos(addr) as Array<Record<string, unknown>>;

      for (const u of raw) {
        // Normalize response format (Koios vs Blockfrost)
        const assetList = u["asset_list"] as Array<Record<string, string>> | undefined;
        const bfAmount = Array.isArray(u["amount"]) ? u["amount"] as Array<{ unit: string; quantity: string }> : [];
        const amount = [{ unit: "lovelace", quantity: String(u["value"] ?? bfAmount.find(a => a.unit === "lovelace")?.quantity ?? "0") }];
        if (assetList) {
          for (const a of assetList) {
            amount.push({ unit: (a["policy_id"] ?? "") + (a["asset_name"] ?? ""), quantity: a["quantity"] ?? "0" });
          }
        } else if (Array.isArray(u["amount"])) {
          // Blockfrost format
          for (const a of u["amount"] as Array<{ unit: string; quantity: string }>) {
            if (a.unit !== "lovelace") amount.push(a);
          }
        }

        // Extract inline datum (Koios wraps in {bytes, value}, Blockfrost is direct)
        const rawDatum = u["inline_datum"] as Record<string, unknown> | null;
        const inlineDatum = rawDatum
          ? ("value" in rawDatum ? rawDatum["value"] as PlutusValue : rawDatum as unknown as PlutusValue)
          : null;

        const bfUtxo: BlockfrostUtxo = {
          tx_hash: (u["tx_hash"] ?? u["tx_id"]) as string,
          tx_index: Number(u["tx_index"] ?? u["output_index"] ?? 0),
          amount,
          inline_datum: inlineDatum,
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
  const now = Date.now();
  const isVerifyTime = now - lastVerifyAt >= VERIFY_INTERVAL_MS;

  // Detect created and extended
  for (const [name, current] of currentBeacons) {
    const known = knownSubscriptions.get(name);
    if (!known) {
      diff.created.push(current);
    } else if (known.utxoRef !== current.utxoRef) {
      diff.extended.push({ old: known, new: current });
    }

    // Beacon is present — cancel any pending removal
    if (pendingRemovals.has(name)) {
      console.log(`[SCANNER] Beacon ${name.slice(0, 16)}… reappeared — cancelling pending removal`);
      pendingRemovals.delete(name);
    }
  }

  // Check known beacons that are absent from this scan
  for (const [name, known] of knownSubscriptions) {
    if (currentBeacons.has(name)) continue;

    const pending = pendingRemovals.get(name);

    if (!pending) {
      // Not yet pending — only start tracking during verification passes
      if (isVerifyTime) {
        console.log(`[SCANNER] Beacon ${name.slice(0, 16)}… absent during verification — starting confirmation (1/${CONFIRM_COUNT})`);
        pendingRemovals.set(name, { firstMissAt: now, lastCheckAt: now, missCount: 1 });
      }
      // Between verifications: ignore the absence
    } else if (now - pending.lastCheckAt >= CONFIRM_INTERVAL_MS) {
      // Already pending — enough time for the next confirmation check
      pending.missCount++;
      pending.lastCheckAt = now;

      if (pending.missCount >= CONFIRM_COUNT) {
        console.log(`[SCANNER] Beacon ${name.slice(0, 16)}… confirmed removed after ${pending.missCount} checks`);
        diff.removed.push(known);
        pendingRemovals.delete(name);
      } else {
        console.log(`[SCANNER] Beacon ${name.slice(0, 16)}… still absent (${pending.missCount}/${CONFIRM_COUNT})`);
      }
    }
    // else: pending but too soon for next confirmation — wait
  }

  if (isVerifyTime) {
    lastVerifyAt = now;
  }

  // ── Persist new state ────────────────────────────────────────────────────
  // Start with beacons found on chain
  const newKnown = new Map<string, TrackedSubscription>();
  for (const [name, sub] of currentBeacons) {
    newKnown.set(name, sub);
  }
  // Preserve beacons that are pending removal (absent but unconfirmed)
  for (const [name] of pendingRemovals) {
    if (!newKnown.has(name)) {
      const old = knownSubscriptions.get(name);
      if (old) newKnown.set(name, old);
    }
  }

  knownSubscriptions.clear();
  for (const [name, sub] of newKnown) {
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
//     creationHeight : Int          → { int: N }
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
    // Expect at least 11 fields (10 original + creation_height)
    if (!f || f.length < 11) return null;

    const [f0, f1, f2, f3, f4, f5, f6, f7, f8, f9, f10] = f as [
      PlutusValue, PlutusValue, PlutusValue, PlutusValue, PlutusValue,
      PlutusValue, PlutusValue, PlutusValue, PlutusValue, PlutusValue,
      PlutusValue,
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

    const creationHeight = bigIntField(f10);
    if (creationHeight === null) return null;

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
      creationHeight,
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

