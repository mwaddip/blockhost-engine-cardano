/**
 * SubscriptionDatum codec — single source of truth for the on-chain schema.
 *
 * Two input shapes hit the engine:
 *   - CBOR hex (Koios `inline_datum.bytes` and any cmttk-built datum)
 *     decoded via cmttk's Data.from
 *   - JSON Plutus tree (Blockfrost / Koios `inline_datum.value`)
 *     a constructor term as { constructor: N, fields: [...] }
 *
 * Both decoders share one schema layout:
 *
 *   Constr 0 [
 *     0  planId          : Int
 *     1  expiry          : Int                            (POSIX ms)
 *     2  subscriber      : Bytes                          (28-byte payment key hash)
 *     3  amountRemaining : Int
 *     4  ratePerInterval : Int
 *     5  intervalMs      : Int                            (POSIX ms)
 *     6  lastCollected   : Int                            (POSIX ms)
 *     7  paymentAsset    : Constr 0 [ Bytes, Bytes ]      (policyId, assetName)
 *     8  beaconId        : Bytes
 *     9  userEncrypted   : Bytes
 *    10  creationHeight  : Int                            (block height salt)
 *   ]
 *
 * encodeSubscriptionDatum produces the CBOR hex form for continuing-output
 * datums (used during withdrawal).
 */

import { Constr, Data } from "@mwaddip/cmttk";
import type { SubscriptionDatum } from "./types.js";

// ── Plutus JSON tree shape (Blockfrost / Koios decoded) ─────────────────────

export interface PlutusConstr {
  constructor: number;
  fields: PlutusValue[];
}

export type PlutusValue =
  | PlutusConstr
  | { int: number | string }
  | { bytes: string }
  | { list: PlutusValue[] }
  | { map: { k: PlutusValue; v: PlutusValue }[] };

// ── Decode: CBOR hex ─────────────────────────────────────────────────────────

/**
 * Decode a SubscriptionDatum from CBOR hex.
 * Returns null on malformed input or schema mismatch.
 */
export function decodeSubscriptionDatumFromCbor(
  cborHex: string,
): SubscriptionDatum | null {
  try {
    const d = Data.from(cborHex);
    if (!(d instanceof Constr) || d.index !== 0 || d.fields.length < 11) {
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
      creationHeight: f[10] as bigint,
    };
  } catch {
    return null;
  }
}

// ── Decode: JSON Plutus tree ────────────────────────────────────────────────

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

/**
 * Decode a SubscriptionDatum from a JSON-decoded Plutus tree.
 * Returns null on malformed input or schema mismatch.
 */
export function decodeSubscriptionDatumFromPlutus(
  raw: PlutusValue,
): SubscriptionDatum | null {
  try {
    if (!isConstr(raw) || raw.constructor !== 0) return null;

    const f = raw.fields;
    if (!f || f.length < 11) return null;

    const f0 = f[0]!, f1 = f[1]!, f2 = f[2]!, f3 = f[3]!, f4 = f[4]!;
    const f5 = f[5]!, f6 = f[6]!, f7 = f[7]!, f8 = f[8]!, f9 = f[9]!, f10 = f[10]!;

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

    if (!isConstr(f7) || f7.constructor !== 0 || f7.fields.length < 2) return null;
    const policyId = bytesField(f7.fields[0]!);
    const assetName = bytesField(f7.fields[1]!);
    if (policyId === null || assetName === null) return null;

    const beaconId = bytesField(f8);
    if (beaconId === null) return null;

    const userEncrypted = bytesField(f9);
    if (userEncrypted === null) return null;

    const creationHeight = bigIntField(f10);
    if (creationHeight === null) return null;

    return {
      planId,
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

// ── Encode: CBOR hex ─────────────────────────────────────────────────────────

/**
 * Encode a SubscriptionDatum to CBOR hex (for continuing-output datums).
 */
export function encodeSubscriptionDatum(datum: SubscriptionDatum): string {
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
    datum.creationHeight,
  ]);
  return Data.to(d);
}
