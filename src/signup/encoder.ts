/**
 * Pure Plutus Data encoding for the subscription flow.
 * DOM-free — importable from Node tests and the browser bundle alike.
 *
 * CBOR primitives come from cmttk/cbor. Constr-array encoding is intentionally
 * indefinite-length (0x9f..0xff) for non-empty field lists to match the
 * signup-engine.js byte-for-byte. cmttk's built-in Data.to uses definite-length
 * arrays, so we keep the Constr helper local.
 */

import {
    hexToBytes,
    bytesToHex,
    concatBytes,
    cborHeader,
    cborUint,
    cborArray,
    cborTag,
} from "@mwaddip/cmttk/cbor";

/** CBOR byte string with Plutus chunking (indefinite-length if > 64 bytes). */
export function cborBytesChunked(bytes: Uint8Array | string): Uint8Array {
    const b = typeof bytes === "string" ? hexToBytes(bytes) : bytes;
    if (b.length <= 64) {
        return concatBytes([cborHeader(2, b.length), b]);
    }
    const parts: Uint8Array[] = [new Uint8Array([0x5f])];
    let offset = 0;
    while (offset < b.length) {
        const chunkLen = Math.min(64, b.length - offset);
        const chunk = b.slice(offset, offset + chunkLen);
        parts.push(concatBytes([cborHeader(2, chunkLen), chunk]));
        offset += chunkLen;
    }
    parts.push(new Uint8Array([0xff]));
    return concatBytes(parts);
}

/** CBOR negative integer (major 1). */
export function cborNint(n: number | bigint): Uint8Array {
    const v = typeof n === "bigint" ? n : BigInt(n);
    return cborHeader(1, -v - 1n);
}

/** CBOR signed integer (dispatches on sign). */
export function cborInt(n: number | bigint): Uint8Array {
    const v = typeof n === "bigint" ? n : BigInt(n);
    return v >= 0n ? cborUint(v) : cborNint(v);
}

/** CBOR indefinite-length array: 0x9f + items + 0xff. */
export function cborArrayIndef(items: Uint8Array[]): Uint8Array {
    const parts: Uint8Array[] = [new Uint8Array([0x9f])];
    for (let i = 0; i < items.length; i++) parts.push(items[i]!);
    parts.push(new Uint8Array([0xff]));
    return concatBytes(parts);
}

/** Plutus Constr(index, fields).
 *  Empty fields → definite empty array 0x80.
 *  Non-empty fields → indefinite array 0x9f..0xff (matches Lucid/CSL wire format). */
export function plutusConstr(index: number, fieldsCbor: Uint8Array[]): Uint8Array {
    const arr = fieldsCbor.length === 0 ? cborArray([]) : cborArrayIndef(fieldsCbor);
    if (index <= 6) return cborTag(121 + index, arr);
    return cborTag(102, cborArray([cborUint(index), arr]));
}

export interface SubscriptionDatumFields {
    planId: number;
    expiry: bigint;
    subscriberKeyHash: string;
    amountRemaining: bigint;
    ratePerInterval: bigint;
    intervalMs: bigint;
    lastCollected: bigint;
    payPolicyId: string;
    payAssetName: string;
    beaconPolicyId: string;
    userEncrypted: string;
    creationHeight: number;
}

/**
 * Encode a SubscriptionDatum as Plutus Data CBOR hex.
 *
 * Constr(0, [plan_id, expiry, subscriber_key_hash, amount_remaining,
 *            rate_per_interval, interval_ms, last_collected,
 *            Constr(0, [policy_id, asset_name]),
 *            beacon_policy_id, user_encrypted, creation_height])
 */
export function encodePlutusSubscriptionDatum(d: SubscriptionDatumFields): string {
    const paymentAsset = plutusConstr(0, [
        cborBytesChunked(d.payPolicyId),
        cborBytesChunked(d.payAssetName),
    ]);

    const fields = [
        cborInt(d.planId),
        cborInt(d.expiry),
        cborBytesChunked(d.subscriberKeyHash),
        cborInt(d.amountRemaining),
        cborInt(d.ratePerInterval),
        cborInt(d.intervalMs),
        cborInt(d.lastCollected),
        paymentAsset,
        cborBytesChunked(d.beaconPolicyId),
        cborBytesChunked(d.userEncrypted),
        cborInt(d.creationHeight),
    ];

    return bytesToHex(plutusConstr(0, fields));
}

export { hexToBytes, bytesToHex };
