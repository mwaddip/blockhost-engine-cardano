/**
 * Plutus Data encoding/decoding — replaces Lucid's Constr and Data.to/Data.from.
 *
 * Constr tag mapping (CIP-0005 / Plutus):
 *   - Constr 0-6  → CBOR tags 121-127
 *   - Constr 7+   → CBOR tag 102 + [index, fields]
 *
 * Field values are recursively encoded:
 *   - bigint → CBOR int (positive or negative)
 *   - string → CBOR bytes (hex string treated as raw bytes)
 *   - Uint8Array → CBOR bytes
 *   - Constr → recursive Plutus Data
 *   - Array → CBOR list of Plutus Data items
 */

import {
  cborHeader,
  cborUint,
  cborBytes,
  cborArray,
  cborMap,
  cborTag,
  hexToBytes,
  bytesToHex,
  decodeCbor,
} from "./cbor.js";
import type { CborValue } from "./cbor.js";

// ── Constr ──────────────────────────────────────────────────────────────────

/** Plutus Data constructor — matches Lucid's Constr API. */
export class Constr<T = PlutusField> {
  readonly index: number;
  readonly fields: T[];

  constructor(index: number, fields: T[]) {
    this.index = index;
    this.fields = fields;
  }
}

/** Allowed field types in Plutus Data. */
export type PlutusField =
  | bigint
  | number
  | string        // hex-encoded bytes
  | Uint8Array
  | Constr<PlutusField>
  | PlutusField[]
  | Map<PlutusField, PlutusField>;

// ── Encode ──────────────────────────────────────────────────────────────────

/** Encode a Plutus Data value to CBOR bytes. */
function encodeField(field: PlutusField): Uint8Array {
  if (field instanceof Constr) {
    return encodeConstr(field);
  }
  if (field instanceof Uint8Array) {
    return cborBytes(field);
  }
  if (Array.isArray(field)) {
    return cborArray(field.map(encodeField));
  }
  if (field instanceof Map) {
    const entries: [Uint8Array, Uint8Array][] = [];
    for (const [k, v] of field) {
      entries.push([encodeField(k), encodeField(v)]);
    }
    return cborMap(entries);
  }
  if (typeof field === "bigint") {
    if (field >= 0n) return cborUint(field);
    // Negative: CBOR major 1, value = -1 - n
    return cborHeader(1, -field - 1n);
  }
  if (typeof field === "number") {
    return encodeField(BigInt(field));
  }
  if (typeof field === "string") {
    // Hex string → bytes
    return cborBytes(hexToBytes(field));
  }
  throw new Error(`Unsupported Plutus Data field type: ${typeof field}`);
}

/** Encode a Constr to CBOR with the correct tag. */
function encodeConstr(constr: Constr<PlutusField>): Uint8Array {
  const fieldsCbor = cborArray(constr.fields.map(encodeField));

  if (constr.index >= 0 && constr.index <= 6) {
    // Tags 121-127
    return cborTag(121 + constr.index, fieldsCbor);
  }
  // Tag 102 + [index, fields]
  return cborTag(102, cborArray([cborUint(BigInt(constr.index)), fieldsCbor]));
}

// ── Decode ──────────────────────────────────────────────────────────────────

/** Decode a CBOR Plutus Data value back into Constr / bigint / string / etc. */
function decodeField(bytes: Uint8Array, pos: number): { value: PlutusField; offset: number } {
  const initial = bytes[pos]!;
  const major = initial >> 5;
  const additional = initial & 0x1f;

  // Check for tag (major 6) first — Constr encoding
  if (major === 6) {
    // Peek at tag number
    let tagNum: number;
    let tagEnd: number;
    if (additional < 24) {
      tagNum = additional;
      tagEnd = pos + 1;
    } else if (additional === 24) {
      tagNum = bytes[pos + 1]!;
      tagEnd = pos + 2;
    } else {
      // Larger tag — fall through to generic decoder
      const raw = decodeCbor(bytes, pos);
      return { value: cborToPlutus(raw.value), offset: raw.offset };
    }

    if (tagNum >= 121 && tagNum <= 127) {
      // Constr 0-6
      const inner = decodeCbor(bytes, tagEnd);
      const fields = (inner.value as CborValue[]).map(cborToPlutus);
      return { value: new Constr(tagNum - 121, fields), offset: inner.offset };
    }
    if (tagNum === 102) {
      // Constr 7+: [index, fields]
      const inner = decodeCbor(bytes, tagEnd);
      const arr = inner.value as CborValue[];
      const index = Number(arr[0] as bigint);
      const fields = (arr[1] as CborValue[]).map(cborToPlutus);
      return { value: new Constr(index, fields), offset: inner.offset };
    }

    // Unknown tag — decode generically
    const decoded = decodeCbor(bytes, pos);
    return { value: cborToPlutus(decoded.value), offset: decoded.offset };
  }

  // Non-tag: use generic decoder
  const decoded = decodeCbor(bytes, pos);
  return { value: cborToPlutus(decoded.value), offset: decoded.offset };
}

/** Convert a generic CBOR decoded value to a Plutus field. */
function cborToPlutus(value: CborValue): PlutusField {
  if (typeof value === "bigint") return value;
  if (value instanceof Uint8Array) return bytesToHex(value);
  if (Array.isArray(value)) return value.map(cborToPlutus);
  if (value instanceof Map) {
    const m = new Map<PlutusField, PlutusField>();
    for (const [k, v] of value) {
      m.set(cborToPlutus(k), cborToPlutus(v));
    }
    return m;
  }
  if (typeof value === "number") return BigInt(value);
  if (value === null || value === undefined) return 0n;
  if (typeof value === "boolean") return value ? 1n : 0n;
  throw new Error(`Unexpected CBOR value in Plutus Data: ${typeof value}`);
}

// ── Public API (matches Lucid's Data) ───────────────────────────────────────

export const Data = {
  /** Encode a Plutus Data value (Constr, bigint, hex string, etc.) to CBOR hex. */
  to(value: PlutusField): string {
    return bytesToHex(encodeField(value));
  },

  /** Decode CBOR hex back to Plutus Data. */
  from(cborHex: string): PlutusField {
    const bytes = hexToBytes(cborHex);
    const { value } = decodeField(bytes, 0);
    return value;
  },
};

/** Convert a UTF-8 string to hex — replaces Lucid's fromText(). */
export function fromText(text: string): string {
  return Buffer.from(text, "utf8").toString("hex");
}
