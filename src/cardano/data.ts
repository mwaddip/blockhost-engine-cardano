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
} from "./cbor.js";

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

/** Read CBOR argument value at pos (after initial byte). Returns [argVal, newPos]. */
function readCborArg(bytes: Uint8Array, pos: number, additional: number): [bigint, number] {
  if (additional < 24) return [BigInt(additional), pos];
  if (additional === 24) return [BigInt(bytes[pos]!), pos + 1];
  if (additional === 25) {
    return [BigInt((bytes[pos]! << 8) | bytes[pos + 1]!), pos + 2];
  }
  if (additional === 26) {
    return [BigInt(((bytes[pos]! << 24) | (bytes[pos + 1]! << 16) | (bytes[pos + 2]! << 8) | bytes[pos + 3]!) >>> 0), pos + 4];
  }
  if (additional === 27) {
    let v = 0n;
    for (let i = 0; i < 8; i++) v = (v << 8n) | BigInt(bytes[pos + i]!);
    return [v, pos + 8];
  }
  if (additional === 31) return [-1n, pos]; // indefinite
  throw new Error("CBOR: unsupported additional " + additional);
}

/**
 * Decode a CBOR Plutus Data value. Fully recursive — preserves Constr tags
 * through nested arrays, maps, etc. Does NOT delegate to the generic decodeCbor.
 */
function decodeField(bytes: Uint8Array, pos: number): { value: PlutusField; offset: number } {
  const initial = bytes[pos]!;
  const major = initial >> 5;
  const additional = initial & 0x1f;
  pos++;

  const [argVal, argEnd] = readCborArg(bytes, pos, additional);
  pos = argEnd;

  switch (major) {
    case 0: // unsigned int
      return { value: argVal, offset: pos };
    case 1: // negative int
      return { value: -1n - argVal, offset: pos };
    case 2: { // byte string → hex
      const len = Number(argVal);
      const val = bytesToHex(bytes.slice(pos, pos + len));
      return { value: val, offset: pos + len };
    }
    case 3: { // text string
      const len = Number(argVal);
      const val = new TextDecoder().decode(bytes.slice(pos, pos + len));
      return { value: val, offset: pos + len };
    }
    case 4: { // array — decode children with decodeField (preserves Constr)
      const arr: PlutusField[] = [];
      if (argVal < 0n) {
        while (bytes[pos] !== 0xff) {
          const item = decodeField(bytes, pos);
          arr.push(item.value);
          pos = item.offset;
        }
        pos++; // skip break
      } else {
        for (let i = 0; i < Number(argVal); i++) {
          const item = decodeField(bytes, pos);
          arr.push(item.value);
          pos = item.offset;
        }
      }
      return { value: arr, offset: pos };
    }
    case 5: { // map
      const map = new Map<PlutusField, PlutusField>();
      if (argVal < 0n) {
        while (bytes[pos] !== 0xff) {
          const k = decodeField(bytes, pos);
          const v = decodeField(bytes, k.offset);
          map.set(k.value, v.value);
          pos = v.offset;
        }
        pos++;
      } else {
        for (let i = 0; i < Number(argVal); i++) {
          const k = decodeField(bytes, pos);
          const v = decodeField(bytes, k.offset);
          map.set(k.value, v.value);
          pos = v.offset;
        }
      }
      return { value: map, offset: pos };
    }
    case 6: { // tag — Constr encoding
      if (argVal >= 121n && argVal <= 127n) {
        // Constr 0-6: tag content is the fields array
        const inner = decodeField(bytes, pos);
        const fields = inner.value as PlutusField[];
        return { value: new Constr(Number(argVal) - 121, fields), offset: inner.offset };
      }
      if (argVal === 102n) {
        // Constr 7+: content is [index, fields]
        const inner = decodeField(bytes, pos);
        const arr = inner.value as PlutusField[];
        const index = Number(arr[0] as bigint);
        const fields = arr[1] as PlutusField[];
        return { value: new Constr(index, fields), offset: inner.offset };
      }
      // Unknown tag — decode content and return as-is
      const inner = decodeField(bytes, pos);
      return { value: inner.value, offset: inner.offset };
    }
    case 7: { // simple values
      if (argVal === 20n) return { value: 0n, offset: pos }; // false
      if (argVal === 21n) return { value: 1n, offset: pos }; // true
      if (argVal === 22n) return { value: 0n, offset: pos }; // null
      return { value: BigInt(Number(argVal)), offset: pos };
    }
    default:
      throw new Error("CBOR: unsupported major type " + major);
  }
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
