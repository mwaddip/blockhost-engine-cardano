/**
 * Minimal CBOR encoder/decoder for Cardano transactions.
 * Extracted from signup-engine.js — production-tested.
 */

// ── Byte helpers ────────────────────────────────────────────────────────────

export function hexToBytes(hex: string): Uint8Array {
  hex = hex.replace(/^0x/, "");
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(hex.substring(i * 2, i * 2 + 2), 16);
  }
  return out;
}

export function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

export function concatBytes(arrays: Uint8Array[]): Uint8Array {
  let total = 0;
  for (const a of arrays) total += a.length;
  const result = new Uint8Array(total);
  let offset = 0;
  for (const a of arrays) {
    result.set(a, offset);
    offset += a.length;
  }
  return result;
}

// ── CBOR encoder ────────────────────────────────────────────────────────────

/** Encode a CBOR header (major type + argument). */
export function cborHeader(major: number, n: number | bigint): Uint8Array {
  const mt = major << 5;
  const v = typeof n === "bigint" ? n : BigInt(n);
  if (v < 0n) throw new Error("cborHeader: negative value");
  if (v < 24n) return new Uint8Array([mt | Number(v)]);
  if (v < 256n) return new Uint8Array([mt | 24, Number(v)]);
  if (v < 65536n) {
    const b = new Uint8Array(3);
    b[0] = mt | 25;
    b[1] = Number((v >> 8n) & 0xffn);
    b[2] = Number(v & 0xffn);
    return b;
  }
  if (v < 4294967296n) {
    const b = new Uint8Array(5);
    b[0] = mt | 26;
    b[1] = Number((v >> 24n) & 0xffn);
    b[2] = Number((v >> 16n) & 0xffn);
    b[3] = Number((v >> 8n) & 0xffn);
    b[4] = Number(v & 0xffn);
    return b;
  }
  const b = new Uint8Array(9);
  b[0] = mt | 27;
  for (let i = 7; i >= 0; i--) {
    b[8 - i] = Number((v >> BigInt(i * 8)) & 0xffn);
  }
  return b;
}

/** Unsigned integer (major 0). */
export function cborUint(n: number | bigint): Uint8Array {
  return cborHeader(0, n);
}

/** Byte string (major 2), definite-length. */
export function cborBytes(data: Uint8Array | string): Uint8Array {
  const bytes = typeof data === "string" ? hexToBytes(data) : data;
  return concatBytes([cborHeader(2, bytes.length), bytes]);
}

/** Array (major 4). Items must already be encoded. */
export function cborArray(items: Uint8Array[]): Uint8Array {
  return concatBytes([cborHeader(4, items.length), ...items]);
}

/** Map (major 5). Entries are [key, value] pairs, already encoded. */
export function cborMap(entries: [Uint8Array, Uint8Array][]): Uint8Array {
  const parts: Uint8Array[] = [cborHeader(5, entries.length)];
  for (const [k, v] of entries) {
    parts.push(k, v);
  }
  return concatBytes(parts);
}

/** Tag (major 6). */
export function cborTag(tagNum: number, content: Uint8Array): Uint8Array {
  return concatBytes([cborHeader(6, tagNum), content]);
}

// ── CBOR decoder ────────────────────────────────────────────────────────────

export type CborValue =
  | bigint
  | boolean
  | null
  | undefined
  | string
  | number
  | Uint8Array
  | CborValue[]
  | Map<CborValue, CborValue>;

export interface CborDecoded {
  value: CborValue;
  offset: number;
}

/** Decode a single CBOR item starting at `pos`. */
export function decodeCbor(bytes: Uint8Array, pos: number): CborDecoded {
  if (pos >= bytes.length) throw new Error("CBOR: unexpected end");
  const initial = bytes[pos]!;
  const major = initial >> 5;
  const additional = initial & 0x1f;
  pos++;

  let argVal: bigint;
  if (additional < 24) {
    argVal = BigInt(additional);
  } else if (additional === 24) {
    argVal = BigInt(bytes[pos++]!);
  } else if (additional === 25) {
    argVal = BigInt((bytes[pos]! << 8) | bytes[pos + 1]!);
    pos += 2;
  } else if (additional === 26) {
    argVal = BigInt(
      ((bytes[pos]! << 24) | (bytes[pos + 1]! << 16) | (bytes[pos + 2]! << 8) | bytes[pos + 3]!) >>> 0,
    );
    pos += 4;
  } else if (additional === 27) {
    argVal = 0n;
    for (let i = 0; i < 8; i++) {
      argVal = (argVal << 8n) | BigInt(bytes[pos + i]!);
    }
    pos += 8;
  } else if (additional === 31) {
    argVal = -1n; // indefinite
  } else {
    throw new Error("CBOR: unsupported additional " + additional);
  }

  switch (major) {
    case 0:
      return { value: argVal, offset: pos };
    case 1:
      return { value: -1n - argVal, offset: pos };
    case 2: {
      if (argVal < 0n) throw new Error("CBOR: indefinite byte strings unsupported");
      const len = Number(argVal);
      return { value: bytes.slice(pos, pos + len), offset: pos + len };
    }
    case 3: {
      if (argVal < 0n) throw new Error("CBOR: indefinite text strings unsupported");
      const tlen = Number(argVal);
      return { value: new TextDecoder().decode(bytes.slice(pos, pos + tlen)), offset: pos + tlen };
    }
    case 4: {
      const arr: CborValue[] = [];
      if (argVal < 0n) {
        while (bytes[pos] !== 0xff) {
          const item = decodeCbor(bytes, pos);
          arr.push(item.value);
          pos = item.offset;
        }
        pos++;
      } else {
        const count = Number(argVal);
        for (let i = 0; i < count; i++) {
          const item = decodeCbor(bytes, pos);
          arr.push(item.value);
          pos = item.offset;
        }
      }
      return { value: arr, offset: pos };
    }
    case 5: {
      const map = new Map<CborValue, CborValue>();
      if (argVal < 0n) {
        while (bytes[pos] !== 0xff) {
          const k = decodeCbor(bytes, pos);
          const v = decodeCbor(bytes, k.offset);
          map.set(k.value, v.value);
          pos = v.offset;
        }
        pos++;
      } else {
        const mcount = Number(argVal);
        for (let i = 0; i < mcount; i++) {
          const k = decodeCbor(bytes, pos);
          const v = decodeCbor(bytes, k.offset);
          map.set(k.value, v.value);
          pos = v.offset;
        }
      }
      return { value: map, offset: pos };
    }
    case 6: {
      const tagged = decodeCbor(bytes, pos);
      return { value: tagged.value, offset: tagged.offset };
    }
    case 7: {
      if (argVal === 20n) return { value: false, offset: pos };
      if (argVal === 21n) return { value: true, offset: pos };
      if (argVal === 22n) return { value: null, offset: pos };
      if (argVal === 23n) return { value: undefined, offset: pos };
      return { value: Number(argVal), offset: pos };
    }
    default:
      throw new Error("CBOR: unsupported major type " + major);
  }
}
