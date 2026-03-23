/**
 * Drop-in shim for libsodium-wrappers-sumo using @noble/curves and @noble/hashes.
 * Implements only the functions that @cardano-sdk/crypto actually calls.
 * Eliminates the 40MB WASM dependency.
 */

import { ed25519 } from "@noble/curves/ed25519";
import { sha512 } from "@noble/hashes/sha2";
import { hmac } from "@noble/hashes/hmac";
import { blake2b } from "@noble/hashes/blake2b";

// Ed25519 curve order
const L = 2n ** 252n + 27742317777372353535851937790883648493n;

function bytesToBigInt(bytes: Uint8Array): bigint {
  let result = 0n;
  for (let i = bytes.length - 1; i >= 0; i--) {
    result = (result << 8n) | BigInt(bytes[i]!); // little-endian
  }
  return result;
}

function bigIntToBytes(n: bigint, len: number): Uint8Array {
  const result = new Uint8Array(len);
  let val = n;
  for (let i = 0; i < len; i++) {
    result[i] = Number(val & 0xffn);
    val >>= 8n;
  }
  return result;
}

const sodium = {
  ready: Promise.resolve(),

  crypto_auth_hmacsha512(message: Uint8Array, key: Uint8Array): Uint8Array {
    return hmac(sha512, key, message);
  },

  crypto_hash_sha512(message: Uint8Array): Uint8Array {
    return sha512(message);
  },

  crypto_generichash(
    hashLength: number,
    message: Uint8Array,
    _key?: Uint8Array,
  ): Uint8Array {
    return blake2b(message, { dkLen: hashLength });
  },

  crypto_scalarmult_ed25519_base_noclamp(scalar: Uint8Array): Uint8Array {
    const s = bytesToBigInt(scalar) % L;
    const point = ed25519.ExtendedPoint.BASE.multiply(s);
    return point.toRawBytes();
  },

  crypto_core_ed25519_add(p: Uint8Array, q: Uint8Array): Uint8Array {
    const P = ed25519.ExtendedPoint.fromHex(p);
    const Q = ed25519.ExtendedPoint.fromHex(q);
    return P.add(Q).toRawBytes();
  },

  crypto_core_ed25519_scalar_add(x: Uint8Array, y: Uint8Array): Uint8Array {
    const result = (bytesToBigInt(x) + bytesToBigInt(y)) % L;
    return bigIntToBytes(result, 32);
  },

  crypto_core_ed25519_scalar_mul(x: Uint8Array, y: Uint8Array): Uint8Array {
    const result = (bytesToBigInt(x) * bytesToBigInt(y)) % L;
    return bigIntToBytes(result, 32);
  },

  crypto_core_ed25519_scalar_reduce(scalar: Uint8Array): Uint8Array {
    const result = bytesToBigInt(scalar) % L;
    return bigIntToBytes(result, 32);
  },

  crypto_sign_detached(
    message: Uint8Array,
    secretKey: Uint8Array,
  ): Uint8Array {
    // secretKey is 64 bytes: [seed(32) | pubkey(32)]
    const seed = secretKey.slice(0, 32);
    return ed25519.sign(message, seed);
  },

  crypto_sign_seed_keypair(seed: Uint8Array): {
    publicKey: Uint8Array;
    privateKey: Uint8Array;
  } {
    const publicKey = ed25519.getPublicKey(seed);
    const privateKey = new Uint8Array(64);
    privateKey.set(seed);
    privateKey.set(publicKey, 32);
    return { publicKey, privateKey };
  },

  crypto_sign_verify_detached(
    signature: Uint8Array,
    message: Uint8Array,
    publicKey: Uint8Array,
  ): boolean {
    return ed25519.verify(signature, message, publicKey);
  },
};

export default sodium;
