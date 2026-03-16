/**
 * Beacon name computation following the cardano-swaps pattern.
 *
 * Each subscription gets a unique beacon token whose name is derived
 * from the plan ID and subscriber's payment key hash.
 */

import { sha256 } from "@noble/hashes/sha2";
import { bytesToHex } from "@noble/hashes/utils";

/**
 * Compute a beacon token name for a subscription.
 * beacon_name = sha256(plan_id_bytes ++ subscriber_payment_key_hash)
 *
 * @param planId - The subscription plan ID (4-byte big-endian integer)
 * @param subscriberKeyHash - The subscriber's payment key hash (hex, 56 chars)
 * @returns Hex-encoded beacon token name (64 chars, sha256 output)
 */
export function computeBeaconName(planId: number, subscriberKeyHash: string): string {
  const planBytes = new Uint8Array(4);
  new DataView(planBytes.buffer).setInt32(0, planId, false); // big-endian

  const keyHashBytes = hexToBytes(subscriberKeyHash);
  const combined = new Uint8Array(planBytes.length + keyHashBytes.length);
  combined.set(planBytes, 0);
  combined.set(keyHashBytes, planBytes.length);

  const hash = sha256(combined);
  return bytesToHex(hash);
}

function hexToBytes(hex: string): Uint8Array {
  if (hex.startsWith("0x")) hex = hex.slice(2);
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.substring(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}
