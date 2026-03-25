/**
 * Beacon name computation following the cardano-swaps pattern.
 *
 * Each subscription gets a unique beacon token whose name is derived
 * from the plan ID, subscriber's payment key hash, and the block height
 * at creation time.  The block height acts as a natural salt so the
 * same subscriber can create multiple subscriptions to the same plan.
 */

import { sha256 } from "@noble/hashes/sha2";
import { bytesToHex } from "@noble/hashes/utils";

/**
 * Compute a beacon token name for a subscription.
 * beacon_name = sha256(plan_id_4BE ++ subscriber_key_hash ++ creation_height_4BE)
 *
 * @param planId             - The subscription plan ID (4-byte big-endian integer)
 * @param subscriberKeyHash  - The subscriber's payment key hash (hex, 56 chars)
 * @param creationHeight     - Block height at subscription creation (4-byte big-endian)
 * @returns Hex-encoded beacon token name (64 chars, sha256 output)
 */
export function computeBeaconName(
  planId: number,
  subscriberKeyHash: string,
  creationHeight: number,
): string {
  const planBytes = new Uint8Array(4);
  new DataView(planBytes.buffer).setInt32(0, planId, false);

  const keyHashBytes = hexToBytes(subscriberKeyHash);

  const heightBytes = new Uint8Array(4);
  new DataView(heightBytes.buffer).setUint32(0, creationHeight, false);

  const combined = new Uint8Array(4 + keyHashBytes.length + 4);
  combined.set(planBytes, 0);
  combined.set(keyHashBytes, 4);
  combined.set(heightBytes, 4 + keyHashBytes.length);

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
