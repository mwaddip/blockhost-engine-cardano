/**
 * Address validation and normalization for Cardano bech32 addresses.
 */

import { bech32 } from "bech32";

/** Validate a Cardano bech32 address */
export function isValidAddress(addr: string): boolean {
  try {
    if (addr.startsWith("addr1") || addr.startsWith("addr_test1")) {
      bech32.decode(addr, 256);
      return true;
    }
    return false;
  } catch {
    return false;
  }
}

/** Validate a policy ID (28 bytes = 56 hex chars) */
export function isValidPolicyId(policyId: string): boolean {
  return /^[0-9a-fA-F]{56}$/.test(policyId);
}

/** Normalize address to lowercase */
export function normalizeAddress(addr: string): string {
  return addr.toLowerCase();
}

/**
 * Extract the payment credential key hash from a bech32 address.
 * Replaces Lucid's getAddressDetails().paymentCredential.hash.
 *
 * Cardano base address layout (type 0x00/0x01):
 *   header(1) + paymentKeyHash(28) + stakeKeyHash(28) = 57 bytes
 *
 * Returns the 28-byte payment key hash as 56-char hex, or null if
 * the address type doesn't contain a key hash payment credential.
 */
export function getPaymentKeyHash(addr: string): string | null {
  try {
    const decoded = bech32.decode(addr, 256);
    const bytes = bech32.fromWords(decoded.words);
    if (bytes.length < 29) return null;

    const header = bytes[0]!;
    const addrType = (header >> 4) & 0x0f;

    // Types 0x00 and 0x01 have a key hash payment credential
    // Types 0x02 and 0x03 have a script hash payment credential
    // Types 0x06 and 0x07 are enterprise addresses (key/script, no staking)
    if (addrType === 0 || addrType === 1 || addrType === 6) {
      // Key hash payment credential: bytes 1-28
      return Buffer.from(bytes.slice(1, 29)).toString("hex");
    }

    return null; // script address or unsupported type
  } catch {
    return null;
  }
}
