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
