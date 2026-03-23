/**
 * Cardano slot ↔ POSIX time conversion.
 *
 * Cardano transaction validity ranges use absolute slot numbers, not POSIX
 * timestamps. The conversion depends on the network's Shelley genesis.
 *
 * Shelley era uses 1-second slots. The slot number is:
 *   slot = (posix_ms - shelley_start_ms) / 1000
 *
 * Network-specific Shelley start times (POSIX ms):
 *   preprod: 1655683200000  (2022-06-20T00:00:00Z)
 *   preview: 1666656000000  (2022-10-25T00:00:00Z)
 *   mainnet: 1591566291000  (2020-06-07T21:44:51Z)
 *
 * These values are fixed at chain genesis and never change.
 */

import type { CardanoNetwork } from "./types.js";

const SHELLEY_START_MS: Record<CardanoNetwork, number> = {
  preprod: 1655683200000,
  preview: 1666656000000,
  mainnet: 1591566291000,
};

/** Convert POSIX milliseconds to an absolute slot number. */
export function posixToSlot(posixMs: number, network: CardanoNetwork): number {
  return Math.floor((posixMs - SHELLEY_START_MS[network]) / 1000);
}

/** Convert an absolute slot number to POSIX milliseconds. */
export function slotToPosix(slot: number, network: CardanoNetwork): number {
  return slot * 1000 + SHELLEY_START_MS[network];
}
