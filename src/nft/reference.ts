/**
 * CIP-68 reference datum helpers.
 *
 * Reads the reference datum and locates the current user-token holder
 * via Blockfrost asset address queries.
 */

import type { CardanoProvider } from "cmttk";
import type { NftReferenceDatum } from "../cardano/types.js";
import { referenceTokenAssetName, userTokenAssetName } from "./mint.js";

// ── Reference datum reader ────────────────────────────────────────────────────

/**
 * Read the CIP-68 reference datum for a given token ID.
 *
 * Queries Blockfrost for all addresses holding the (100) reference token,
 * then fetches the UTXO at that address and extracts the inline datum.
 * The reference token is expected to be locked at exactly one script address.
 *
 * Returns null if the token does not exist or has no inline datum.
 */
export async function readReferenceDatum(
  provider: CardanoProvider,
  nftPolicyId: string,
  tokenId: number,
): Promise<NftReferenceDatum | null> {
  const refAssetName = referenceTokenAssetName(tokenId);
  const asset = nftPolicyId + refAssetName;

  try {
    // Find addresses holding this reference token
    const addresses = await provider.fetchAssetAddresses(asset);
    if (addresses.length === 0) return null;

    // The reference token must be at exactly one address (the script address)
    const addr = addresses[0]!.address;
    const rawUtxos = await provider.fetchUtxos(addr, asset);
    if (rawUtxos.length === 0) return null;

    // Extract the inline datum from the first matching UTXO.
    // Koios: inline_datum = { bytes, value } — we want "value".
    // Blockfrost: inline_datum is the Plutus data directly.
    const utxo = rawUtxos[0] as Record<string, unknown>;
    const rawDatum = utxo["inline_datum"] as Record<string, unknown> | null;
    if (!rawDatum) return null;
    const datum = "value" in rawDatum ? rawDatum["value"] : rawDatum;

    return parseNftReferenceDatum(datum);
  } catch {
    return null;
  }
}

// ── NFT holder lookup ─────────────────────────────────────────────────────────

/**
 * Find the current holder of a CIP-68 (222) user token.
 *
 * Queries Blockfrost for addresses that hold the user token for this token ID.
 * Returns the bech32 address of the holder, or null if not found.
 */
export async function findNftHolder(
  provider: CardanoProvider,
  nftPolicyId: string,
  tokenId: number,
): Promise<string | null> {
  const asset = nftPolicyId + userTokenAssetName(tokenId);

  try {
    const addresses = await provider.fetchAssetAddresses(asset);
    if (addresses.length === 0) return null;
    // User token is fungible-quantity-1 so only one address can hold it
    return addresses[0]!.address;
  } catch {
    return null;
  }
}

// ── Datum parser ──────────────────────────────────────────────────────────────

/**
 * Parse a CIP-68 reference datum from its Blockfrost inline_datum representation.
 *
 * Supports two layouts:
 *   - Constructor 0 with a single ByteArray field (canonical CIP-68 format)
 *   - A bare ByteArray map entry (simplified storage)
 *
 * Returns null if the datum cannot be interpreted.
 */
function parseNftReferenceDatum(inlineDatum: unknown): NftReferenceDatum | null {
  try {
    const datum = inlineDatum as Record<string, unknown>;

    // Canonical CIP-68: { constructor: 0, fields: [{ bytes: "<hex>" }] }
    if (
      datum["constructor"] === 0 &&
      Array.isArray(datum["fields"]) &&
      (datum["fields"] as unknown[]).length >= 1
    ) {
      const field = (datum["fields"] as Record<string, unknown>[])[0];
      const bytes = field?.["bytes"];
      if (typeof bytes === "string") {
        return { userEncrypted: bytes };
      }
    }

    // Simplified: bare bytes map
    if (typeof datum["bytes"] === "string") {
      return { userEncrypted: datum["bytes"] };
    }

    return null;
  } catch {
    return null;
  }
}

