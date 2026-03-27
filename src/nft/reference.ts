/**
 * CIP-68 NFT holder lookup.
 */

import type { CardanoProvider } from "cmttk";
import { userTokenAssetName } from "./mint.js";

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
  } catch (err) {
    console.warn(`[NFT] Error finding holder for token ${tokenId}: ${err instanceof Error ? err.message : err}`);
    return null;
  }
}
