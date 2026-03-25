/**
 * CIP-68 NFT asset name helpers.
 *
 * CIP-68 token labels:
 *   (222) user token    — 000de140 prefix — freely tradeable by subscriber
 *   (100) reference token — 000643b0 prefix — locked at script address with datum
 */

const CIP68_USER_TOKEN_PREFIX = "000de140";
const CIP68_REFERENCE_TOKEN_PREFIX = "000643b0";

/**
 * Compute the CIP-68 user token asset name from a sequential integer token ID.
 * Asset name = 000de140 + tokenId padded to 8 hex digits.
 */
export function userTokenAssetName(tokenId: number): string {
  return CIP68_USER_TOKEN_PREFIX + tokenId.toString(16).padStart(8, "0");
}

/**
 * Compute the CIP-68 reference token asset name from a sequential integer token ID.
 * Asset name = 000643b0 + tokenId padded to 8 hex digits.
 */
export function referenceTokenAssetName(tokenId: number): string {
  return CIP68_REFERENCE_TOKEN_PREFIX + tokenId.toString(16).padStart(8, "0");
}
