/**
 * CIP-68 NFT minting helpers.
 *
 * Provides asset name computation and mint parameter preparation for
 * CIP-68 access credential NFTs.  The actual transaction building is
 * deferred to the blockhost-mint-nft script (Task 8) which integrates
 * MeshJS for full Cardano transaction construction and submission.
 *
 * CIP-68 token labels:
 *   (222) user token    — 000de140 prefix — freely tradeable by subscriber
 *   (100) reference token — 000643b0 prefix — locked at script address with datum
 */

// ── CIP-68 prefixes ───────────────────────────────────────────────────────────

const CIP68_USER_TOKEN_PREFIX = "000de140";      // (222) user token label
const CIP68_REFERENCE_TOKEN_PREFIX = "000643b0"; // (100) reference token label

// ── Asset name helpers ────────────────────────────────────────────────────────

/**
 * Compute the CIP-68 user token asset name from a sequential integer token ID.
 * Asset name = 000de140 + tokenId padded to 8 hex digits.
 */
export function userTokenAssetName(tokenId: number): string {
  const idHex = tokenId.toString(16).padStart(8, "0");
  return CIP68_USER_TOKEN_PREFIX + idHex;
}

/**
 * Compute the CIP-68 reference token asset name from a sequential integer token ID.
 * Asset name = 000643b0 + tokenId padded to 8 hex digits.
 */
export function referenceTokenAssetName(tokenId: number): string {
  const idHex = tokenId.toString(16).padStart(8, "0");
  return CIP68_REFERENCE_TOKEN_PREFIX + idHex;
}

/**
 * Extract the token ID integer from a CIP-68 asset name (either prefix).
 * Returns null if the name does not match either known prefix.
 */
export function tokenIdFromAssetName(assetNameHex: string): number | null {
  if (assetNameHex.startsWith(CIP68_USER_TOKEN_PREFIX)) {
    return parseInt(assetNameHex.slice(CIP68_USER_TOKEN_PREFIX.length), 16);
  }
  if (assetNameHex.startsWith(CIP68_REFERENCE_TOKEN_PREFIX)) {
    return parseInt(assetNameHex.slice(CIP68_REFERENCE_TOKEN_PREFIX.length), 16);
  }
  return null;
}

/** Return true if the asset name is a CIP-68 (222) user token. */
export function isUserToken(assetNameHex: string): boolean {
  return assetNameHex.startsWith(CIP68_USER_TOKEN_PREFIX);
}

/** Return true if the asset name is a CIP-68 (100) reference token. */
export function isReferenceToken(assetNameHex: string): boolean {
  return assetNameHex.startsWith(CIP68_REFERENCE_TOKEN_PREFIX);
}

// ── Mint parameters ───────────────────────────────────────────────────────────

/** Parameters required to build a CIP-68 mint transaction. */
export interface MintParams {
  /** NFT minting policy ID (56 hex chars). */
  policyId: string;
  /** Sequential token ID — determines the asset name suffix. */
  tokenId: number;
  /** Recipient bech32 address — receives the (222) user token. */
  recipientAddress: string;
  /** Script address that holds the (100) reference token and inline datum. */
  referenceScriptAddress: string;
  /** Encrypted connection details (hex) — stored in the reference datum. */
  userEncrypted: string;
  /** Server signing key hex — authorises the minting policy. */
  serverKeyHex: string;
}

/**
 * Assemble a MintParams record from individual fields.
 *
 * The returned value is passed to the blockhost-mint-nft script, which
 * uses MeshJS to construct and submit the Cardano transaction that mints
 * both the user token (to recipientAddress) and the reference token (to
 * referenceScriptAddress with the userEncrypted inline datum).
 */
export function prepareMintParams(
  policyId: string,
  tokenId: number,
  recipientAddress: string,
  referenceScriptAddress: string,
  userEncrypted: string,
  serverKeyHex: string,
): MintParams {
  return {
    policyId,
    tokenId,
    recipientAddress,
    referenceScriptAddress,
    userEncrypted,
    serverKeyHex,
  };
}
