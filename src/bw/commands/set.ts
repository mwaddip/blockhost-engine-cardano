/**
 * bw set encrypt <nft_id> <data>
 *
 * Update the CIP-68 reference token's datum with new encrypted data.
 *
 * TODO: Requires building a transaction that updates the inline datum on the
 * reference token UTXO using an UpdateReference redeemer.
 * Depends on MeshJS integration.
 */

import type { Addressbook } from "../../fund-manager/types.js";

/**
 * CLI handler
 */
export async function setCommand(
  args: string[],
  _book: Addressbook,
): Promise<void> {
  const [subCommand, ...rest] = args;

  if (subCommand === "encrypt") {
    await setEncryptCommand(rest);
    return;
  }

  console.error("Usage: bw set encrypt <nft_id> <data>");
  process.exit(1);
}

async function setEncryptCommand(args: string[]): Promise<void> {
  if (args.length < 2) {
    console.error("Usage: bw set encrypt <nft_id> <data>");
    console.error("  <nft_id>  — integer token ID");
    console.error("  <data>    — hex-encoded encrypted data");
    process.exit(1);
  }

  const [nftIdStr, data] = args;
  if (!nftIdStr || !data) {
    console.error("Usage: bw set encrypt <nft_id> <data>");
    process.exit(1);
  }

  const tokenId = parseInt(nftIdStr, 10);
  if (!Number.isInteger(tokenId) || tokenId < 0) {
    console.error(`Invalid nft_id: ${nftIdStr}`);
    process.exit(1);
  }

  console.log(`[TODO] Update reference datum for token ${tokenId} with data: ${data.slice(0, 32)}...`);
  console.log("TODO: set encrypt not yet implemented.");
  console.log(
    "      Requires building a transaction updating the CIP-68 reference token datum.",
    "Depends on MeshJS integration.",
  );
}
