/**
 * Blockfrost client wrapper for Cardano chain queries and tx submission.
 */

import { BlockFrostAPI } from "@blockfrost/blockfrost-js";
import type { CardanoNetwork } from "./types.js";

let _client: BlockFrostAPI | null = null;

/**
 * Get or create a Blockfrost API client.
 *
 * @param projectId - Blockfrost project ID (e.g. "preprodXXXXXXX")
 * @param network - Cardano network (mainnet, preprod, preview)
 * @returns Blockfrost API client instance
 */
export function getBlockfrost(projectId: string, network: CardanoNetwork): BlockFrostAPI {
  if (_client) return _client;

  const baseUrl = network === "mainnet"
    ? "https://cardano-mainnet.blockfrost.io/api"
    : network === "preprod"
      ? "https://cardano-preprod.blockfrost.io/api"
      : "https://cardano-preview.blockfrost.io/api";

  _client = new BlockFrostAPI({ projectId, customBackend: baseUrl });
  return _client;
}

/** Query UTXOs at an address, optionally filtered by asset */
export async function queryUtxos(
  client: BlockFrostAPI,
  address: string,
  asset?: string,
): Promise<unknown[]> {
  try {
    if (asset) {
      return await client.addressesUtxosAssetAll(address, asset);
    }
    return await client.addressesUtxosAll(address);
  } catch (err: unknown) {
    if (
      err &&
      typeof err === "object" &&
      "status_code" in err &&
      (err as { status_code: number }).status_code === 404
    ) {
      return [];
    }
    throw err;
  }
}

/** Get current tip (latest block) */
export async function getTip(
  client: BlockFrostAPI,
): Promise<{ slot: number; block: number; time: number }> {
  const tip = await client.blocksLatest();
  return {
    slot: tip.slot ?? 0,
    block: tip.height ?? 0,
    time: tip.time,
  };
}

/** Submit a signed transaction */
export async function submitTx(client: BlockFrostAPI, txCbor: string): Promise<string> {
  return await client.txSubmit(txCbor);
}
