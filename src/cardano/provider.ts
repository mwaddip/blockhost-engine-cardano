/**
 * Chain query provider — re-exports from cmttk + BlockHost-specific legacy shims.
 *
 * The provider interface, implementations (Koios, Blockfrost), and factory
 * (getProvider / resetProvider) now live in the cmttk package.
 *
 * This file re-exports those and keeps the legacy BlockFrostAPI class and
 * helper functions that are specific to the BlockHost codebase.
 */

import type { CardanoNetwork } from "./types.js";

// ── Re-exports from cmttk ───────────────────────────────────────────────────

export { getProvider, resetProvider } from "cmttk";
export type { CardanoProvider, ProtocolParams } from "cmttk";

// ── Legacy compatibility layer ──────────────────────────────────────────────
//
// The monitor, fund-manager, admin, reconciler, and is CLI still pass
// BlockFrostAPI objects around. These shims satisfy that interface using
// native fetch so the SDK can be removed.

/**
 * Lightweight Blockfrost REST client matching the subset of BlockFrostAPI
 * methods used across the codebase. Backed by native fetch().
 */
export class BlockFrostAPI {
  private baseUrl: string;
  private projectId: string;

  constructor(opts: { projectId: string; customBackend?: string }) {
    this.projectId = opts.projectId;
    // Auto-detect network from project ID prefix
    if (opts.customBackend) {
      this.baseUrl = opts.customBackend;
    } else if (opts.projectId.startsWith("mainnet")) {
      this.baseUrl = "https://cardano-mainnet.blockfrost.io/api";
    } else if (opts.projectId.startsWith("preview")) {
      this.baseUrl = "https://cardano-preview.blockfrost.io/api";
    } else {
      this.baseUrl = "https://cardano-preprod.blockfrost.io/api";
    }
  }

  private async get(path: string): Promise<unknown> {
    const res = await fetch(`${this.baseUrl}${path}`, {
      headers: { "project_id": this.projectId },
    });
    if (res.status === 404) throw Object.assign(new Error("Not found"), { status_code: 404 });
    if (!res.ok) throw new Error(`Blockfrost ${res.status}: ${await res.text()}`);
    return res.json();
  }

  private async getAll(path: string): Promise<unknown[]> {
    const all: unknown[] = [];
    let page = 1;
    while (true) {
      const sep = path.includes("?") ? "&" : "?";
      const result = await this.get(`${path}${sep}page=${page}&order=asc`) as unknown[];
      all.push(...result);
      if (result.length < 100) break;
      page++;
    }
    return all;
  }

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  async addressesUtxos(address: string): Promise<any[]> {
    return this.get(`/addresses/${address}/utxos`) as Promise<any[]>;
  }

  async addressesUtxosAll(address: string): Promise<unknown[]> {
    return this.getAll(`/addresses/${address}/utxos`);
  }

  async addressesUtxosAssetAll(address: string, asset: string): Promise<unknown[]> {
    return this.getAll(`/addresses/${address}/utxos/${asset}`);
  }

  async blocksLatest(): Promise<Record<string, unknown>> {
    return this.get("/blocks/latest") as Promise<Record<string, unknown>>;
  }

  async txSubmit(txCbor: string): Promise<string> {
    const res = await fetch(`${this.baseUrl}/tx/submit`, {
      method: "POST",
      headers: { "project_id": this.projectId, "Content-Type": "application/cbor" },
      body: Buffer.from(txCbor, "hex"),
    });
    if (!res.ok) throw new Error(`Blockfrost submit ${res.status}: ${await res.text()}`);
    return (await res.text()).replace(/"/g, "").trim();
  }

  async txsMetadata(txHash: string): Promise<unknown[]> {
    return this.get(`/txs/${txHash}/metadata`) as Promise<unknown[]>;
  }

  async addressesTransactions(
    address: string,
    opts?: { count?: number; order?: string },
  ): Promise<unknown[]> {
    const count = opts?.count ?? 100;
    const order = opts?.order ?? "desc";
    return this.get(`/addresses/${address}/transactions?count=${count}&order=${order}`) as Promise<unknown[]>;
  }

  async assetsAddresses(asset: string): Promise<Array<{ address: string; quantity: string }>> {
    return this.get(`/assets/${asset}/addresses`) as Promise<Array<{ address: string; quantity: string }>>;
  }

  async addresses(address: string): Promise<unknown> {
    return this.get(`/addresses/${address}`);
  }

  async epochsLatestParameters(): Promise<Record<string, unknown>> {
    return this.get("/epochs/latest/parameters") as Promise<Record<string, unknown>>;
  }
}

/** @deprecated Use getProvider() instead */
export function getBlockfrost(projectId: string, _network: CardanoNetwork): BlockFrostAPI {
  return new BlockFrostAPI({ projectId });
}

/** @deprecated Use provider.fetchUtxos() instead */
export async function queryUtxos(
  client: BlockFrostAPI,
  address: string,
  asset?: string,
): Promise<unknown[]> {
  try {
    if (asset) return await client.addressesUtxosAssetAll(address, asset);
    return await client.addressesUtxosAll(address);
  } catch (err: unknown) {
    if (err && typeof err === "object" && "status_code" in err && (err as { status_code: number }).status_code === 404) return [];
    throw err;
  }
}

/** @deprecated Use provider.fetchTip() instead */
export async function getTip(client: BlockFrostAPI): Promise<{ slot: number; block: number; time: number }> {
  const tip = await client.blocksLatest();
  return { slot: Number(tip["slot"] ?? 0), block: Number(tip["height"] ?? 0), time: Number(tip["time"] ?? 0) };
}

/** @deprecated Use provider.submitTx() instead */
export async function submitTx(client: BlockFrostAPI, txCbor: string): Promise<string> {
  return client.txSubmit(txCbor);
}
