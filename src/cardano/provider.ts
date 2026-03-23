/**
 * Chain query provider — abstracts Blockfrost and Koios behind a common interface.
 *
 * Default: Koios (free, no API key required).
 * Optional: Blockfrost (higher rate limits, requires project ID).
 *
 * Both providers use native fetch() — no external SDK dependencies.
 */

import type { CardanoNetwork } from "./types.js";

// ── Provider interface ──────────────────────────────────────────────────────

/** Common interface for chain queries. Both Koios and Blockfrost implement this. */
export interface CardanoProvider {
  /** Provider name for logging */
  readonly name: string;

  /** Query UTXOs at an address, optionally filtered by asset (policyId + assetNameHex) */
  fetchUtxos(address: string, asset?: string): Promise<unknown[]>;

  /** Get the latest block/slot */
  fetchTip(): Promise<{ slot: number; block: number; time: number }>;

  /** Submit a signed transaction (CBOR hex) */
  submitTx(txCbor: string): Promise<string>;

  /** Get transaction metadata by tx hash */
  fetchTxMetadata(txHash: string): Promise<unknown[]>;

  /** Get recent transactions for an address */
  fetchAddressTransactions(
    address: string,
    options?: { count?: number; order?: "asc" | "desc" },
  ): Promise<unknown[]>;

  /** Get addresses holding a specific asset */
  fetchAssetAddresses(asset: string): Promise<Array<{ address: string; quantity: string }>>;

  /** Get address summary (balances) */
  fetchAddressInfo(address: string): Promise<unknown>;

  /** Get protocol parameters (fee coefficients, min UTXO) */
  fetchProtocolParams(): Promise<ProtocolParams>;
}

/** Subset of protocol parameters needed for tx building. */
export interface ProtocolParams {
  minFeeA: number;
  minFeeB: number;
  coinsPerUtxoByte: number;
  costModelV3?: number[];
  priceMem: number;
  priceStep: number;
}

// ── Koios provider ──────────────────────────────────────────────────────────

const KOIOS_URLS: Record<CardanoNetwork, string> = {
  mainnet: "https://api.koios.rest/api/v1",
  preprod: "https://preprod.koios.rest/api/v1",
  preview: "https://preview.koios.rest/api/v1",
};

class KoiosProvider implements CardanoProvider {
  readonly name = "koios";
  private baseUrl: string;

  private static MAX_RETRIES = 4;
  private static BASE_DELAY_MS = 1000;

  constructor(network: CardanoNetwork) {
    this.baseUrl = KOIOS_URLS[network];
  }

  private async request(path: string, options?: RequestInit): Promise<unknown> {
    const url = `${this.baseUrl}${path}`;

    for (let attempt = 0; attempt <= KoiosProvider.MAX_RETRIES; attempt++) {
      const res = await fetch(url, {
        ...options,
        headers: {
          "Content-Type": "application/json",
          "Accept": "application/json",
          ...options?.headers,
        },
      });

      if (res.ok) return res.json();
      if (res.status === 404) return null;

      if (res.status === 429 || res.status >= 500) {
        if (attempt < KoiosProvider.MAX_RETRIES) {
          const retryAfter = res.headers.get("Retry-After");
          const delay = retryAfter
            ? parseInt(retryAfter, 10) * 1000
            : KoiosProvider.BASE_DELAY_MS * Math.pow(2, attempt);
          console.warn(`[KOIOS] ${res.status} on ${path}, retrying in ${delay}ms (${attempt + 1}/${KoiosProvider.MAX_RETRIES})`);
          await new Promise((r) => setTimeout(r, delay));
          continue;
        }
      }

      throw new Error(`Koios ${res.status}: ${await res.text()}`);
    }

    throw new Error(`Koios: retries exhausted for ${path}`);
  }

  private async post(path: string, body: unknown): Promise<unknown> {
    return this.request(path, { method: "POST", body: JSON.stringify(body) });
  }

  async fetchUtxos(address: string, asset?: string): Promise<unknown[]> {
    const result = await this.post("/address_utxos", {
      _addresses: [address],
      _extended: true,
    }) as unknown[] | null;

    if (!result) return [];

    if (asset) {
      return (result as Array<Record<string, unknown>>).filter((utxo) => {
        const assetList = utxo["asset_list"] as Array<Record<string, string>> | undefined;
        if (!assetList) return false;
        const policyId = asset.slice(0, 56);
        const assetName = asset.slice(56);
        return assetList.some((a) => a["policy_id"] === policyId && a["asset_name"] === assetName);
      });
    }

    return result;
  }

  async fetchTip(): Promise<{ slot: number; block: number; time: number }> {
    const result = await this.request("/tip") as Array<Record<string, unknown>> | null;
    if (!result || result.length === 0) throw new Error("Failed to fetch tip from Koios");
    const tip = result[0]!;
    return {
      slot: Number(tip["abs_slot"] ?? 0),
      block: Number(tip["block_no"] ?? 0),
      time: Number(tip["block_time"] ?? 0),
    };
  }

  async submitTx(txCbor: string): Promise<string> {
    const url = `${this.baseUrl}/submittx`;
    const cborBytes = Buffer.from(txCbor, "hex");
    const res = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/cbor" },
      body: cborBytes,
    });
    if (!res.ok) throw new Error(`Koios submit failed ${res.status}: ${await res.text()}`);
    const txHash = await res.text();
    return txHash.replace(/"/g, "").trim();
  }

  async fetchTxMetadata(txHash: string): Promise<unknown[]> {
    const result = await this.post("/tx_metadata", { _tx_hashes: [txHash] }) as unknown[] | null;
    return result ?? [];
  }

  async fetchAddressTransactions(
    address: string,
    options?: { count?: number; order?: "asc" | "desc" },
  ): Promise<unknown[]> {
    const result = await this.post("/address_txs", {
      _addresses: [address],
      _after_block_height: 0,
    }) as unknown[] | null;

    if (!result) return [];
    const sorted = options?.order === "asc" ? result : result.reverse();
    return options?.count ? sorted.slice(0, options.count) : sorted;
  }

  async fetchAssetAddresses(asset: string): Promise<Array<{ address: string; quantity: string }>> {
    const policyId = asset.slice(0, 56);
    const assetName = asset.slice(56);
    const result = await this.post("/asset_addresses", {
      _asset_policy: policyId,
      _asset_name: assetName,
    }) as Array<Record<string, string>> | null;

    if (!result) return [];
    return result.map((r) => ({
      address: r["payment_address"] ?? r["address"] ?? "",
      quantity: r["quantity"] ?? "0",
    }));
  }

  async fetchAddressInfo(address: string): Promise<unknown> {
    const result = await this.post("/address_info", {
      _addresses: [address],
    }) as unknown[] | null;
    return result?.[0] ?? null;
  }

  async fetchProtocolParams(): Promise<ProtocolParams> {
    const result = await this.request("/epoch_params?limit=1") as Array<Record<string, unknown>> | null;
    if (!result || result.length === 0) throw new Error("Failed to fetch protocol params from Koios");
    const p = result[0]!;
    const costModels = p["cost_models"] as Record<string, number[]> | undefined;
    return {
      minFeeA: Number(p["min_fee_a"] ?? 44),
      minFeeB: Number(p["min_fee_b"] ?? 155381),
      coinsPerUtxoByte: Number(p["coins_per_utxo_size"] ?? 4310),
      costModelV3: costModels?.["PlutusV3"],
      priceMem: Number(p["price_mem"] ?? 0.0577),
      priceStep: Number(p["price_step"] ?? 0.0000721),
    };
  }
}

// ── Blockfrost provider (native fetch) ──────────────────────────────────────

const BLOCKFROST_URLS: Record<CardanoNetwork, string> = {
  mainnet: "https://cardano-mainnet.blockfrost.io/api/v0",
  preprod: "https://cardano-preprod.blockfrost.io/api/v0",
  preview: "https://cardano-preview.blockfrost.io/api/v0",
};

class BlockfrostProvider implements CardanoProvider {
  readonly name = "blockfrost";
  private baseUrl: string;
  private projectId: string;

  constructor(projectId: string, network: CardanoNetwork) {
    this.baseUrl = BLOCKFROST_URLS[network];
    this.projectId = projectId;
  }

  private async request(path: string, options?: RequestInit): Promise<unknown> {
    const res = await fetch(`${this.baseUrl}${path}`, {
      ...options,
      headers: {
        "project_id": this.projectId,
        "Content-Type": "application/json",
        ...options?.headers,
      },
    });

    if (res.ok) return res.json();
    if (res.status === 404) return null;
    throw new Error(`Blockfrost ${res.status}: ${await res.text()}`);
  }

  async fetchUtxos(address: string, asset?: string): Promise<unknown[]> {
    const path = asset
      ? `/addresses/${address}/utxos/${asset}`
      : `/addresses/${address}/utxos`;

    // Blockfrost paginates — fetch all pages
    const all: unknown[] = [];
    let page = 1;
    while (true) {
      const result = await this.request(`${path}?page=${page}&order=asc`) as unknown[] | null;
      if (!result || result.length === 0) break;
      all.push(...result);
      if (result.length < 100) break; // less than a full page = last page
      page++;
    }
    return all;
  }

  async fetchTip(): Promise<{ slot: number; block: number; time: number }> {
    const tip = await this.request("/blocks/latest") as Record<string, unknown> | null;
    if (!tip) throw new Error("Failed to fetch tip from Blockfrost");
    return {
      slot: Number(tip["slot"] ?? 0),
      block: Number(tip["height"] ?? 0),
      time: Number(tip["time"] ?? 0),
    };
  }

  async submitTx(txCbor: string): Promise<string> {
    const res = await fetch(`${this.baseUrl}/tx/submit`, {
      method: "POST",
      headers: {
        "project_id": this.projectId,
        "Content-Type": "application/cbor",
      },
      body: Buffer.from(txCbor, "hex"),
    });
    if (!res.ok) throw new Error(`Blockfrost submit ${res.status}: ${await res.text()}`);
    const txHash = await res.text();
    return txHash.replace(/"/g, "").trim();
  }

  async fetchTxMetadata(txHash: string): Promise<unknown[]> {
    const result = await this.request(`/txs/${txHash}/metadata`) as unknown[] | null;
    return result ?? [];
  }

  async fetchAddressTransactions(
    address: string,
    options?: { count?: number; order?: "asc" | "desc" },
  ): Promise<unknown[]> {
    const count = options?.count ?? 100;
    const order = options?.order ?? "desc";
    const result = await this.request(`/addresses/${address}/transactions?count=${count}&order=${order}`) as unknown[] | null;
    return result ?? [];
  }

  async fetchAssetAddresses(asset: string): Promise<Array<{ address: string; quantity: string }>> {
    const result = await this.request(`/assets/${asset}/addresses`) as Array<Record<string, string>> | null;
    if (!result) return [];
    return result.map((r) => ({ address: r["address"] ?? "", quantity: r["quantity"] ?? "0" }));
  }

  async fetchAddressInfo(address: string): Promise<unknown> {
    return this.request(`/addresses/${address}`);
  }

  async fetchProtocolParams(): Promise<ProtocolParams> {
    const p = await this.request("/epochs/latest/parameters") as Record<string, unknown> | null;
    if (!p) throw new Error("Failed to fetch protocol params from Blockfrost");
    const costModels = p["cost_models"] as Record<string, unknown> | undefined;
    let costModelV3: number[] | undefined;
    if (costModels?.["PlutusV3"]) costModelV3 = costModels["PlutusV3"] as number[];
    return {
      minFeeA: Number(p["min_fee_a"] ?? 44),
      minFeeB: Number(p["min_fee_b"] ?? 155381),
      coinsPerUtxoByte: Number(p["coins_per_utxo_size"] ?? "4310"),
      costModelV3,
      priceMem: Number(p["price_mem"] ?? "0.0577"),
      priceStep: Number(p["price_step"] ?? "0.0000721"),
    };
  }
}

// ── Factory ─────────────────────────────────────────────────────────────────

let _provider: CardanoProvider | null = null;

/**
 * Create or return a cached CardanoProvider.
 *
 * If blockfrostProjectId is provided, uses Blockfrost.
 * Otherwise, uses Koios (free, no API key required).
 */
export function getProvider(
  network: CardanoNetwork,
  blockfrostProjectId?: string,
): CardanoProvider {
  if (_provider) return _provider;

  if (blockfrostProjectId) {
    _provider = new BlockfrostProvider(blockfrostProjectId, network);
  } else {
    _provider = new KoiosProvider(network);
  }

  console.log(`[PROVIDER] Using ${_provider.name} (${network})`);
  return _provider;
}

/** Reset the cached provider (for testing) */
export function resetProvider(): void {
  _provider = null;
}

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
