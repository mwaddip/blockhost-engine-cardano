/**
 * Chain query provider — abstracts Blockfrost and Koios behind a common interface.
 *
 * Default: Koios (free, no API key required).
 * Optional: Blockfrost (higher rate limits, requires project ID).
 */

import { BlockFrostAPI } from "@blockfrost/blockfrost-js";
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
  /** Fee per byte (minFeeA / txFeePerByte), lovelace */
  minFeeA: number;
  /** Fixed fee component (minFeeB / txFeeFixed), lovelace */
  minFeeB: number;
  /** Coins per UTXO byte (for min UTXO calculation) */
  coinsPerUtxoByte: number;
  /** PlutusV3 cost model (array of integers) — needed for script_data_hash */
  costModelV3?: number[];
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

  /** Max retries on 429 / 5xx before giving up */
  private static MAX_RETRIES = 4;
  /** Base delay in ms — doubles on each retry (1s, 2s, 4s, 8s) */
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

      if (res.ok) {
        return res.json();
      }

      if (res.status === 404) return null;

      // Rate limited or server error — retry with exponential backoff
      if (res.status === 429 || res.status >= 500) {
        if (attempt < KoiosProvider.MAX_RETRIES) {
          // Respect Retry-After header if present, otherwise exponential backoff
          const retryAfter = res.headers.get("Retry-After");
          const delay = retryAfter
            ? parseInt(retryAfter, 10) * 1000
            : KoiosProvider.BASE_DELAY_MS * Math.pow(2, attempt);
          console.warn(
            `[KOIOS] ${res.status} on ${path}, retrying in ${delay}ms (attempt ${attempt + 1}/${KoiosProvider.MAX_RETRIES})`,
          );
          await new Promise((r) => setTimeout(r, delay));
          continue;
        }
      }

      // Non-retryable error or retries exhausted
      throw new Error(`Koios ${res.status}: ${await res.text()}`);
    }

    // Should not reach here, but satisfy TypeScript
    throw new Error(`Koios: retries exhausted for ${path}`);
  }

  private async post(path: string, body: unknown): Promise<unknown> {
    return this.request(path, {
      method: "POST",
      body: JSON.stringify(body),
    });
  }

  async fetchUtxos(address: string, asset?: string): Promise<unknown[]> {
    // Koios uses POST for address UTXOs
    const result = await this.post("/address_utxos", {
      _addresses: [address],
      _extended: true,
    }) as unknown[] | null;

    if (!result) return [];

    if (asset) {
      // Filter for UTXOs containing the specific asset
      return (result as Array<Record<string, unknown>>).filter((utxo) => {
        const assetList = utxo["asset_list"] as Array<Record<string, string>> | undefined;
        if (!assetList) return false;
        const policyId = asset.slice(0, 56);
        const assetName = asset.slice(56);
        return assetList.some(
          (a) => a["policy_id"] === policyId && a["asset_name"] === assetName,
        );
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
    // Koios expects the raw CBOR bytes as the request body
    const url = `${this.baseUrl}/submittx`;
    const cborBytes = Buffer.from(txCbor, "hex");
    const res = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/cbor" },
      body: cborBytes,
    });
    if (!res.ok) {
      throw new Error(`Koios submit failed ${res.status}: ${await res.text()}`);
    }
    const txHash = await res.text();
    return txHash.replace(/"/g, "").trim();
  }

  async fetchTxMetadata(txHash: string): Promise<unknown[]> {
    const result = await this.post("/tx_metadata", {
      _tx_hashes: [txHash],
    }) as unknown[] | null;
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

    // Koios returns all txs; apply count limit client-side
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
    };
  }
}

// ── Blockfrost provider (wraps @blockfrost/blockfrost-js) ───────────────────

class BlockfrostProvider implements CardanoProvider {
  readonly name = "blockfrost";
  private client: BlockFrostAPI;

  constructor(projectId: string, network: CardanoNetwork) {
    const baseUrl =
      network === "mainnet"
        ? "https://cardano-mainnet.blockfrost.io/api"
        : network === "preprod"
          ? "https://cardano-preprod.blockfrost.io/api"
          : "https://cardano-preview.blockfrost.io/api";

    this.client = new BlockFrostAPI({ projectId, customBackend: baseUrl });
  }

  async fetchUtxos(address: string, asset?: string): Promise<unknown[]> {
    try {
      if (asset) {
        return await this.client.addressesUtxosAssetAll(address, asset);
      }
      return await this.client.addressesUtxosAll(address);
    } catch (err: unknown) {
      if (this.is404(err)) return [];
      throw err;
    }
  }

  async fetchTip(): Promise<{ slot: number; block: number; time: number }> {
    const tip = await this.client.blocksLatest();
    return {
      slot: tip.slot ?? 0,
      block: tip.height ?? 0,
      time: tip.time,
    };
  }

  async submitTx(txCbor: string): Promise<string> {
    return await this.client.txSubmit(txCbor);
  }

  async fetchTxMetadata(txHash: string): Promise<unknown[]> {
    try {
      return await this.client.txsMetadata(txHash);
    } catch (err: unknown) {
      if (this.is404(err)) return [];
      throw err;
    }
  }

  async fetchAddressTransactions(
    address: string,
    options?: { count?: number; order?: "asc" | "desc" },
  ): Promise<unknown[]> {
    try {
      return await this.client.addressesTransactions(address, {
        count: options?.count,
        order: options?.order,
      });
    } catch (err: unknown) {
      if (this.is404(err)) return [];
      throw err;
    }
  }

  async fetchAssetAddresses(asset: string): Promise<Array<{ address: string; quantity: string }>> {
    try {
      const result = await this.client.assetsAddresses(asset);
      return result.map((r) => ({ address: r.address, quantity: r.quantity }));
    } catch (err: unknown) {
      if (this.is404(err)) return [];
      throw err;
    }
  }

  async fetchAddressInfo(address: string): Promise<unknown> {
    try {
      return await this.client.addresses(address);
    } catch (err: unknown) {
      if (this.is404(err)) return null;
      throw err;
    }
  }

  async fetchProtocolParams(): Promise<ProtocolParams> {
    const p = await this.client.epochsLatestParameters();
    // Blockfrost cost_models needs a separate call
    let costModelV3: number[] | undefined;
    try {
      const cm = p.cost_models as Record<string, unknown> | null;
      if (cm?.["PlutusV3"]) costModelV3 = cm["PlutusV3"] as number[];
    } catch { /* not available */ }
    return {
      minFeeA: p.min_fee_a,
      minFeeB: p.min_fee_b,
      coinsPerUtxoByte: Number(p.coins_per_utxo_size ?? "4310"),
      costModelV3,
    };
  }

  private is404(err: unknown): boolean {
    return (
      !!err &&
      typeof err === "object" &&
      "status_code" in err &&
      (err as { status_code: number }).status_code === 404
    );
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

// ── Legacy convenience exports (used by existing code) ──────────────────────

/** @deprecated Use getProvider() instead */
export function getBlockfrost(projectId: string, _network: CardanoNetwork): BlockFrostAPI {
  // The SDK auto-detects network from the project ID prefix (preprod/preview/mainnet)
  return new BlockFrostAPI({ projectId });
}

/** @deprecated Use provider.fetchUtxos() instead */
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

/** @deprecated Use provider.fetchTip() instead */
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

/** @deprecated Use provider.submitTx() instead */
export async function submitTx(client: BlockFrostAPI, txCbor: string): Promise<string> {
  return await client.txSubmit(txCbor);
}
