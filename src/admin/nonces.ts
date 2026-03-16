/**
 * Anti-replay nonce tracking for admin commands (block-height based)
 *
 * Nonces are block heights. The server rejects any nonce <= lastSeenNonce
 * (monotonically increasing). This eliminates wall-clock dependency and
 * prevents replay attacks permanently — metadata is on-chain forever,
 * but old nonces can never be reused because they'll always be <= lastSeen.
 *
 * Pruning: nonces older than 1 year are removed from the seen set to
 * prevent unbounded growth. The monotonic check (lastSeenNonce) still
 * protects against replays of pruned nonces.
 */

import * as fs from "fs";
import * as path from "path";

const NONCE_FILE = "/var/lib/blockhost/admin-nonces.json";
const NONCE_DIR = path.dirname(NONCE_FILE);

/** Approximately 1 year of Cardano blocks (~86400 blocks/day × 365) */
const PRUNE_AGE_BLOCKS = 31_536_000;

interface NonceStore {
  /** Highest nonce (block height) ever accepted — monotonic guard */
  lastSeenNonce: number;
  /** Set of seen nonces for diagnostics (pruned after ~1 year) */
  seenNonces: Record<string, number>;
}

let store: NonceStore = { lastSeenNonce: 0, seenNonces: {} };
let loaded = false;

/**
 * Ensure the nonce directory exists
 */
function ensureDir(): void {
  if (!fs.existsSync(NONCE_DIR)) {
    fs.mkdirSync(NONCE_DIR, { recursive: true });
  }
}

/**
 * Load nonces from persistent storage on startup
 */
export function loadNonces(): void {
  if (loaded) return;

  try {
    ensureDir();

    if (fs.existsSync(NONCE_FILE)) {
      const data = fs.readFileSync(NONCE_FILE, "utf8");
      const parsed = JSON.parse(data) as Partial<NonceStore>;

      // Handle migration from old wall-clock format
      if ("nonces" in parsed && !("lastSeenNonce" in parsed)) {
        // Old format: { nonces: { "abc": { timestamp: 123 } } }
        // Migrate: discard old nonces, start fresh with monotonic guard
        console.log(`[ADMIN] Migrating nonce store from wall-clock to block-height format`);
        store = { lastSeenNonce: 0, seenNonces: {} };
      } else {
        store = {
          lastSeenNonce: parsed.lastSeenNonce ?? 0,
          seenNonces: parsed.seenNonces ?? {},
        };
      }

      console.log(
        `[ADMIN] Loaded nonce store (lastSeen: ${store.lastSeenNonce}, tracked: ${Object.keys(store.seenNonces).length})`,
      );
    }
  } catch (err) {
    console.error(`[ADMIN] Error loading nonces: ${err}`);
    store = { lastSeenNonce: 0, seenNonces: {} };
  }

  loaded = true;
}

/**
 * Save nonces to persistent storage
 */
function saveNonces(): void {
  try {
    ensureDir();
    const tmp = NONCE_FILE + ".tmp";
    fs.writeFileSync(tmp, JSON.stringify(store, null, 2));
    fs.renameSync(tmp, NONCE_FILE);
  } catch (err) {
    console.error(`[ADMIN] Error saving nonces: ${err}`);
  }
}

/**
 * Check if a nonce has already been used.
 *
 * A nonce is rejected if:
 * 1. It's <= lastSeenNonce (monotonic guard prevents all replays), OR
 * 2. It's already in the seen set (duplicate in same batch)
 */
export function isNonceUsed(nonce: string): boolean {
  loadNonces();

  const nonceNum = parseInt(nonce, 10);
  if (isNaN(nonceNum)) return true; // Non-numeric nonces are always rejected

  // Monotonic guard: reject anything at or below the highest seen
  if (nonceNum <= store.lastSeenNonce) return true;

  // Also check the seen set (handles out-of-order within same prune window)
  return nonce in store.seenNonces;
}

/**
 * Mark a nonce as used (call BEFORE executing command).
 * Updates the monotonic high-water mark.
 */
export function markNonceUsed(nonce: string): void {
  loadNonces();

  const nonceNum = parseInt(nonce, 10);
  if (isNaN(nonceNum)) return;

  store.seenNonces[nonce] = nonceNum;

  if (nonceNum > store.lastSeenNonce) {
    store.lastSeenNonce = nonceNum;
  }

  saveNonces();
}

/**
 * Prune nonces older than ~1 year (by block height distance).
 * The monotonic guard still protects against replays of pruned nonces.
 *
 * @param _maxAgeSeconds - Ignored (kept for API compat during migration). Pruning is block-based.
 */
export function pruneOldNonces(_maxAgeSeconds?: number): void {
  loadNonces();

  const cutoff = store.lastSeenNonce - PRUNE_AGE_BLOCKS;
  if (cutoff <= 0) return; // Nothing old enough to prune

  let pruned = 0;
  for (const [nonce, height] of Object.entries(store.seenNonces)) {
    if (height < cutoff) {
      delete store.seenNonces[nonce];
      pruned++;
    }
  }

  if (pruned > 0) {
    console.log(`[ADMIN] Pruned ${pruned} old nonces (cutoff block: ${cutoff})`);
    saveNonces();
  }
}
