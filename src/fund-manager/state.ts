/**
 * State persistence for fund-manager
 * Tracks last run times to survive monitor restarts
 */

import * as fs from "fs";
import * as path from "path";
import type { FundManagerState } from "./types.js";

const STATE_FILE = "/var/lib/blockhost/fund-manager-state.json";
const STATE_DIR = path.dirname(STATE_FILE);

const DEFAULT_STATE: FundManagerState = {
  last_fund_cycle: 0,
  last_gas_check: 0,
  hot_wallet_generated: false,
};

let cachedState: FundManagerState | null = null;

function ensureDir(): void {
  if (!fs.existsSync(STATE_DIR)) {
    fs.mkdirSync(STATE_DIR, { recursive: true });
  }
}

/**
 * Load state from persistent storage
 */
export function loadState(): FundManagerState {
  if (cachedState) return cachedState;

  try {
    ensureDir();
    if (fs.existsSync(STATE_FILE)) {
      const data = fs.readFileSync(STATE_FILE, "utf8");
      const state: FundManagerState = { ...DEFAULT_STATE, ...JSON.parse(data) };
      cachedState = state;
      return state;
    }
  } catch (err) {
    console.error(`[FUND] Error loading state: ${err}`);
  }

  cachedState = { ...DEFAULT_STATE };
  return cachedState;
}

/**
 * Save state to persistent storage
 */
function saveState(state: FundManagerState): void {
  try {
    ensureDir();
    const tmp = STATE_FILE + ".tmp";
    fs.writeFileSync(tmp, JSON.stringify(state, null, 2));
    fs.renameSync(tmp, STATE_FILE);
    cachedState = state;
  } catch (err) {
    console.error(`[FUND] Error saving state: ${err}`);
  }
}

/**
 * Update a single field and persist
 */
export function updateState(partial: Partial<FundManagerState>): void {
  const state = loadState();
  Object.assign(state, partial);
  saveState(state);
}
