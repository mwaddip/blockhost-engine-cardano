/**
 * Shared path constants and environment configuration.
 *
 * All path constants that were previously duplicated across modules
 * are centralized here. Import from this module instead of redeclaring.
 */

/** Root config directory */
export const CONFIG_DIR = process.env["BLOCKHOST_CONFIG_DIR"] ?? "/etc/blockhost";

/** Root state directory */
export const STATE_DIR = process.env["BLOCKHOST_STATE_DIR"] ?? "/var/lib/blockhost";

/** Addressbook JSON file */
export const ADDRESSBOOK_PATH = `${CONFIG_DIR}/addressbook.json`;

/** web3-defaults.yaml config */
export const WEB3_DEFAULTS_PATH = `${CONFIG_DIR}/web3-defaults.yaml`;

/** blockhost.yaml config */
export const BLOCKHOST_CONFIG_PATH = `${CONFIG_DIR}/blockhost.yaml`;

/** Aiken blueprint (plutus.json) */
export const PLUTUS_JSON_PATH = `${CONFIG_DIR}/plutus.json`;

/** Testing mode flag file */
export const TESTING_MODE_FILE = "/etc/blockhost/.testing-mode";

/** VMs database */
export const VMS_JSON_PATH = `${STATE_DIR}/vms.json`;

/** Minimum ADA for outputs carrying native tokens */
export const MIN_ADA_FOR_TOKEN_OUTPUT = 2_000_000n;

/** Timeout for Python subprocesses (ms) */
export const PYTHON_TIMEOUT_MS = 10_000;
