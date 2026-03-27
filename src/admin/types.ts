/**
 * Admin command types for HMAC-authenticated metadata protocol
 */

import type { ChildProcess } from "child_process";

/**
 * Admin command payload (parsed from transaction metadata)
 *
 * Wire format: "{nonce} {command}" + HMAC-SHA256(sharedKey)[:16 bytes]
 */
export interface AdminCommand {
  command: string;           // Command text (maps to action in command database)
  nonce: string;             // Anti-replay nonce
}

/**
 * Parameters for knock command action
 */
export interface KnockParams {
  ports?: number[];          // Ports to open (validated against allowed_ports)
  duration?: number;         // How long to keep ports open (seconds)
  source?: string;           // IPv6 address — if set, open ports only for this source
}

/**
 * Admin configuration from blockhost.yaml
 */
export interface AdminConfig {
  wallet_address: string;           // Admin wallet (bech32 addr1... or addr_test1...)
  shared_key: string;               // HMAC shared key (32-byte hex, no prefix)
  credential_nft_id?: string;       // Admin NFT token ID (optional)
  max_command_age?: number;         // Deprecated: pruning is now block-height based. Kept for config compat.
}

/**
 * Command definition in admin-commands.json
 */
export interface CommandDefinition {
  action: string;                    // Action type: 'knock', etc.
  description?: string;              // Admin reference only
  params: Record<string, unknown>;   // Per-command parameters (ports, duration, source)
  config?: Record<string, unknown>;  // Action constraints (allowed_ports, default_duration); defaults to params
}

/**
 * Command database structure (admin-commands.json)
 */
export interface CommandDatabase {
  commands: Record<string, CommandDefinition>;
}

/**
 * Knock action configuration (from command definition params)
 */
export interface KnockActionConfig {
  allowed_ports?: number[];         // Ports that can be opened (default: [22])
  default_duration?: number;        // Default duration if not specified (default: 300)
}

/**
 * Result of command execution
 */
export interface CommandResult {
  success: boolean;
  message: string;
  data?: unknown;
}

/**
 * Active knock state (tracked in memory)
 */
export interface ActiveKnock {
  txHash: string;
  ports: number[];
  source?: string;              // IPv6 source filter (if set, rules are per-source)
  startTime: number;
  duration: number;
  timeoutId: NodeJS.Timeout;
  loginSource?: string;         // IP narrowed to after login detection (phase 2)
  heartbeatInterval?: NodeJS.Timeout;  // Heartbeat file poller
  tailProcess?: ChildProcess;   // auth.log tail handle
}
