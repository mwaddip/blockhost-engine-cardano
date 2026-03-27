/**
 * Knock command handler - opens firewall ports temporarily
 *
 * Two-phase lifecycle:
 *   Phase 1 (pre-login): Ports open (wide or source-filtered). default_duration timeout applies.
 *     Heartbeat poller watches for /run/blockhost/knock.active to appear.
 *   Phase 2 (post-login): .active detected → read IP → close old rules → reopen for that IP
 *     only → cancel duration timeout → poll .active mtime, close when stale (15 min).
 */

import { spawn } from "child_process";
import * as fs from "fs";
import * as net from "net";
import type { CommandResult, KnockParams, KnockActionConfig, ActiveKnock } from "../types.js";
import { iptablesOpen, iptablesClose } from "../../root-agent/client.js";

// Track active knocks in memory
const activeKnocks: Map<string, ActiveKnock> = new Map();

// --- Constants ---

const KNOCK_ACTIVE_FILE = "/run/blockhost/knock.active";
const HEARTBEAT_POLL_MS = 30_000;       // 30s poll interval
const HEARTBEAT_STALE_MS = 15 * 60_000; // 15 min staleness threshold
const MAX_KNOCK_DURATION_S = 3600;      // 1 hour hard cap on pre-login duration

// --- IP Validation ---

/**
 * Validate an IP address (IPv4 or IPv6) using net.isIP().
 * Defense against injection via .active file content.
 */
function isValidIP(addr: string): boolean {
  if (!addr || /\s/.test(addr)) return false;
  return net.isIP(addr) !== 0;
}

/**
 * Validate an IPv6 address (basic format check)
 */
function isValidIPv6(addr: string): boolean {
  if (!addr || /\s/.test(addr)) return false;
  return net.isIPv6(addr);
}

// --- Active File Helpers ---

function writeActiveFile(ip: string): void {
  try {
    fs.writeFileSync(KNOCK_ACTIVE_FILE, ip + "\n", { mode: 0o644 });
  } catch (err) {
    console.warn(`[KNOCK] Failed to write ${KNOCK_ACTIVE_FILE}: ${err}`);
  }
}

function readActiveFile(): { ip: string; mtime: number } | null {
  try {
    const stat = fs.statSync(KNOCK_ACTIVE_FILE);
    const content = fs.readFileSync(KNOCK_ACTIVE_FILE, "utf-8").trim();
    if (!isValidIP(content)) {
      console.warn(`[KNOCK] Invalid IP in ${KNOCK_ACTIVE_FILE}: ${content.slice(0, 60)}`);
      return null;
    }
    return { ip: content, mtime: stat.mtimeMs };
  } catch {
    return null;
  }
}

function removeActiveFile(): void {
  try {
    fs.unlinkSync(KNOCK_ACTIVE_FILE);
  } catch {
    // File already gone — fine
  }
}

// --- Port Operations ---

/**
 * Open a single port via root agent
 */
async function openPort(port: number, source?: string): Promise<void> {
  const label = source ? ` for ${source}` : "";
  console.log(`[KNOCK] Opening port ${port}${label} via root agent`);
  await iptablesOpen(port, "tcp", "blockhost-knock", source);
}

/**
 * Close a single port via root agent
 */
async function closePort(port: number, source?: string): Promise<void> {
  const label = source ? ` for ${source}` : "";
  console.log(`[KNOCK] Closing port ${port}${label} via root agent`);
  try {
    await iptablesClose(port, "tcp", "blockhost-knock", source);
  } catch (err) {
    console.warn(`[KNOCK] Could not remove rule for port ${port}: ${err}`);
  }
}

// --- Phase Transition ---

/**
 * Transition from phase 1 (wide open) to phase 2 (per-IP).
 * Idempotent — returns early if loginSource already set.
 */
async function transitionToPostLogin(txHash: string, loginIp: string): Promise<void> {
  const knock = activeKnocks.get(txHash);
  if (!knock) return;

  // Idempotent: already transitioned
  if (knock.loginSource) return;

  console.log(`[KNOCK] Transitioning to post-login for IP ${loginIp} (tx: ${txHash})`);

  // Close old (phase 1) rules using the original source filter
  for (const port of knock.ports) {
    await closePort(port, knock.source);
  }

  // Open per-IP rules
  for (const port of knock.ports) {
    await openPort(port, loginIp);
  }

  // Cancel duration timeout — heartbeat manages lifetime now
  clearTimeout(knock.timeoutId);

  // Record login source and kill tail process (no longer needed if heartbeat drives)
  knock.loginSource = loginIp;
  if (knock.tailProcess) {
    knock.tailProcess.kill();
    knock.tailProcess = undefined;
  }

  console.log(`[KNOCK] Post-login: ports ${knock.ports.join(", ")} narrowed to ${loginIp}`);
}

// --- Heartbeat Poller ---

/**
 * Start the heartbeat poller for a knock session.
 *
 * Phase 1: polls for .active to appear → calls transitionToPostLogin
 * Phase 2: polls .active mtime → closes knock when stale or removed
 *
 * Also cleans stale .active from a previous crash on startup.
 */
function startHeartbeatPoller(txHash: string): void {
  const knock = activeKnocks.get(txHash);
  if (!knock) return;

  // Clean stale .active from previous crash
  const existing = readActiveFile();
  if (existing) {
    console.log(`[KNOCK] Removing stale ${KNOCK_ACTIVE_FILE} from previous session`);
    removeActiveFile();
  }

  knock.heartbeatInterval = setInterval(() => {
    const current = activeKnocks.get(txHash);
    if (!current) {
      // Knock was closed externally — stop polling
      clearInterval(knock.heartbeatInterval!);
      return;
    }

    const active = readActiveFile();

    if (!current.loginSource) {
      // Phase 1: waiting for .active to appear
      if (active) {
        transitionToPostLogin(txHash, active.ip).catch((err) => {
          console.error(`[KNOCK] Heartbeat transition error: ${err}`);
        });
      }
    } else {
      // Phase 2: check staleness
      if (!active) {
        console.log(`[KNOCK] ${KNOCK_ACTIVE_FILE} removed, closing knock`);
        closeKnock(txHash, "heartbeat-removed").catch((err) => {
          console.error(`[KNOCK] Error closing knock on file removal: ${err}`);
        });
        return;
      }

      const age = Date.now() - active.mtime;
      if (age > HEARTBEAT_STALE_MS) {
        console.log(
          `[KNOCK] ${KNOCK_ACTIVE_FILE} stale (${Math.round(age / 60_000)}min), closing knock`,
        );
        closeKnock(txHash, "heartbeat-stale").catch((err) => {
          console.error(`[KNOCK] Error closing knock on staleness: ${err}`);
        });
      }
    }
  }, HEARTBEAT_POLL_MS);
}

// --- Auth Log Monitor ---

/**
 * Monitor auth.log for successful SSH login.
 *
 * On detection: extract IP, validate, write .active, call transitionToPostLogin.
 * Handles both IPv4 and IPv6 source addresses.
 */
function startAuthLogMonitor(txHash: string, ports: number[]): void {
  const knock = activeKnocks.get(txHash);
  if (!knock) return;

  // Only monitor if port 22 is in the list
  if (!ports.includes(22)) {
    return;
  }

  const authLogPath = "/var/log/auth.log";
  if (!fs.existsSync(authLogPath)) {
    console.log(`[KNOCK] Auth log not found, skipping login monitoring`);
    return;
  }

  console.log(`[KNOCK] Monitoring ${authLogPath} for SSH login...`);

  const tail = spawn("tail", ["-F", "-n", "0", authLogPath]);
  knock.tailProcess = tail;

  let buffer = "";

  tail.stdout.on("data", (data: Buffer) => {
    buffer += data.toString();
    const lines = buffer.split("\n");
    buffer = lines.pop() || ""; // Keep incomplete line

    for (const line of lines) {
      // Look for successful SSH login
      // Format: "Accepted publickey for user from IP port PORT ssh2"
      if (line.includes("Accepted") && line.includes("ssh2")) {
        console.log(`[KNOCK] Detected SSH login: ${line}`);

        // Extract source IP (IPv4 or IPv6)
        const match = line.match(/from\s+(\S+)\s+port\s+/);
        const matchedIp = match?.[1];
        if (matchedIp && isValidIP(matchedIp)) {
          console.log(`[KNOCK] Login from IP: ${matchedIp}`);

          writeActiveFile(matchedIp);
          transitionToPostLogin(txHash, matchedIp).catch((err) => {
            console.warn(`[KNOCK] Error transitioning after SSH login: ${err}`);
          });
        } else {
          console.warn(`[KNOCK] Could not extract valid IP from login line`);
        }
        return;
      }
    }
  });

  tail.on("error", (err) => {
    console.warn(`[KNOCK] Auth log monitor error: ${err}`);
  });
}

// --- Close Knock ---

/**
 * Close a knock session. Handles both phases:
 *   Phase 2 (loginSource set): close per-IP rules
 *   Phase 1 (no loginSource): close original source-filtered rules
 */
async function closeKnock(txHash: string, reason: string): Promise<void> {
  const knock = activeKnocks.get(txHash);
  if (!knock) {
    return;
  }

  console.log(`[KNOCK] Closing knock session (reason: ${reason}, tx: ${txHash})`);

  // Clear all timers and processes
  clearTimeout(knock.timeoutId);
  if (knock.heartbeatInterval) {
    clearInterval(knock.heartbeatInterval);
  }
  if (knock.tailProcess) {
    knock.tailProcess.kill();
  }

  // Close ports — use loginSource (phase 2) or original source (phase 1)
  const closeSource = knock.loginSource ?? knock.source;
  for (const port of knock.ports) {
    await closePort(port, closeSource);
  }

  // Remove .active file
  removeActiveFile();

  // Remove from active knocks
  activeKnocks.delete(txHash);

  console.log(`[KNOCK] Knock session closed: ${knock.ports.join(", ")}`);
}

// --- Execute Knock ---

/**
 * Execute the knock command
 */
export async function executeKnock(
  params: KnockParams,
  config: KnockActionConfig,
  txHash: string,
): Promise<CommandResult> {
  // Merge params with defaults from config
  const allowedPorts = config.allowed_ports ?? [22];
  const defaultDuration = config.default_duration ?? 300;

  // Validate and sanitize ports
  const requestedPorts = params.ports ?? allowedPorts;
  const ports = requestedPorts.filter((port) => {
    if (!Number.isInteger(port) || port < 1 || port > 65535) {
      console.warn(`[KNOCK] Invalid port number: ${port}`);
      return false;
    }
    if (!allowedPorts.includes(port)) {
      console.warn(`[KNOCK] Port not allowed: ${port}`);
      return false;
    }
    return true;
  });

  if (ports.length === 0) {
    return {
      success: false,
      message: "No valid ports to open",
    };
  }

  // Validate duration (capped to prevent indefinitely open ports)
  const duration = Math.min(
    Math.max(1, params.duration ?? defaultDuration),
    MAX_KNOCK_DURATION_S,
  );

  // Validate optional source IPv6 address
  const source = params.source;
  if (source && !isValidIPv6(source)) {
    return {
      success: false,
      message: `Invalid IPv6 source address: ${source}`,
    };
  }

  const sourceLabel = source ? ` for ${source}` : "";
  console.log(
    `[KNOCK] Opening ports ${ports.join(", ")}${sourceLabel} for ${duration}s (tx: ${txHash})`,
  );

  try {
    // Open ports via root agent
    for (const port of ports) {
      await openPort(port, source);
    }

    // Set timeout to close ports (phase 1 duration limit)
    const timeoutId = setTimeout(() => {
      closeKnock(txHash, "timeout").catch((err) => {
        console.error(`[KNOCK] Error closing knock on timeout: ${err}`);
      });
    }, duration * 1000);

    // Track this knock
    activeKnocks.set(txHash, {
      txHash,
      ports,
      source,
      startTime: Date.now(),
      duration,
      timeoutId,
    });

    // Start heartbeat poller (handles both phase transitions and staleness)
    startHeartbeatPoller(txHash);

    // Start monitoring auth.log for SSH login
    startAuthLogMonitor(txHash, ports);

    return {
      success: true,
      message: `Opened ports ${ports.join(", ")}${sourceLabel} for ${duration} seconds`,
      data: { ports, duration, source, txHash },
    };
  } catch (err) {
    console.error(`[KNOCK] Error opening ports: ${err}`);
    // Clean up any partially opened ports
    for (const port of ports) {
      try {
        await closePort(port, source);
      } catch {
        // Ignore cleanup errors
      }
    }
    return {
      success: false,
      message: `Failed to open ports: ${err}`,
    };
  }
}

/**
 * Close all active knocks (for shutdown)
 */
export async function closeAllKnocks(): Promise<void> {
  console.log(`[KNOCK] Closing ${activeKnocks.size} active knock sessions`);
  for (const txHash of activeKnocks.keys()) {
    await closeKnock(txHash, "shutdown");
  }
}
