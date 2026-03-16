/**
 * web3-auth-svc — HTTPS signing server for Cardano CIP-30 authentication.
 *
 * Serves the signing page and provides callback endpoints for the PAM module's
 * session-based authentication flow. Accepts CIP-30 COSE_Sign1 signatures and
 * writes structured .sig files for the PAM verifier. Compiled to a standalone
 * bundle for deployment on VMs.
 *
 * Routes:
 *   GET /                           — Serve signing page HTML
 *   GET /engine.js                  — Serve signing page engine JS
 *   GET /auth/pending/:session_id   — Return session JSON from pending dir
 *   POST /auth/callback/:session_id — Accept CIP-30 signature, write .sig file
 *
 * Config: /etc/web3-auth/config.toml (TOML, [https] section)
 *
 * .sig file format (JSON):
 *   { chain, signature, public_key, otp, machine_id }
 *   chain = "cardano" — tells the PAM module which verification plugin to use
 *
 * SPECIAL profile: S7 P9 E8 C5 I7 A7 L7
 *   P9: Auth boundary — validate every input, trust nothing from the network.
 *   E8: Long-running daemon — must not crash, must not leak.
 *
 * TODO: Full COSE_Sign1 + Ed25519 cryptographic verification.
 *   Steps 3-5 below require cbor/cose libraries not yet available in the bundle:
 *     3. Parse COSE_Sign1 structure and verify the protected headers
 *     4. Extract the Ed25519 public key from the COSE_Key structure
 *     5. Verify the Ed25519 signature over COSE SigStructure bytes
 *   Currently: OTP timing-safe compare + field validation. Crypto verification deferred.
 */

import * as https from "node:https";
import * as fs from "node:fs";
import * as path from "node:path";
import { timingSafeEqual } from "node:crypto";

// ── Constants ──────────────────────────────────────────────────────────

const DEFAULT_PENDING_DIR = "/run/libpam-web3/pending";
let PENDING_DIR = DEFAULT_PENDING_DIR;
const MAX_BODY_SIZE = 16_384;
const DEFAULT_CONFIG_PATH = "/etc/web3-auth/config.toml";

const SESSION_ID_RE = /^[0-9a-f]{32}$/;
// Hex strings for COSE_Sign1 signature and COSE_Key from CIP-30 signData
const HEX_RE = /^[0-9a-fA-F]+$/;

// ── Config ─────────────────────────────────────────────────────────────

interface HttpsConfig {
  port: number;
  bind: string;
  cert_path: string;
  key_path: string;
  signing_page_path: string;
  pending_dir: string;
}

/**
 * Minimal TOML parser for the [https] section. Handles string values,
 * integers, and single-line string arrays. No external dependencies.
 */
function parseToml(content: string): Record<string, Record<string, unknown>> {
  const result: Record<string, Record<string, unknown>> = {};
  let section = "";

  for (const raw of content.split("\n")) {
    const line = raw.trim();
    if (!line || line.startsWith("#")) continue;

    const secMatch = line.match(/^\[([a-zA-Z_][a-zA-Z0-9_]*)\]$/);
    if (secMatch?.[1]) {
      section = secMatch[1];
      result[section] = result[section] || {};
      continue;
    }

    const kvMatch = line.match(/^([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*(.+)$/);
    if (!kvMatch?.[1] || !kvMatch[2] || !section) continue;

    const key = kvMatch[1];
    const val = kvMatch[2].trim();

    if (val.startsWith('"') && val.endsWith('"')) {
      result[section]![key] = val.slice(1, -1);
    } else if (val.startsWith("[")) {
      const inner = val.slice(1, val.lastIndexOf("]"));
      result[section]![key] = inner
        .split(",")
        .map((s) => s.trim())
        .filter((s) => s.length > 0)
        .map((s) => (s.startsWith('"') && s.endsWith('"') ? s.slice(1, -1) : s));
    } else {
      const num = Number(val);
      result[section]![key] = Number.isNaN(num) ? val : num;
    }
  }

  return result;
}

function loadConfig(configPath: string): HttpsConfig {
  const content = fs.readFileSync(configPath, "utf8");
  const toml = parseToml(content);
  const sec = toml["https"];

  if (!sec) {
    throw new Error(`missing [https] section in ${configPath}`);
  }

  const port = typeof sec.port === "number" ? sec.port : 8443;
  const bind =
    Array.isArray(sec.bind) && sec.bind.length > 0 ? String(sec.bind[0]) : "::";
  const cert_path = String(sec.cert_path || "");
  const key_path = String(sec.key_path || "");
  const signing_page_path = String(
    sec.signing_page_path || "/usr/share/blockhost/signing-page/index.html"
  );
  const pending_dir = String(sec.pending_dir || DEFAULT_PENDING_DIR);

  if (!cert_path) throw new Error("https.cert_path is required");
  if (!key_path) throw new Error("https.key_path is required");

  return { port, bind, cert_path, key_path, signing_page_path, pending_dir };
}

// ── Validation ────────────────────────────────────────────────────────

function isValidSessionId(id: string): boolean {
  return SESSION_ID_RE.test(id);
}

/** Validate a hex string from CIP-30 signData result. */
function isValidHex(str: string): boolean {
  return str.length > 0 && str.length % 2 === 0 && HEX_RE.test(str);
}

// ── Payload Types ─────────────────────────────────────────────────────

/**
 * POST body from the CIP-30 signing page callback.
 *   signature  — hex-encoded COSE_Sign1 structure from api.signData()
 *   key        — hex-encoded COSE_Key (public key) from api.signData()
 *   otp        — the OTP code the user entered
 *   machineId  — the machine identifier the user entered
 */
interface CallbackPayload {
  signature: string;
  key: string;
  otp: string;
  machineId: string;
}

/**
 * Parse and validate the callback POST body.
 * Rejects unknown fields to prevent injection of unexpected data.
 */
function parseCallbackBody(body: string): CallbackPayload | null {
  let parsed: unknown;
  try {
    parsed = JSON.parse(body);
  } catch {
    return null;
  }

  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    return null;
  }

  const obj = parsed as Record<string, unknown>;
  const keys = Object.keys(obj);

  if (keys.length !== 4) return null;
  if (typeof obj["signature"] !== "string") return null;
  if (typeof obj["key"] !== "string") return null;
  if (typeof obj["otp"] !== "string") return null;
  if (typeof obj["machineId"] !== "string") return null;

  // Sanity bounds: OTP short numeric, machineId reasonable length
  if (obj["otp"].length > 16 || obj["machineId"].length > 128) return null;

  // Validate hex encoding of CIP-30 fields
  if (!isValidHex(obj["signature"])) return null;
  if (!isValidHex(obj["key"])) return null;

  return {
    signature: obj["signature"],
    key: obj["key"],
    otp: obj["otp"],
    machineId: obj["machineId"],
  };
}

// ── Session ───────────────────────────────────────────────────────────

interface SessionData {
  otp: string;
  machine_id: string;
}

function readSession(sessionId: string): SessionData | null {
  const jsonPath = path.join(PENDING_DIR, `${sessionId}.json`);
  try {
    const content = fs.readFileSync(jsonPath, "utf8");
    const parsed: unknown = JSON.parse(content);
    if (typeof parsed !== "object" || parsed === null) return null;
    const obj = parsed as Record<string, unknown>;
    if (typeof obj["otp"] !== "string" || typeof obj["machine_id"] !== "string") {
      return null;
    }
    return { otp: obj["otp"], machine_id: obj["machine_id"] };
  } catch {
    return null;
  }
}

// ── Verification & .sig Write ─────────────────────────────────────────

/**
 * Structured .sig content for Cardano CIP-30 authentication.
 * The `chain` field tells the PAM module which verification plugin to use.
 */
interface CardanoSigFile {
  chain: "cardano";
  signature: string;
  public_key: string;
  otp: string;
  machine_id: string;
}

/**
 * Validate the callback payload, check OTP, and write the .sig file.
 *
 * Returns null on success, or an error string describing the failure.
 * Error strings are safe to log but must NOT be returned to the client
 * (they may reveal internal state).
 *
 * Cryptographic verification of the COSE_Sign1 structure is deferred — the
 * PAM verifier plugin performs full Ed25519 verification when it reads the
 * .sig file. The auth-svc validates OTP timing-safe and ensures structural
 * integrity of the hex fields before writing.
 */
function validateAndWriteSig(sessionId: string, payload: CallbackPayload): string | null {
  // First-claim-wins: prevent overwrite of existing .sig
  const sigPath = path.join(PENDING_DIR, `${sessionId}.sig`);
  if (fs.existsSync(sigPath)) return "session already processed";

  // Load session and cross-check OTP + machine_id
  const session = readSession(sessionId);
  if (!session) return "session not found or malformed";

  // Timing-safe OTP comparison to resist timing oracle attacks
  const otpA = Buffer.from(payload.otp);
  const otpB = Buffer.from(session.otp);
  if (otpA.length !== otpB.length) return "otp mismatch";
  if (!timingSafeEqual(otpA, otpB)) return "otp mismatch";

  if (payload.machineId !== session.machine_id) return "machine_id mismatch";

  // TODO: Full COSE_Sign1 cryptographic verification (deferred — needs cbor/cose libs):
  //   1. CBOR-decode payload.signature as COSE_Sign1 array
  //   2. Verify protected header contains alg=-8 (EdDSA)
  //   3. CBOR-decode payload.key as COSE_Key, extract crv=Ed25519, x=public_key_bytes
  //   4. Reconstruct Sig_Structure: ["Signature1", protected, b"", payload_bytes]
  //      where payload_bytes = UTF-8("Authenticate to {machineId} with code: {otp}")
  //   5. Verify Ed25519 signature over CBOR(Sig_Structure) using extracted public key

  // Build structured .sig content
  const sigContent: CardanoSigFile = {
    chain: "cardano",
    signature: payload.signature,
    public_key: payload.key,
    otp: payload.otp,
    machine_id: payload.machineId,
  };

  // Atomic write: tmp → rename (prevents partial reads by PAM)
  const tmpPath = path.join(PENDING_DIR, `${sessionId}.sig.tmp`);
  try {
    fs.writeFileSync(tmpPath, JSON.stringify(sigContent));
    fs.renameSync(tmpPath, sigPath);
  } catch (err) {
    try {
      fs.unlinkSync(tmpPath);
    } catch {
      // tmp may not exist
    }
    return `sig file write failed: ${err instanceof Error ? err.message : String(err)}`;
  }

  console.log(`[AUTH] Accepted CIP-30 signature for session ${sessionId}`);
  return null;
}

// ── Route Handlers ────────────────────────────────────────────────────

function sendResponse(
  res: import("node:http").ServerResponse,
  statusCode: number,
  body: string,
  contentType = "text/plain"
): void {
  res.writeHead(statusCode, { "Content-Type": contentType });
  res.end(body);
}

function handleGetPending(
  sessionId: string,
  res: import("node:http").ServerResponse
): void {
  if (!isValidSessionId(sessionId)) {
    sendResponse(res, 404, "Not Found");
    return;
  }

  const jsonPath = path.join(PENDING_DIR, `${sessionId}.json`);

  let contents: string;
  try {
    contents = fs.readFileSync(jsonPath, "utf8");
  } catch {
    sendResponse(res, 404, "Not Found");
    return;
  }

  sendResponse(res, 200, contents, "application/json");
}

function handlePostCallback(
  sessionId: string,
  req: import("node:http").IncomingMessage,
  res: import("node:http").ServerResponse
): void {
  if (!isValidSessionId(sessionId)) {
    sendResponse(res, 404, "Not Found");
    return;
  }

  // Content-Type must be JSON
  const contentType = req.headers["content-type"] || "";
  if (!contentType.includes("application/json")) {
    sendResponse(res, 400, "Content-Type must be application/json");
    return;
  }

  const chunks: Buffer[] = [];
  let bodySize = 0;
  let aborted = false;

  req.on("data", (chunk: Buffer) => {
    bodySize += chunk.length;
    if (bodySize > MAX_BODY_SIZE) {
      if (!aborted) {
        aborted = true;
        sendResponse(res, 413, "body too large");
        req.destroy();
      }
      return;
    }
    chunks.push(chunk);
  });

  req.on("end", () => {
    if (aborted) return;

    const body = Buffer.concat(chunks).toString("utf8").trim();

    const payload = parseCallbackBody(body);
    if (!payload) {
      sendResponse(res, 400, "invalid request body");
      return;
    }

    const error = validateAndWriteSig(sessionId, payload);

    if (error === null) {
      sendResponse(res, 200, "OK");
    } else if (error === "session already processed") {
      sendResponse(res, 409, "Conflict");
    } else if (error === "session not found or malformed") {
      sendResponse(res, 404, "Not Found");
    } else {
      // P9: never leak internal error details to the network
      console.error(`[AUTH] Callback rejected for session ${sessionId}: ${error}`);
      sendResponse(res, 400, "verification failed");
    }
  });

  req.on("error", () => {
    // Connection closed by client
  });
}

// ── Server ────────────────────────────────────────────────────────────

function main(): void {
  const configPath = process.argv[2] || DEFAULT_CONFIG_PATH;
  const config = loadConfig(configPath);
  PENDING_DIR = config.pending_dir;

  let signingPageHtml: string;
  try {
    signingPageHtml = fs.readFileSync(config.signing_page_path, "utf8");
  } catch (err) {
    console.error(
      `Failed to read signing page: ${config.signing_page_path}: ${err}`
    );
    process.exit(1);
  }

  // Load engine.js from the same directory as the signing page
  const signingPageDir = path.dirname(config.signing_page_path);
  let engineJs = "";
  try {
    engineJs = fs.readFileSync(path.join(signingPageDir, "engine.js"), "utf8");
  } catch {
    console.log("[AUTH] No engine.js found — signing page uses inline JS");
  }

  const tlsOptions: https.ServerOptions = {
    cert: fs.readFileSync(config.cert_path),
    key: fs.readFileSync(config.key_path),
  };

  const server = https.createServer(tlsOptions, (req, res) => {
    res.setHeader("X-Content-Type-Options", "nosniff");
    res.setHeader("Cache-Control", "no-store");

    const url = new URL(req.url || "/", "https://localhost");
    const pathname = url.pathname;

    // GET / — serve CIP-30 signing page
    if (req.method === "GET" && pathname === "/") {
      sendResponse(res, 200, signingPageHtml, "text/html; charset=utf-8");
      return;
    }

    // GET /engine.js — serve wallet interaction bundle
    if (req.method === "GET" && pathname === "/engine.js" && engineJs) {
      sendResponse(res, 200, engineJs, "application/javascript; charset=utf-8");
      return;
    }

    // GET /auth/pending/:session_id
    const pendingMatch = pathname.match(/^\/auth\/pending\/([^/]+)$/);
    if (req.method === "GET" && pendingMatch?.[1]) {
      handleGetPending(pendingMatch[1], res);
      return;
    }

    // POST /auth/callback/:session_id
    const callbackMatch = pathname.match(/^\/auth\/callback\/([^/]+)$/);
    if (req.method === "POST" && callbackMatch?.[1]) {
      handlePostCallback(callbackMatch[1], req, res);
      return;
    }

    sendResponse(res, 404, "Not Found");
  });

  // Dual-stack bind: listen on IPv6 (which also accepts IPv4 on Linux)
  server.listen(config.port, config.bind, () => {
    console.log(
      `[AUTH] web3-auth-svc (cardano) listening on [${config.bind}]:${config.port}`
    );
    console.log(`[AUTH] Signing page: ${config.signing_page_path}`);
    console.log(`[AUTH] Pending dir: ${PENDING_DIR}`);
  });

  server.on("error", (err) => {
    console.error(`[AUTH] Server error: ${err}`);
    process.exit(1);
  });

  process.on("SIGTERM", () => {
    console.log("[AUTH] Shutting down...");
    server.close(() => process.exit(0));
  });

  process.on("SIGINT", () => {
    console.log("[AUTH] Shutting down...");
    server.close(() => process.exit(0));
  });
}

main();
