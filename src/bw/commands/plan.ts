/**
 * bw plan create <name> <price> [--interval-slots <n>]
 *
 * Create a plan reference UTXO with an inline PlanDatum at the server's own
 * address (or a known plan registry address).
 *
 * Uses the minimal tx toolkit (src/cardano/) — no Lucid.
 */

import type { Addressbook } from "../../fund-manager/types.js";
import { resolveToken } from "../cli-utils.js";
import { loadWeb3Config } from "../../fund-manager/web3-config.js";
import { getProvider } from "cmttk";
import { deriveWallet } from "cmttk";
import { Constr, Data, fromText } from "cmttk";
import { buildAndSubmitScriptTx } from "cmttk";
import * as fs from "fs";
import * as yaml from "js-yaml";
import { CONFIG_DIR, STATE_DIR, MIN_ADA_FOR_TOKEN_OUTPUT } from "../../paths.js";

// ── Datum encoding ───────────────────────────────────────────────────────────

/**
 * Encode a PlanDatum to CBOR hex.
 *
 * Aiken PlanDatum = Constr(0, [
 *   plan_id: Int,
 *   name: ByteArray,
 *   price_per_day: Int,
 *   accepted_payment_assets: List<Constr(0, [policy_id, asset_name])>,
 *   active: Bool (Aiken Bool = Constr(1,[]) for True, Constr(0,[]) for False)
 * ])
 */
function encodePlanDatum(
  planId: number,
  name: string,
  pricePerDay: bigint,
  acceptedAssets: Array<{ policyId: string; assetName: string }>,
  active: boolean,
): string {
  const assetList = acceptedAssets.map(
    (a) => new Constr(0, [a.policyId, a.assetName]),
  );
  // Aiken Bool: True = Constr(1, []), False = Constr(0, [])
  const activeBool = active ? new Constr(1, []) : new Constr(0, []);
  const d = new Constr(0, [
    BigInt(planId),
    fromText(name),
    pricePerDay,
    assetList,
    activeBool,
  ]);
  return Data.to(d);
}

// ── Auto-increment plan ID ───────────────────────────────────────────────────

function getNextPlanId(): number {
  const counterPath = `${STATE_DIR}/next-plan-id`;
  const lockPath = counterPath + ".lock";
  fs.mkdirSync(STATE_DIR, { recursive: true });

  let lockFd = -1;
  for (let i = 0; i < 50; i++) {
    try {
      lockFd = fs.openSync(lockPath, fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_WRONLY);
      break;
    } catch {
      if (i === 49) {
        try { fs.unlinkSync(lockPath); } catch {}
        try {
          lockFd = fs.openSync(lockPath, fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_WRONLY);
        } catch { /* give up */ }
        break;
      }
      const deadline = Date.now() + 100;
      while (Date.now() < deadline) {}
    }
  }

  try {
    let current = 1;
    try {
      const raw = fs.readFileSync(counterPath, "utf8").trim();
      const parsed = parseInt(raw, 10);
      if (!isNaN(parsed) && parsed > 0) current = parsed;
    } catch { /* file doesn't exist — start at 1 */ }
    fs.writeFileSync(counterPath, String(current + 1), "utf8");
    return current;
  } finally {
    if (lockFd >= 0) try { fs.closeSync(lockFd); } catch {}
    try { fs.unlinkSync(lockPath); } catch {}
  }
}

// ── CLI handler ──────────────────────────────────────────────────────────────

export async function planCommand(
  args: string[],
  book: Addressbook,
): Promise<void> {
  const [subCommand, ...rest] = args;

  if (subCommand === "create") {
    await planCreateCommand(rest, book);
    return;
  }

  console.error("Usage: bw plan create <name> <price> [--interval-slots <n>]");
  console.error("  Example: bw plan create basic 5000000");
  process.exit(1);
}

async function planCreateCommand(
  args: string[],
  book: Addressbook,
): Promise<void> {
  // Parse flags
  const positional: string[] = [];
  let intervalSlots: number | undefined;

  for (let i = 0; i < args.length; i++) {
    if (args[i] === "--interval-slots") {
      const val = args[i + 1];
      if (!val) {
        console.error("--interval-slots requires a value");
        process.exit(1);
      }
      intervalSlots = parseInt(val, 10);
      i++;
    } else {
      const arg = args[i];
      if (arg !== undefined) {
        positional.push(arg);
      }
    }
  }

  if (positional.length < 2) {
    console.error("Usage: bw plan create <name> <price> [--interval-slots <n>]");
    console.error("  <price> is in lovelace (or payment token base units) per day");
    process.exit(1);
  }

  const [name, priceStr] = positional;
  if (!name || !priceStr) {
    console.error("Usage: bw plan create <name> <price>");
    process.exit(1);
  }

  const pricePerDay = BigInt(priceStr);

  // Load web3 config to get accepted payment assets
  let acceptedAssets: Array<{ policyId: string; assetName: string }> = [];
  try {
    const web3 = loadWeb3Config();
    acceptedAssets.push({ policyId: "", assetName: "" });
    try {
      const stable = resolveToken("stable");
      if (stable.policyId !== "") {
        acceptedAssets.push(stable);
      }
    } catch {
      // no stable token configured — ADA only
    }
    void web3;
  } catch {
    acceptedAssets = [{ policyId: "", assetName: "" }];
  }

  // Determine signing role
  const signingRole =
    book["server"]?.keyfile
      ? "server"
      : Object.entries(book).find(([, e]) => e.keyfile)?.[0];
  if (!signingRole) throw new Error("No signing wallet available in addressbook");

  const signerEntry = book[signingRole]!;
  const mnemonic = fs.readFileSync(signerEntry.keyfile!, "utf8").trim();
  const { network, blockfrostProjectId, koiosUrl } = loadWeb3Config();
  const wallet = await deriveWallet(mnemonic, network);
  const provider = getProvider(network, blockfrostProjectId || undefined, koiosUrl || undefined);

  // Persistent auto-increment plan ID
  const planId = getNextPlanId();

  // Encode the datum
  const datumCbor = encodePlanDatum(planId, name, pricePerDay, acceptedAssets, true);

  // Read the subscription validator address from config — plans are stored there
  // so the signup page can find them
  let planAddress = wallet.address; // fallback to deployer address
  try {
    const w3 = yaml.load(fs.readFileSync(`${CONFIG_DIR}/web3-defaults.yaml`, "utf8")) as Record<string, Record<string, string>>;
    const validatorAddr = w3?.["blockchain"]?.["subscription_validator_address"];
    if (validatorAddr) planAddress = validatorAddr;
  } catch { /* use fallback */ }

  // Create the plan reference UTXO at the validator address
  const txHash = await buildAndSubmitScriptTx({
    provider,
    walletAddress: wallet.address,
    scriptInputs: [],
    outputs: [{
      address: planAddress,
      assets: { lovelace: MIN_ADA_FOR_TOKEN_OUTPUT },
      datumCbor,
    }],
    signingKey: new Uint8Array([...wallet.paymentKey]),
  });

  console.log(txHash);
  const intervalInfo = intervalSlots ? `, interval=${intervalSlots} slots` : "";
  console.error(`Plan "${name}" created: id=${planId}, price=${pricePerDay.toString()}/day${intervalInfo}`);
}
