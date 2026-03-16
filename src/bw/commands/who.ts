/**
 * bw who <identifier>
 *
 * Query the holder of a CIP-68 (222) user token.
 *
 * Forms:
 *   bw who <nft_id>    — who holds NFT token ID? (integer)
 *   bw who admin       — who holds the admin NFT? (reads blockhost.yaml)
 *
 * Reads nft_policy_id and blockfrost_project_id from web3-defaults.yaml.
 * Reads admin.credential_nft_id from /etc/blockhost/blockhost.yaml.
 */

import * as fs from "fs";
import * as yaml from "js-yaml";
import { findNftHolder } from "../../nft/reference.js";
import { getBlockfrostClient } from "../cli-utils.js";
import { loadWeb3Config } from "../../fund-manager/web3-config.js";

const CONFIG_DIR = process.env["BLOCKHOST_CONFIG_DIR"] ?? "/etc/blockhost";
const BLOCKHOST_CONFIG_PATH = `${CONFIG_DIR}/blockhost.yaml`;

// ── Admin NFT ID loader ───────────────────────────────────────────────────────

function loadAdminNftId(): number {
  if (!fs.existsSync(BLOCKHOST_CONFIG_PATH)) {
    throw new Error(`Config not found: ${BLOCKHOST_CONFIG_PATH}`);
  }

  const raw = yaml.load(
    fs.readFileSync(BLOCKHOST_CONFIG_PATH, "utf8"),
  ) as Record<string, unknown>;

  const admin = raw["admin"] as Record<string, unknown> | undefined;
  if (
    !admin ||
    admin["credential_nft_id"] === undefined ||
    admin["credential_nft_id"] === null
  ) {
    throw new Error("admin.credential_nft_id not set in blockhost.yaml");
  }

  const id = Number(admin["credential_nft_id"]);
  if (!Number.isInteger(id) || id < 0) {
    throw new Error(
      `Invalid admin.credential_nft_id: ${String(admin["credential_nft_id"])}`,
    );
  }

  return id;
}

// ── CLI handler ───────────────────────────────────────────────────────────────

export async function whoCommand(args: string[]): Promise<void> {
  if (args.length < 1) {
    console.error("Usage: bw who <identifier>");
    console.error("  identifier: token ID (0, 1, 2, ...) or 'admin'");
    process.exit(1);
  }

  const identifier = args[0];
  if (!identifier) {
    console.error("Usage: bw who <identifier>");
    process.exit(1);
  }

  let tokenId: number;

  if (identifier === "admin") {
    tokenId = loadAdminNftId();
  } else if (/^\d+$/.test(identifier)) {
    tokenId = parseInt(identifier, 10);
  } else {
    console.error(
      `Invalid identifier: '${identifier}'. Use a token ID or 'admin'.`,
    );
    process.exit(1);
  }

  const cfg = loadWeb3Config();
  const client = getBlockfrostClient();

  const holder = await findNftHolder(client, cfg.nftPolicyId, tokenId);

  if (!holder) {
    console.error(`Error: token ${tokenId} does not exist or has no holder`);
    process.exit(1);
  }

  console.log(holder);
}
