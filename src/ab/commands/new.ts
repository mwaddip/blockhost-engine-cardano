/**
 * ab new <name> — Generate new wallet via root agent and add to addressbook
 */

import { loadAddressbook } from "../../bw/cli-utils.js";
import { generateWallet as rootAgentGenerateWallet } from "../../root-agent/client.js";
import { assertMutableRole } from "../index.js";

export async function newCommand(args: string[]): Promise<void> {
  if (args.length !== 1) {
    console.error("Usage: ab new <name>");
    process.exit(1);
  }

  const [name] = args;
  if (!name) {
    console.error("Usage: ab new <name>");
    process.exit(1);
  }

  if (!/^[a-zA-Z0-9_]{1,32}$/.test(name)) {
    console.error(
      `Error: invalid name '${name}'. Must be 1-32 alphanumeric/underscore characters.`,
    );
    process.exit(1);
  }

  assertMutableRole(name);

  const book = loadAddressbook();

  if (book[name]) {
    console.error(
      `Error: '${name}' already exists in addressbook.`,
    );
    process.exit(1);
  }

  const { address } = await rootAgentGenerateWallet(name);
  console.log(`Generated wallet '${name}' → ${address}`);
  console.log(`Key saved to /etc/blockhost/${name}.key`);
}
