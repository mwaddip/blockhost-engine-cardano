/**
 * bw plan create <name> <price>
 *
 * Create or update a plan reference UTXO.
 *
 * TODO: Requires building a transaction that creates a UTXO at the plan
 * reference address with an inline PlanDatum. Depends on MeshJS integration.
 */

import type { Addressbook } from "../../fund-manager/types.js";

/**
 * CLI handler
 */
export async function planCommand(
  args: string[],
  _book: Addressbook,
): Promise<void> {
  const [subCommand, ...rest] = args;

  if (subCommand === "create") {
    await planCreateCommand(rest);
    return;
  }

  console.error("Usage: bw plan create <name> <price>");
  console.error("  Example: bw plan create basic 5000000");
  process.exit(1);
}

async function planCreateCommand(args: string[]): Promise<void> {
  if (args.length < 2) {
    console.error("Usage: bw plan create <name> <price>");
    console.error("  <price> is in lovelace (or payment token base units)");
    process.exit(1);
  }

  const [name, priceStr] = args;
  if (!name || !priceStr) {
    console.error("Usage: bw plan create <name> <price>");
    process.exit(1);
  }

  const price = BigInt(priceStr);

  console.log(`[TODO] Create plan: name="${name}" price=${price.toString()}`);
  console.log("TODO: plan create not yet implemented.");
  console.log(
    "      Requires building a Cardano transaction with inline PlanDatum.",
    "Depends on MeshJS integration.",
  );
}
