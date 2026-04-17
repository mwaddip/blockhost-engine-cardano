# cmttk: add browser / CIP-30 support

## Why

`cmttk.buildAndSubmitScriptTx` builds, signs (with a local `signingKey`), and
submits a Plutus-script transaction in one pass. That shape works for backend
code. For a browser dApp using CIP-30, the wallet holds the signing key —
consumer code needs to build the tx, hand it to `wallet.signTx()`, merge the
wallet's vkey witnesses back in, and submit.

Right now the only way to do that with cmttk is to reimplement the entire
body/witness-set construction by hand. `blockhost-engine-cardano`'s
`scripts/signup-engine.js` does exactly that — ~400 lines of hand-rolled
CBOR that duplicates `buildAndSubmitScriptTx`'s internals and gets them
subtly wrong (hardcoded fee, hardcoded min-UTxO, hardcoded `script_data_hash`
that has to be manually recomputed after protocol changes).

The goal: let cmttk own Cardano tx construction, leave only CIP-30 protocol
bits (wallet enable, `signTx`, `signData`, CIP-68 datum shape) in the consumer.

## Proposed exports

Three new public exports plus one bugfix. No breaking changes to existing APIs.

### 1. `parseCip30Utxos(cborHexArray)` — new

```typescript
export function parseCip30Utxos(cborHexArray: string[]): Utxo[];
```

CIP-30 wallets return UTXOs as an array of CBOR hex strings, each encoding a
`[input, output]` pair. Input is `[txHash bytes, index uint]`. Output is either
pre-Babbage `[address, value, ?datum_hash]` or post-Babbage map
`{0: address, 1: value, 2: datum_option, 3: script_ref}`. Value is either a
bare uint (ADA-only) or `[lovelace, multiasset]`.

Signature mirrors `parseKoiosUtxos` — same `Utxo` return type — so consumers
can feed the result straight into `selectUtxos`, `buildUnsignedScriptTx`, etc.

Logic already exists in `signup-engine`'s `parseCip30Utxo` + `parseMultiAsset`
(post-port: `src/signup/index.ts` in blockhost-engine-cardano) — straightforward
to port under `cmttk/src/tx.ts` or a new `cmttk/src/cip30.ts` module.

### 2. `buildUnsignedScriptTx(params)` — new

```typescript
export interface UnsignedScriptTx {
    /** Serialised tx body — pass this to CIP-30 `wallet.signTx(hex, true)`. */
    txBodyCbor: Uint8Array;
    /** Partial witness set containing redeemers + plutus scripts (no vkeys). */
    witnessSet: Uint8Array;
    /** Redeemer CBOR alone (reuse for merging). */
    redeemersCbor: Uint8Array;
    /** PlutusV3 scripts array CBOR (reuse for merging). */
    plutusV3Scripts: Uint8Array;
    /** Computed script_data_hash, already embedded in txBodyCbor. */
    scriptDataHash: Uint8Array;
    /** Final fee used in the body (for display / UX). */
    fee: bigint;
}

export async function buildUnsignedScriptTx(params: {
    provider: CardanoProvider;
    walletAddress: string;
    walletUtxos: Utxo[];                 // pre-parsed (parseCip30Utxos)
    collateralUtxos: Utxo[];             // pre-parsed — from api.getCollateral()
    scriptInputs: ScriptInput[];
    outputs: TxOutput[];
    mints?: MintEntry[];
    spendingScriptCbor?: string;
    validFrom?: number;
    validTo?: number;
    network?: CardanoNetwork;
    requiredSigners?: string[];
}): Promise<UnsignedScriptTx>;
```

Essentially `buildAndSubmitScriptTx` with:

1. `signingKey` removed.
2. `walletUtxos` taken as a parameter instead of fetched via `provider.fetchUtxos`
   (browser already has them from `api.getUtxos()`, and CIP-30 balance includes
   pending-tx outputs that a Koios refetch would miss).
3. `collateralUtxos` taken as a parameter (CIP-30 exposes `api.getCollateral()`
   explicitly — don't re-derive from `walletUtxos`).
4. Returns the assembled body + partial witness set instead of signing and
   submitting.

All the existing internals stay — iterative fee calculation, two-pass
min-UTxO bumping, `computeScriptDataHash` against `costModelV3`, canonical
CBOR field ordering. The only change is the exit: return the pieces instead
of signing.

Suggested refactor: lift the closures (`buildAllOutputs`, `buildFullTxBody`,
`buildFullWitnessSet`, `buildRedeemers`, `buildPlutusV3Scripts`,
`computeScriptDataHash`) out of `buildAndSubmitScriptTx` into module-scope
helpers, have both `buildUnsignedScriptTx` and `buildAndSubmitScriptTx` call
them. Keeps the logic single-sourced.

### 3. `mergeCip30Witness(unsigned, walletWitnessCbor)` — new

```typescript
export function mergeCip30Witness(
    unsigned: UnsignedScriptTx,
    walletWitnessCbor: string,   // hex, returned by wallet.signTx(..., true)
): string;  // signed tx hex, ready for provider.submitTx
```

CIP-30 `signTx(cbor, partial=true)` returns a CBOR-encoded witness set
(possibly just `{0: [vkey_witnesses]}`, possibly a fuller set). This helper:

1. Decodes `walletWitnessCbor` via `decodeCbor`.
2. Extracts field `0` (vkey_witness array) and any other fields the wallet
   added — e.g. field `1` (native_scripts), field `4` (bootstrap_witness).
3. Merges into the partial witness set from `buildUnsignedScriptTx` alongside
   field `5` (redeemers) and field `7` (plutus_v3_scripts).
4. Assembles the final tx: `[body, witness_set, true, null]`.
5. Returns hex.

The current `signup-engine` implementation of this merge is a fragile byte
sniff (`walletWitBytes[0] === 0xa1 && walletWitBytes[1] === 0x00`) — only
works for definite-length 1-entry maps. Do it properly with `decodeCbor`.

### 4. Browser-compat fix in existing code — bug

`provider.ts` `KoiosProvider.submitTx` and `BlockfrostProvider.submitTx`
both call `Buffer.from(txCbor, "hex")`. `Buffer` is Node-only; esbuild
`--platform=browser` refuses to bundle it. Replace with the existing
`hexToBytes` from `cbor.ts`:

```typescript
// was:  body: Buffer.from(txCbor, "hex"),
// now:  body: hexToBytes(txCbor),
```

That single change makes `cmttk/provider` bundlable for browser. (Consumers
that hit CORS on direct Koios URLs can still pass `koiosUrl: "/api/v1"` to
`getProvider` to use a local proxy — that already works.)

## Consumer migration

Today in `blockhost-engine-cardano/src/signup/index.ts`, `buildSubscriptionTx`
is ~300 lines of tx body/witness construction followed by ~40 lines of
wallet-signing + submission. After these cmttk additions:

```typescript
import {
    getProvider,
    parseCip30Utxos,
    buildUnsignedScriptTx,
    mergeCip30Witness,
    Constr, Data,
} from "cmttk";

// …inside the subscribe click handler, after building the datum hex…

const walletUtxos   = parseCip30Utxos(await api.getUtxos());
const collateralUtxos = parseCip30Utxos(await api.getCollateral());
const provider      = getProvider(CONFIG.network, undefined, "/api/v1");

const unsigned = await buildUnsignedScriptTx({
    provider,
    walletAddress: hexAddressToBech32(usedAddress),
    walletUtxos,
    collateralUtxos,
    scriptInputs: [],
    outputs: [
        {
            address: scriptAddrBech32,
            assets: { lovelace: scriptOutputLovelace, [beaconUnit]: 1n },
            datumCbor,
        },
        // optional deployer-fee output
        ...(CONFIG.deployerAddress ? [{
            address: CONFIG.deployerAddress,
            assets: { lovelace: 2_500_000n },
        }] : []),
    ],
    mints: [{
        policyId: CONFIG.beaconPolicyId,
        assets: { [beaconName]: 1n },
        redeemerCbor: Data.to(new Constr(0, [])),
        scriptCbor: CONFIG.beaconScriptCbor,
    }],
    validFrom: Date.now() - 60_000,
    validTo: Date.now() + 15 * 60_000,
    network: CONFIG.network as CardanoNetwork,
    requiredSigners: [subscriberKeyHash],
});

const walletWitnessHex = await api.signTx(bytesToHex(unsigned.txBodyCbor), true);
const signedTxHex      = mergeCip30Witness(unsigned, walletWitnessHex);
const txHash           = await provider.submitTx(signedTxHex);
```

**Net effect in `blockhost-engine-cardano`:** delete ~500 lines —
`buildSubscriptionTx`, `parseCip30Utxo`, `parseMultiAsset`, `buildInputsCbor`,
`buildScriptOutput`, `buildChangeOutput`, `buildMintCbor`, `submitViaKoios`,
and the hardcoded `SCRIPT_DATA_HASH = "0fe49daf..."`. Fee, min-UTxO, and
script_data_hash become correct for whatever protocol parameters are live.

## Design notes

- **No breaking changes.** Existing `buildAndSubmitScriptTx` signature stays.
  Under the hood it composes `buildUnsignedScriptTx` + local signing + submit.
- **`ScriptInput`, `TxOutput`, `MintEntry`, `Utxo`, `Assets`** types are reused
  as-is.
- **Constr-array encoding.** `Data.to` in cmttk emits *definite*-length arrays
  for non-empty `Constr` fields. blockhost's on-chain subscription datum was
  originally produced with *indefinite*-length (`0x9f..0xff`) arrays (the
  Lucid/CSL convention) and existing script UTxOs have that shape. This is
  purely a serialisation difference — Plutus Data semantics are identical —
  so the validator accepts both. blockhost's `encodePlutusSubscriptionDatum`
  already stays local (see `src/signup/encoder.ts` in blockhost-engine-cardano)
  and uses indefinite-length for bytewise continuity with the legacy encoder;
  it calls into cmttk only for `cborHeader`/`cborUint`/etc. This migration
  does not require changing `Data.to`.
- **No CIP-30 wallet client in cmttk.** `api.enable()`, `api.signTx`,
  `api.signData`, `api.getUtxos`, `api.getCollateral` stay entirely in the
  consumer. cmttk only needs to accept the UTXO CBOR the wallet hands back,
  build a signable body, and merge the signature.

## Testing

- Unit test `parseCip30Utxos` against captured CBOR strings from Eternl /
  Nami / Lace (ADA-only, multi-asset, post-Babbage map output, pre-Babbage
  array output).
- Unit test `mergeCip30Witness` against a handcrafted wallet witness CBOR
  (1-entry map, 2-entry map with native scripts).
- Integration: in a browser, drive `buildUnsignedScriptTx` +
  `mergeCip30Witness` against preprod Koios — build, sign via Eternl, submit.
  Compare `txHash` reappears on cardanoscan within a block.
- Regression: confirm existing `buildAndSubmitScriptTx` test suite still
  passes after the internal refactor (if any tests exist).

## Version

Suggest cmttk 0.6.0 (minor bump — new APIs, no removals). Update the github
tag reference in downstream `package.json` files (`cmttk":
"github:mwaddip/cmttk#v0.6.0"`) after release.
