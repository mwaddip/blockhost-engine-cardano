# Cardano Transaction Building Pitfalls

Notes from building a minimal Cardano tx toolkit from scratch. These are
the things that aren't obvious from the spec and cost hours to debug.

## Slot numbers vs POSIX time

Transaction validity ranges (`validFrom`, `validTo` / TTL) use **absolute slot
numbers**, not POSIX timestamps. The conversion depends on the network's Shelley
genesis start time:

```
slot = floor((posix_ms - shelley_start_ms) / 1000)
```

Network-specific Shelley start times (POSIX ms):

| Network | Shelley start (ms) | Date |
|---------|-------------------|------|
| preprod | 1655683200000 | 2022-06-20T00:00:00Z |
| preview | 1666656000000 | 2022-10-25T00:00:00Z |
| mainnet | 1591566291000 | 2020-06-07T21:44:51Z |

These are immutable — baked into each network's genesis config.

**Symptom if wrong:** `OutsideValidityIntervalUTxO` with absurdly large slot
numbers (because you passed POSIX ms where slots were expected).

## Script hashing

The Cardano script hash (policy ID / validator hash) is:

```
blake2b_224(language_tag ++ script_cbor_bytes)
```

Where:
- `language_tag` = `0x01` (PlutusV1), `0x02` (PlutusV2), `0x03` (PlutusV3)
- `script_cbor_bytes` = the **full CBOR byte string** from `plutus.json`'s
  `compiledCode`, including the outer CBOR wrapper

The `compiledCode` in `plutus.json` is hex-encoded CBOR: a CBOR byte string
(major type 2) wrapping the flat-encoded UPLC program. The hash covers the
full CBOR encoding, **not** just the inner flat bytes.

```
compiledCode = "5901d3010100..."
                ^^^^^^ CBOR header (byte string, length 467)
                      ^^^^^^^^ flat UPLC bytes

script_hash = blake2b_224(0x03 ++ hex_to_bytes("5901d3010100..."))
```

**Symptom if wrong:** `MissingScriptWitnessesUTXOW` — the node can't find a
script witness matching the expected policy ID.

## Witness set: PlutusV3 scripts

PlutusV3 scripts go in **field 7** of the witness set (not field 6, which is
PlutusV2). Each entry is the raw CBOR bytes from `compiledCode` — the full
CBOR byte string, not unwrapped.

```
witness_set = {
  0: [vkey_witnesses...],
  5: redeemers,
  7: [script_cbor_bytes, ...]  // PlutusV3
}
```

## Redeemers encoding

Redeemers are a **CBOR array** (not a map) of 4-element arrays:

```
redeemers = [
  [tag, index, redeemer_data, [ex_mem, ex_steps]],
  ...
]
```

- `tag`: 0 = spend, 1 = mint, 2 = cert, 3 = reward
- `index`: position of the input (for spend) or policy (for mint) in the
  **sorted** inputs/mint map
- `redeemer_data`: raw Plutus Data CBOR (e.g., `d87980` for `Constr(0, [])`)
  — **NOT** wrapped in a CBOR byte string
- `[ex_mem, ex_steps]`: execution unit budget

**Symptom if wrong:** `DeserialiseFailure` or `ExtraRedeemers`.

## Script data hash

Required in the tx body (field 11) when any Plutus scripts are present:

```
script_data_hash = blake2b_256(
  redeemers_cbor ++
  datums_cbor ++
  language_views_cbor
)
```

- `redeemers_cbor`: the exact bytes used in the witness set (field 5)
- `datums_cbor`: `0x80` (empty CBOR array) when using inline datums only
- `language_views_cbor`: CBOR map `{ language_id: [cost_model_values...] }`

Language IDs: 0 = PlutusV1, 1 = PlutusV2, 2 = PlutusV3.

The cost model values must be fetched from protocol parameters. For preprod
PlutusV3 there are 297 integer values. Each is encoded as a CBOR integer
(positive or negative) in a definite-length CBOR array.

```
language_views = { 2: [100788, 420, 1, 1, 1000, ...] }
```

**Symptom if wrong:** `PPViewHashesDontMatch` — the node's computed hash
doesn't match what you supplied.

## Fee calculation for script transactions

The simple fee formula `minFeeA * tx_size + minFeeB` only covers the
transaction size. Script execution adds:

```
total_fee = size_fee + exec_fee
size_fee = minFeeA * tx_size_bytes + minFeeB
exec_fee = priceMem * ex_mem + priceStep * ex_steps
```

A simple transfer costs ~170k lovelace. A script transaction with one
Plutus validator can cost 1-2 ADA depending on execution units.

Use generous ex_unit budgets in the redeemer (the node will check the
actual cost), and set a high initial fee estimate for the two-pass
calculation.

**Symptom if wrong:** `FeeTooSmallUTxO`.

## Collateral

Any transaction that executes Plutus scripts requires collateral:

- **Field 13** (collateral inputs): UTXOs pledged as collateral
- **Field 16** (collateral return): output for excess collateral
- **Field 17** (total collateral): amount pledged (typically 150% of fee)

The collateral inputs must be **ADA-only** UTXOs from the signer's wallet.
If no collateral return is specified, the entire UTXO is forfeited on script
failure.

**Symptom if wrong:** `NoCollateralInputs` or `InsufficientCollateral`.

## Token conservation in change outputs

When coin selection picks UTXOs that contain native tokens (NFTs, etc.),
those tokens **must** appear in an output. If they're not in any explicit
output, they must be returned in the change output.

```
sum(input_tokens) = sum(output_tokens) + sum(minted_tokens)
```

**Symptom if wrong:** `ValueNotConservedUTxO` with a mismatch showing tokens
in the supplied value but not in the expected value.

## Inline datum encoding in outputs

Post-Babbage outputs use a map format. Inline datums go in field 2 as:

```
output = {
  0: address_bytes,
  1: value,
  2: [1, #6.24(datum_cbor)]  // 1 = inline, tag 24 = CBOR-in-CBOR
}
```

The datum CBOR is wrapped in CBOR tag 24 (encoded CBOR data item) and then
in a 2-element array where index 0 would be a datum hash.

## Plutus Data CBOR tags

Plutus constructors use non-standard CBOR tags:

| Constructor | CBOR tag |
|------------|----------|
| Constr 0 | 121 |
| Constr 1 | 122 |
| Constr 2 | 123 |
| ... | ... |
| Constr 6 | 127 |
| Constr 7+ | 102, with `[index, fields]` as content |

Aiken booleans: `True` = `Constr(1, [])`, `False` = `Constr(0, [])`.

When decoding, a generic CBOR decoder will strip the tag — you need a
Plutus-aware decoder that converts tags 121-127 back to `Constr(0-6, fields)`.

## Input sorting

Conway era requires transaction inputs to be sorted lexicographically by
`(tx_hash, output_index)` and encoded as a CBOR set (tag 258).
