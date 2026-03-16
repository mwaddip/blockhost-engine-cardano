# CLI Tools

## bw (blockwallet)

Scriptable wallet operations for Cardano. Reads config from `web3-defaults.yaml` and addressbook from `addressbook.json`.

```bash
bw send <amount> <token> <from> <to>       # Send ADA or tokens between wallets
bw balance <role> [token]                   # Show wallet balances
bw split <amount> <token> <ratios> <from> <to1> <to2> ...  # Split tokens by ratio
bw withdraw <to>                            # Batch-collect subscription UTXOs
bw swap <amount> <from-token> ada <wallet>  # Swap tokens via DEX (stub)
bw who <identifier>                         # Query CIP-68 NFT holder
bw config stable [policyId.assetName]       # Get/set primary stablecoin
bw plan create <name> <price>               # Create subscription plan (stub)
bw set encrypt <nft_id> <data>              # Update NFT reference datum (stub)
bw --debug --cleanup <address>              # Sweep all testnet ADA to address
```

- **Token shortcuts**: `ada` (native lovelace), `stable` (configured payment token), or `policyId.assetName`
- **Roles**: `admin`, `server`, `hot`, `dev`, `broker` (resolved from `addressbook.json`)
- **Signing**: Only roles with `keyfile` in the addressbook can be used as `<from>`/`<wallet>`
- **Amounts**: ADA amounts are in lovelace unless explicitly noted

### bw who

Query the holder of a CIP-68 `(222)` user token.

```bash
bw who 42          # Who holds NFT token ID 42?
bw who admin       # Who holds the admin NFT? (reads admin.credential_nft_id from blockhost.yaml)
```

Reads `nft_policy_id` from `web3-defaults.yaml`. Prints the bech32 address of the current holder. No addressbook required.

### bw config stable

```bash
bw config stable                         # Print current payment token policy ID
bw config stable abc123...def.5374       # Set payment token (policyId.assetName)
```

Reads and writes the payment token configuration stored in the plan reference UTXO or off-chain config.

### bw plan create

```bash
bw plan create basic 5000000     # Create plan named "basic", 5 ADA/day price
```

**Status: stub.** Requires building a Cardano transaction with an inline `PlanDatum`. Depends on MeshJS integration.

### bw set encrypt

```bash
bw set encrypt 42 <hex-encrypted-data>   # Update NFT #42 reference datum
```

**Status: stub.** Updates the `user_encrypted` field in the CIP-68 reference token datum. Requires MeshJS transaction building.

### bw swap

```bash
bw swap 10000000 stable ada server       # Swap 10 ADA worth of stablecoin for ADA
```

**Status: stub.** DEX swap integration (e.g. Minswap, SundaeSwap) not yet implemented.

### bw --debug --cleanup

```bash
bw --debug --cleanup addr1qxyz...
```

Debug utility. Sweeps ADA from all signing wallets back to a single address. Requires `--debug` flag as a safety guard. Skips wallets that are the target or have insufficient balance for fees.

The fund-manager imports `executeSend()`, `executeWithdraw()`, and `executeSwap()` from bw command modules directly — all wallet operations flow through the same code paths.

---

## ab (addressbook)

Manages wallet entries in `/etc/blockhost/addressbook.json`. No RPC or blockchain config required — purely local filesystem operations. All addresses are bech32.

```bash
ab add <name> <addr1...>     # Add new entry
ab del <name>                # Delete entry
ab up <name> <addr1...>      # Update entry's address
ab new <name>                # Generate new Cardano wallet, save mnemonic, add to addressbook
ab list                      # Show all entries
ab --init <admin> <server> [dev] [broker] <keyfile>  # Bootstrap addressbook
```

- **Immutable roles**: `server`, `admin`, `hot`, `dev`, `broker` — cannot be added, deleted, updated, or generated via `ab`
- **`ab new`**: Generates a BIP39 mnemonic via `keygen.ts`, saves it to `/etc/blockhost/<name>.key` (chmod 600, `blockhost` group), adds bech32 address to the addressbook
- **`ab up`**: Only changes the address; preserves existing `keyfile` if present
- **`ab del`**: Removes the JSON entry but does NOT delete the keyfile (if any)
- **`ab --init`**: Bootstrap addressbook for fresh installs. Positional args: admin address, server address, optionally dev and broker addresses, then server keyfile (always last). Fails if addressbook already has entries.

---

## is (identity predicate)

Yes/no identity questions via exit code. Exit 0 = yes, exit 1 = no. Config from `web3-defaults.yaml` (`blockfrost_project_id`, `network`, `nft_policy_id`).

```bash
is <wallet> <nft_id>         # Does wallet hold CIP-68 NFT token?
is contract <address>        # Does an address have UTXOs on-chain?
```

Arguments are order-independent, disambiguated by type:
- **Address**: Cardano bech32 (`addr1...` or `addr_test1...`)
- **NFT ID**: integer
- **`contract`**: literal keyword

The `is contract` form uses `client.addressesUtxos()` — a Blockfrost 404 (address never used) exits 1; any UTXOs present exits 0. The term "contract" is used loosely; any address can be checked.

---

## bhcrypt

Encryption/decryption utility for ECIES and SHAKE256 symmetric operations.

```bash
bhcrypt encrypt-ecies <pubkey-hex> <plaintext>   # ECIES encrypt for server
bhcrypt decrypt-ecies <plaintext>                 # Decrypt with server.key
bhcrypt encrypt-sym <key-hex> <plaintext>         # SHAKE256 + AES-256-GCM encrypt
bhcrypt decrypt-sym <key-hex> <ciphertext>        # Symmetric decrypt
```

The ECIES path uses secp256k1 ECDH + HKDF-SHA256 + AES-256-GCM. Wire format: `ephemeralPub(65) + IV(12) + ciphertext+tag`. Implemented in `src/crypto.ts`.

Note: Cardano wallets use Ed25519, but the server-side ECIES encryption for `user_encrypted` in subscription datums uses secp256k1 (same as OPNet engine). The server's secp256k1 key is separate from its Cardano signing key.
