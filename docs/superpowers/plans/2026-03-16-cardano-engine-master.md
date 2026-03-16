# Cardano Engine — Master Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a Cardano engine for BlockHost using the UTXO-native subscription model (cardano-swaps beacon pattern), satisfying the same ENGINE_INTERFACE.md contract as the EVM and OPNet engines.

**Architecture:** Per-subscriber UTXOs at a shared validator address with CIP-89 beacon tokens for discoverability. Three Aiken validators (subscription, beacon minting, NFT minting). CIP-68 reference tokens for NFT metadata. Blockfrost for chain queries. MeshJS for transaction building. TypeScript/Node.js runtime matching the OPNet engine structure.

**Tech Stack:** Aiken (validators), TypeScript/Node.js (engine runtime), MeshJS (tx building), Blockfrost SDK (chain queries), esbuild (bundling), Ed25519 (signing)

**Base codebase:** Fork structure from `blockhost-engine-opnet`. Keep chain-agnostic modules, replace OPNet-specific code with Cardano equivalents.

---

## Subsystem Dependency Order

The subsystems must be built in this order. Each produces independently testable software, but later subsystems depend on earlier ones.

```
Phase 1: Foundation
  ├── Plan 1: Project Scaffolding & Cardano Utilities
  │            (package.json, tsconfig, wallet, provider, types)
  │
  └── Plan 2: Aiken Validators
               (subscription, beacon, NFT minting policies)

Phase 2: Core Engine
  ├── Plan 3: Monitor & Beacon Scanner
  │            (polling loop, UTXO scanning, subscription detection)
  │
  ├── Plan 4: Handlers & Pipeline
  │            (subscription lifecycle, VM provisioning integration)
  │
  └── Plan 5: NFT Minting & Reconciler
               (CIP-68 mint, ownership scanning, GECOS sync)

Phase 3: CLI Tools
  ├── Plan 6: bw (blockwallet) CLI
  │            (send, balance, who, withdraw, plan, config, set)
  │
  ├── Plan 7: ab, is, bhcrypt CLIs
  │            (addressbook, identity predicate, crypto tool)
  │
  └── Plan 8: blockhost-mint-nft & deploy-contracts Scripts
               (NFT minting script, validator deployment)

Phase 4: User-Facing
  ├── Plan 9: Auth-svc & Signing Page
  │            (CIP-30 wallet UI, HTTPS callback server, .sig format)
  │
  └── Plan 10: Signup Page Engine JS
                (MeshJS tx building, subscription creation)

Phase 5: Operations
  ├── Plan 11: Fund Manager
  │             (batch collection, distribution, state)
  │
  └── Plan 12: Admin Commands
                (tx metadata scanning, knock handler)

Phase 6: Integration
  ├── Plan 13: Wizard Plugin & engine.json
  │             (installer integration, finalization steps)
  │
  └── Plan 14: Packaging & Build
                (two .debs, esbuild config, systemd units)
```

---

## Plan 1: Project Scaffolding & Cardano Utilities

**Goal:** Set up the project structure and build the Cardano-specific foundation layer that everything else depends on.

**Files to create:**
- `package.json` — dependencies: `@meshsdk/core`, `@blockfrost/blockfrost-js`, `bip39`, `@stricahq/bip32ed25519`, `@noble/hashes`, `@noble/curves`, plus chain-agnostic deps from OPNet (`serde`, `toml`, etc.)
- `tsconfig.json` — strict TypeScript, ESM, bundler resolution
- `engine.json` — Cardano engine manifest
- `src/cardano/provider.ts` — Blockfrost client wrapper (init from config, query UTXOs, submit tx)
- `src/cardano/wallet.ts` — CIP-1852 key derivation from BIP39 mnemonic, Ed25519 signing
- `src/cardano/types.ts` — Datum/redeemer TypeScript types matching Aiken validators
- `src/cardano/beacon.ts` — Beacon name computation (`sha2_256(plan_id ++ subscriber_key_hash)`)
- `src/cardano/tx-builder.ts` — Transaction construction helpers (UTXO selection, fee calc, script interaction)
- `src/cardano/address.ts` — bech32 address validation, CIP-89 address derivation
- `src/fund-manager/web3-config.ts` — Load Cardano config from `web3-defaults.yaml`
- `src/crypto.ts` — ECIES encrypt/decrypt (secp256k1 for server key, same as EVM), AES-GCM symmetric
- `src/provisioner.ts` — Copy from OPNet (chain-agnostic)
- `src/root-agent/client.ts` — Copy from OPNet (chain-agnostic)

**Files to copy from OPNet (no changes):**
- `src/fund-manager/state.ts`
- `src/fund-manager/types.ts` (adapt address format)
- `src/fund-manager/config.ts`

**Tests:** Unit tests for wallet derivation, beacon name computation, address validation, config loading.

---

## Plan 2: Aiken Validators

**Goal:** Write, build, and test the three Aiken validators.

**Files to create:**
- `aiken.toml` — Aiken project configuration
- `validators/subscription.ak` — Subscription spending validator (ServiceCollect, SubscriberCancel, SubscriberExtend, Migrate)
- `validators/beacon.ak` — Beacon minting/staking policy (CreateSubscription, CloseSubscription)
- `validators/nft.ak` — NFT minting policy (server-authorized, CIP-68 pair minting)
- `lib/types.ak` — Shared datum/redeemer type definitions
- `lib/utils.ak` — Shared validation helpers (staking credential check, etc.)

**Tests:** Aiken built-in test framework. Test each spending path, edge cases (expired subscriptions, wrong payment amount, unauthorized mint).

**Output:** `plutus.json` blueprint with CBOR-encoded scripts, computed script hashes.

---

## Plan 3: Monitor & Beacon Scanner

**Goal:** The polling loop that detects new subscriptions, cancellations, and extensions by scanning for beacon tokens.

**Files to create:**
- `src/monitor/index.ts` — Main polling loop (adapted from OPNet: replace block scanning with beacon UTXO scanning)
- `src/monitor/scanner.ts` — Blockfrost-based beacon UTXO scanner (query validator address, diff against known state)
- `src/monitor/state.ts` — Track known subscription UTXOs (in-memory map of beacon → datum)

**Dependencies:** Plan 1 (provider, types, beacon computation)

---

## Plan 4: Handlers & Pipeline

**Goal:** The provisioning pipeline triggered by subscription events.

**Files to create:**
- `src/handlers/index.ts` — Event dispatch (new subscription → provision, cancellation → destroy, extension → extend)
- `src/handlers/provision.ts` — 8-step provisioning pipeline (adapted from OPNet handlers)

**Dependencies:** Plan 1 (crypto, provisioner), Plan 3 (monitor feeds events)

**Files to copy/adapt from OPNet:** Handler pipeline structure, provisioner CLI calls.

---

## Plan 5: NFT Minting & Reconciler

**Goal:** CIP-68 NFT minting and ownership reconciliation.

**Files to create:**
- `src/reconcile/index.ts` — Scan UTXOs holding NFT policy assets, compare with vms.json, call update-gecos on mismatch
- `src/nft/mint.ts` — Build CIP-68 minting transaction (user token + reference token with datum)
- `src/nft/reference.ts` — Read/update CIP-68 reference datum (userEncrypted)

**Dependencies:** Plan 1 (provider, tx-builder), Plan 2 (NFT minting policy)

---

## Plan 6: bw (blockwallet) CLI

**Goal:** The primary wallet operations CLI, adapted for Cardano.

**Files to create:**
- `src/bw/index.ts` — Argument routing
- `src/bw/cli-utils.ts` — Provider/wallet init, token resolution
- `src/bw/commands/send.ts` — ADA and native token transfers
- `src/bw/commands/balance.ts` — UTXO-based balance queries
- `src/bw/commands/who.ts` — NFT ownership lookup via asset query
- `src/bw/commands/withdraw.ts` — Batch subscription UTXO collection
- `src/bw/commands/plan.ts` — Create/update plan reference UTXO
- `src/bw/commands/config.ts` — Payment token configuration
- `src/bw/commands/set.ts` — Update CIP-68 reference datum (userEncrypted)
- `src/bw/commands/split.ts` — Token distribution by ratio
- `src/bw/commands/swap.ts` — DEX aggregator integration (stub initially)
- `src/bw/commands/cleanup.ts` — Debug sweep

**Dependencies:** Plan 1 (provider, wallet, tx-builder, types)

---

## Plan 7: ab, is, bhcrypt CLIs

**Goal:** Supporting CLI tools.

**Files to create/adapt:**
- `src/ab/` — Copy from OPNet, adapt address validation to bech32
- `src/is/index.ts` — Rewrite for Cardano (check validator address, native asset ownership)
- `src/bhcrypt.ts` — Adapt for Ed25519 keypair gen, keep ECIES/AES-GCM symmetric

**Dependencies:** Plan 1 (wallet, address utils)

---

## Plan 8: blockhost-mint-nft & deploy-contracts

**Goal:** CLI scripts for NFT minting and validator deployment.

**Files to create:**
- `scripts/mint_nft` — Build and submit CIP-68 minting transaction
- `scripts/deploy-contracts` — Deploy reference script UTXOs, record hashes in config
- `scripts/keygen.ts` — Generate Cardano wallet from BIP39 mnemonic

**Dependencies:** Plan 1 (wallet, tx-builder), Plan 2 (compiled validators)

---

## Plan 9: Auth-svc & Signing Page

**Goal:** CIP-30 signing page and HTTPS callback server for VM authentication.

**Files to create:**
- `src/auth-svc/index.ts` — HTTPS server (adapt from OPNet: CIP-30 COSE_Sign1 verification, Ed25519)
- `auth-svc/signing-page/index.html` — CIP-30 wallet connection UI
- `auth-svc/signing-page/engine.js` — Cardano wallet detection, signData, callback POST

**Dependencies:** Plan 1 (crypto for Ed25519 verification)

---

## Plan 10: Signup Page Engine JS

**Goal:** Client-side subscription transaction builder.

**Files to create:**
- `scripts/signup-template.html` — Signup page template
- `scripts/signup-engine.js` — MeshJS-based tx builder (CIP-30 wallet, beacon minting, datum construction, UTXO selection via Blockfrost)
- `scripts/generate-signup-page` — Template rendering script

**Dependencies:** Plan 2 (validator script hashes for addresses), Plan 1 (types for datum construction)

---

## Plan 11: Fund Manager

**Goal:** Batch subscription collection and revenue distribution.

**Files to create:**
- `src/fund-manager/index.ts` — Cycle scheduling (simplified: no gas check cycle)
- `src/fund-manager/withdrawal.ts` — Build batch collection transaction (consume N subscription UTXOs)
- `src/fund-manager/distribution.ts` — Copy from OPNet (chain-agnostic math), adapt send calls
- `src/fund-manager/addressbook.ts` — Adapt for bech32 addresses
- `src/fund-manager/token-utils.ts` — Cardano balance/transfer operations

**Dependencies:** Plan 1 (provider, tx-builder, wallet), Plan 6 (bw send/balance for distribution)

---

## Plan 12: Admin Commands

**Goal:** Encrypted command processing via transaction metadata.

**Files to create:**
- `src/admin/index.ts` — Scan Blockfrost for txs from admin address with metadata label
- `src/admin/config.ts` — Load admin config
- `src/admin/nonces.ts` — Copy from OPNet (chain-agnostic)
- `src/admin/types.ts` — Copy from OPNet (chain-agnostic)
- `src/admin/handlers/knock.ts` — Copy from OPNet (chain-agnostic)

**Dependencies:** Plan 1 (provider, crypto)

---

## Plan 13: Wizard Plugin & engine.json

**Goal:** Installer integration for the Cardano engine.

**Files to create:**
- `engine.json` — Cardano engine manifest (constraints, finalization steps)
- `blockhost/engine_cardano/__init__.py`
- `blockhost/engine_cardano/wizard.py` — Flask blueprint, blockchain config page
- `blockhost/engine_cardano/templates/engine_cardano/blockchain.html`
- `blockhost/engine_cardano/templates/engine_cardano/summary_section.html`

**Dependencies:** Plan 8 (deploy-contracts for finalization)

---

## Plan 14: Packaging & Build

**Goal:** Two .deb packages (host engine + VM auth-svc template).

**Files to create:**
- `packaging/build.sh` — esbuild bundles, DEBIAN control files, wrapper scripts
- `examples/blockhost-monitor.service` — Systemd unit for monitor
- `root-agent-actions/wallet.py` — Ed25519 wallet generation plugin

**Dependencies:** All previous plans (this bundles everything)

---

## Execution Strategy

**Start with Plans 1 and 2 in parallel** — the Aiken validators and the TypeScript foundation have no code dependencies on each other (they share type definitions conceptually but not at compile time).

**Plans 3-5 are the core** — once foundation + validators exist, the monitor, handlers, and NFT system form the minimum viable engine.

**Plans 6-8 are the CLI layer** — needed for operational use but the engine can run without them in testing (use direct Blockfrost/MeshJS calls).

**Plans 9-10 are user-facing** — the signup page and auth-svc are needed for end-to-end flow but can be tested with manual transaction construction initially.

**Plans 11-14 are operational** — fund manager, admin commands, packaging. These complete the production engine but aren't needed for a testnet proof-of-concept.

---

## Testing Strategy

Each plan has its own test scope:

- **Validators (Plan 2):** Aiken's built-in test framework. Property-based tests for spending paths.
- **Cardano utilities (Plan 1):** Unit tests with vitest/jest. Mock Blockfrost responses.
- **Monitor/Handlers (Plans 3-4):** Integration tests against Blockfrost preprod. Manual subscription creation → verify detection.
- **CLI tools (Plans 6-8):** Integration tests on preprod. Create/query/transfer operations against real chain state.
- **Auth-svc (Plan 9):** Unit tests for COSE_Sign1 parsing and Ed25519 verification. Integration test with a Cardano wallet extension in a browser.
- **Fund manager (Plan 11):** Unit tests for batch tx construction. Integration test on preprod.

---

## Testnet Setup (prerequisite)

Before any integration testing:

1. Generate deployer wallet (BIP39 mnemonic → CIP-1852 keys → preprod address)
2. Fund from PreProd faucet (https://docs.cardano.org/cardano-testnets/tools/faucet/)
3. Get Blockfrost preprod project ID (https://blockfrost.io)
4. Mint test stablecoin (simple minting policy, fixed supply)
5. Deploy validators to preprod (creates reference script UTXOs)
6. Create initial plan reference UTXO
7. Record all hashes/addresses in `~/projects/sharedenv/cardano-preprod.env`
