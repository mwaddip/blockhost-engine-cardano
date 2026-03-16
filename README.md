# Blockhost Engine (Cardano)

Blockchain-based VM hosting subscription system on Cardano. Users lock funds at a validator address, which triggers automatic VM provisioning with NFT-based SSH authentication.

## How It Works

1. **User visits signup page** — Connects CIP-30 wallet (Eternl, Nami, etc.), signs challenge, locks subscription funds at validator address
2. **Subscription UTXO is created** — Beacon token minted under beacon policy, inline datum carries encrypted user data
3. **Monitor service detects beacon** — Scans Blockfrost for new beacon tokens at the validator address, triggers VM provisioning
4. **VM is created** — With web3-only SSH authentication (no passwords, no keys)
5. **NFT is minted** — CIP-68 user token (for the subscriber) + reference token (holds encrypted datum)
6. **User authenticates** — Signs with CIP-30 wallet on VM's signing page, gets SSH access

## Architecture

```
┌─────────────────┐     ┌──────────────────┐     ┌─────────────────┐
│   Signup Page   │────>│  Validator Addr  │────>│  Monitor Svc    │
│   (static HTML) │     │  (Cardano L1)    │     │  (TypeScript)   │
└─────────────────┘     └──────────────────┘     └────────┬────────┘
         │                       │                         │
         │               Beacon tokens                     v
         │               (CIP-89 disc.)          ┌─────────────────┐
         │                                        │  Provisioner    │
         v                                        │  (pluggable)    │
┌─────────────────┐     ┌──────────────────┐     └────────┬────────┘
│   User's VM     │<────│  CIP-68 NFT      │<────│  Engine         │
│   (web3 auth)   │     │  (user+ref token)│     │  (manifest)     │
└─────────────────┘     └──────────────────┘     └─────────────────┘
                                 │
                          Blockfrost API
                          (chain queries)
```

Subscriptions are UTXO-native: each subscriber's funds are locked at the validator address with an inline datum. There is no shared contract state. The beacon token makes UTXOs discoverable without enumeration. The engine reads on-chain state via Blockfrost — no custom node required.

## Components

| Component | Language | Description |
|-----------|----------|-------------|
| `validators/` | Aiken | Subscription, beacon, and NFT minting policies (compiled to Plutus) |
| `src/monitor/` | TypeScript | Beacon UTXO scanner via Blockfrost |
| `src/handlers/` | TypeScript | Scan diff handlers (VM provisioning, NFT minting) |
| `src/admin/` | TypeScript | Transaction metadata admin commands (HMAC-authenticated) |
| `src/reconcile/` | TypeScript | Hourly NFT ownership reconciliation |
| `src/fund-manager/` | TypeScript | Batch UTXO collection and revenue distribution |
| `src/bw/` | TypeScript | blockwallet CLI for scriptable wallet operations |
| `src/ab/` | TypeScript | Addressbook CLI for managing wallet entries |
| `src/is/` | TypeScript | Identity predicate CLI (NFT ownership, address checks) |
| `src/auth-svc/` | TypeScript | CIP-30 auth signing server (esbuild-bundled for VMs) |
| `src/root-agent/` | TypeScript | Client for the privileged root agent daemon |
| `blockhost/engine_cardano/` | Python | Installer wizard plugin |
| `auth-svc/signing-page/` | HTML/JS | Signing page template + engine bundle |
| `scripts/` | TS/JS/Python | Deployment, signup page, keygen |

## Prerequisites

- Node.js 22+
- Python 3.10+
- [Aiken](https://aiken-lang.org/) — Cardano smart contract compiler (`aiken build`, `aiken check`)
- `blockhost-common` package (shared configuration)
- A Blockfrost account and project ID (`preprod` or `mainnet`)
- A provisioner package (e.g. `blockhost-provisioner-proxmox`) with a manifest

## Development Setup

This is a component of the BlockHost system — it's installed via `packaging/build.sh` as part of a full deployment. For local development:

```bash
git clone https://github.com/mwaddip/blockhost-engine-cardano.git
cd blockhost-engine-cardano
npm install
```

```bash
npx tsc --noEmit          # Type-check TypeScript
npm run monitor            # Run beacon monitor (needs config on a deployed host)
```

Aiken validator compilation:

```bash
aiken build                # Compile validators to Plutus blueprints
aiken check                # Run Aiken tests
```

Packaging (produces `.deb` for host + auth-svc template):

```bash
./packaging/build.sh
```

## Project Structure

```
blockhost-engine-cardano/
├── validators/                         # Aiken validators (Plutus)
│   ├── subscription.ak                 # Subscription spending validator
│   ├── beacon.ak                       # Beacon minting policy (CIP-89)
│   └── nft.ak                          # NFT minting policy (CIP-68)
├── lib/blockhost/                      # Aiken shared library
│   ├── types.ak                        # Datum and redeemer types
│   └── utils.ak                        # Validator utilities
├── scripts/                            # Deployment & utility scripts
│   ├── deploy-contracts                # Validator deployer (aiken blueprint apply)
│   ├── mint_nft                        # NFT minter (blockhost-mint-nft)
│   ├── generate-signup-page            # Signup page generator (Python)
│   ├── signup-template.html            # Signup page template (replaceable HTML/CSS)
│   ├── signup-engine.js                # Signup page engine bundle (CIP-30 wallet logic)
│   └── keygen.ts                       # BIP39 / CIP-1852 wallet generator
├── blockhost/engine_cardano/           # Installer wizard plugin
│   ├── wizard.py                       # Blueprint, API routes, finalization steps
│   └── templates/engine_cardano/       # Wizard page templates
├── engine.json                         # Engine manifest
├── src/                                # TypeScript source
│   ├── monitor/                        # Beacon UTXO scanner
│   ├── handlers/                       # Scan diff event handlers
│   ├── admin/                          # Transaction metadata admin commands
│   ├── reconcile/                      # NFT ownership reconciliation
│   ├── fund-manager/                   # Batch collection & distribution
│   ├── cardano/                        # Cardano helpers (Blockfrost, wallet, beacon)
│   ├── nft/                            # NFT mint and CIP-68 reference queries
│   ├── crypto.ts                       # ECIES + SHAKE256
│   ├── bhcrypt.ts                      # bhcrypt CLI
│   ├── bw/                             # blockwallet CLI
│   ├── ab/                             # addressbook CLI
│   ├── is/                             # identity predicate CLI
│   ├── auth-svc/                       # CIP-30 auth signing server
│   └── root-agent/                     # Root agent client
├── auth-svc/                           # Auth service assets
│   └── signing-page/                   # template.html + engine.js → index.html
├── aiken.toml                          # Aiken project config
├── plutus.json                         # Compiled Plutus blueprints (generated)
├── docs/                               # Detailed documentation
└── examples/                           # Deployment examples
```

## Documentation

| Document | Contents |
|----------|----------|
| [docs/validators.md](docs/validators.md) | Aiken validators, datum structure, redeemers, beacon name computation |
| [docs/vm-authentication.md](docs/vm-authentication.md) | CIP-30 auth flow, auth-svc, .sig format, template package |
| [docs/reconciler.md](docs/reconciler.md) | Hourly ownership scan, CIP-68 token holder lookup, GECOS sync |
| [docs/configuration.md](docs/configuration.md) | Config files, addressbook, revenue sharing |
| [docs/fund-manager.md](docs/fund-manager.md) | Batch UTXO collection, lovelace distribution, hot wallet |
| [docs/cli.md](docs/cli.md) | bw, ab, is, bhcrypt — all CLIs |
| [docs/engine-manifest.md](docs/engine-manifest.md) | engine.json schema, Cardano constraints |
| [docs/privilege-separation.md](docs/privilege-separation.md) | Root agent protocol, Cardano wallet generation |
| [docs/templating.md](docs/templating.md) | Signup page template, Cardano-specific placeholders |

## License

MIT

## Related Packages

- `blockhost-common` — Shared configuration and Python modules
- `blockhost-provisioner-proxmox` — VM provisioning (Proxmox)
- `blockhost-provisioner-libvirt` — VM provisioning (libvirt/KVM)
- `libpam-web3` — PAM module for web3 authentication (installed on VMs)
