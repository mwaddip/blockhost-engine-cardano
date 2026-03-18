# Blockhost Engine (Cardano)

UTXO-native VM hosting subscription system on Cardano. Subscribers lock funds at a validator address with beacon tokens for discoverability. No shared contract state, no custody transfer — subscribers retain control of their funds until the service collects earned payment at configurable intervals.

## How It Works

1. **User visits signup page** — Connects CIP-30 wallet (Eternl, Nami, etc.), selects plan, pays
2. **Subscription UTXO created** — Funds locked at per-subscriber script address with beacon token + inline datum
3. **Monitor detects beacon** — Scans for new beacon tokens via Koios, triggers VM provisioning
4. **VM is created** — With web3-only SSH authentication (no passwords, no keys)
5. **NFT is minted** — CIP-68 credential with encrypted connection details in reference datum
6. **User authenticates** — Signs with Cardano wallet on VM's signing page, PAM plugin verifies

## Architecture

```
┌─────────────────┐     ┌──────────────────┐     ┌─────────────────┐
│   Signup Page   │────>│  Subscription    │────>│  Monitor Svc    │
│   (static HTML) │     │  Validator (Aiken)│     │  (TypeScript)   │
└─────────────────┘     └──────────────────┘     └────────┬────────┘
                                                          │
                                                          v
┌─────────────────┐     ┌──────────────────┐     ┌─────────────────┐
│   User's VM     │<────│  Provisioner     │<────│  Engine         │
│   (PAM plugin)  │     │  (pluggable)     │     │  (manifest)     │
└─────────────────┘     └──────────────────┘     └─────────────────┘
```

Key differences from EVM/OPNet engines:
- **Per-subscriber UTXOs** at CIP-89 addresses (script payment + subscriber staking)
- **Beacon tokens** instead of contract events for subscription discovery
- **Interval-based collection** — service claims earned payment periodically, not all at once
- **Fair cancellation** — validator enforces earned/refund split
- **Koios** as default chain provider (free, no API key)

## Components

| Component | Language | Description |
|-----------|----------|-------------|
| `validators/` | Aiken | Subscription, beacon, and NFT minting policies |
| `src/monitor/` | TypeScript | Beacon UTXO scanner |
| `src/handlers/` | TypeScript | Subscription lifecycle handlers (provision, extend, cancel) |
| `src/admin/` | TypeScript | On-chain admin commands via transaction metadata |
| `src/reconcile/` | TypeScript | NFT ownership reconciliation and GECOS sync |
| `src/fund-manager/` | TypeScript | Batch subscription collection and revenue distribution |
| `src/bw/` | TypeScript | blockwallet CLI (send, balance, withdraw, plan, who, set) |
| `src/ab/` | TypeScript | Addressbook CLI |
| `src/is/` | TypeScript | Identity predicate CLI |
| `src/bhcrypt.ts` | TypeScript | Crypto tool (keypair gen, ECIES, symmetric, Cardano keygen) |
| `src/cardano/` | TypeScript | Cardano utilities (provider, wallet, beacon, address, types) |
| `src/root-agent/` | TypeScript | Root agent client (privilege separation) |
| `blockhost/engine_cardano/` | Python | Installer wizard plugin |
| `scripts/` | TS/Bash/Python | Deployment, minting, signup page generation |

## On-chain Components (Aiken Validators)

Three Plutus V3 validators, parameterized at deploy time:

- **Subscription validator** — Spending script with 4 redeemers: `ServiceCollect` (interval-based partial collection), `SubscriberCancel` (fair split), `SubscriberExtend` (top up), `Migrate` (upgrade path)
- **Beacon minting policy** — Mints discoverable beacon tokens alongside subscriptions, burns on collection/cancellation
- **NFT minting policy** — CIP-68 access credentials (user token + reference token with encrypted datum)

## Authentication

Authentication is handled by the **libpam-web3 Cardano plugin** (separate repo), not this engine. The engine defines:
- The `.sig` file format (`{ chain: "cardano", signature, public_key, otp, machine_id }`)
- The GECOS format (`wallet=<bech32_addr>,nft=<token_id>`)
- The CIP-30 signData flow for credential derivation

See [docs/auth-plugin-interface.md](docs/auth-plugin-interface.md) for the full specification.

## Prerequisites

- Node.js 22+
- Python 3.10+
- Aiken v1.1.21+ (for validator development)
- `blockhost-common` package
- A provisioner package (e.g. `blockhost-provisioner-proxmox`)

## Development Setup

```bash
git clone https://github.com/mwaddip/blockhost-engine-cardano.git
cd blockhost-engine-cardano
npm install
```

```bash
npx tsc --noEmit                    # Type-check TypeScript
export PATH="$HOME/.aiken/bin:$PATH"
aiken build                         # Build validators -> plutus.json
aiken check                         # Run validator tests
```

Packaging (produces `.deb` for host):

```bash
./packaging/build.sh
```

## Project Structure

```
blockhost-engine-cardano/
├── validators/                     # Aiken validators (Plutus V3)
│   ├── subscription.ak             # Subscription spending validator
│   ├── beacon.ak                   # Beacon minting/staking policy
│   └── nft.ak                      # NFT minting policy (CIP-68)
├── lib/blockhost/                  # Shared Aiken library code
│   ├── types.ak                    # Datum/redeemer type definitions
│   └── utils.ak                    # Validation helpers
├── src/                            # TypeScript source
│   ├── monitor/                    # Beacon UTXO scanner
│   ├── handlers/                   # Subscription lifecycle handlers
│   ├── admin/                      # On-chain admin commands
│   ├── reconcile/                  # NFT ownership reconciliation
│   ├── fund-manager/               # Batch collection & distribution
│   ├── cardano/                    # Cardano utilities (provider, wallet, types)
│   ├── bw/                         # blockwallet CLI
│   ├── ab/                         # addressbook CLI
│   ├── is/                         # identity predicate CLI
│   ├── crypto.ts                   # ECIES + SHAKE256 symmetric
│   ├── bhcrypt.ts                  # Crypto tool CLI
│   ├── provisioner.ts              # Provisioner manifest reader
│   └── root-agent/                 # Root agent client
├── scripts/                        # Deployment & utility scripts
│   ├── deploy-contracts            # Validator deployment
│   ├── mint_nft.ts                 # CIP-68 NFT minting
│   ├── keygen.ts                   # Cardano wallet generation
│   ├── generate-signup-page        # Signup page renderer
│   ├── signup-template.html        # Signup page HTML template
│   └── signup-engine.js            # Browser-side subscription tx builder
├── blockhost/engine_cardano/       # Installer wizard plugin
│   ├── wizard.py                   # Flask blueprint + finalization steps
│   └── templates/engine_cardano/   # Wizard page templates
├── engine.json                     # Engine manifest
├── aiken.toml                      # Aiken project config
├── plutus.json                     # Compiled validator blueprint
├── packaging/                      # .deb build script
├── root-agent-actions/             # Root agent wallet plugin
├── examples/                       # Systemd units
└── docs/                           # Documentation
```

## Documentation

| Document | Contents |
|----------|----------|
| [docs/validators.md](docs/validators.md) | Aiken validators: datum, redeemers, spending paths |
| [docs/auth-plugin-interface.md](docs/auth-plugin-interface.md) | Auth plugin spec: .sig format, verification steps, GECOS |
| [docs/vm-authentication.md](docs/vm-authentication.md) | Auth flow overview, GECOS format, reconciliation |
| [docs/reconciler.md](docs/reconciler.md) | NFT ownership reconciliation, GECOS sync |
| [docs/configuration.md](docs/configuration.md) | Config files, addressbook, revenue sharing |
| [docs/fund-manager.md](docs/fund-manager.md) | Batch collection, distribution, hot wallet |
| [docs/cli.md](docs/cli.md) | bw, ab, is, bhcrypt — all CLI tools |
| [docs/engine-manifest.md](docs/engine-manifest.md) | engine.json schema, constraints |
| [docs/privilege-separation.md](docs/privilege-separation.md) | Root agent protocol |
| [docs/templating.md](docs/templating.md) | Signup page templates, placeholders |

## License

MIT

## Related Packages

- `blockhost-common` — Shared configuration and Python modules
- `blockhost-provisioner-proxmox` — VM provisioning (Proxmox)
- `blockhost-provisioner-libvirt` — VM provisioning (libvirt/KVM)
- `libpam-web3` — PAM module + chain-specific auth plugins (installed on VMs)
