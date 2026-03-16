# Privilege Separation

The monitor service runs as the unprivileged `blockhost` user. Operations that require root are delegated to a separate **root agent daemon** (provided by `blockhost-common`) via a Unix socket at `/run/blockhost/root-agent.sock`.

This is chain-agnostic infrastructure shared across all BlockHost engines. The only Cardano-specific detail is how wallet generation works.

## Protocol

Length-prefixed JSON: 4-byte big-endian length + JSON payload (both directions).

- Request: `{"action": "action-name", "params": {...}}`
- Response: `{"ok": true, ...}` or `{"ok": false, "error": "reason"}`

## Client

The TypeScript client (`src/root-agent/client.ts`) provides typed wrappers:

| Action | Description |
|--------|-------------|
| `iptables-open` | Add an ACCEPT rule for a port |
| `iptables-close` | Remove an ACCEPT rule for a port |
| `generate-wallet` | Generate a Cardano wallet, save mnemonic to `/etc/blockhost/<name>.key`, update addressbook |
| `addressbook-save` | Write addressbook entries to `/etc/blockhost/addressbook.json` |

The `qm-start` action (Proxmox VM start) is available via the root agent when the Proxmox provisioner is in use.

## Cardano Wallet Generation

The root agent's `generate-wallet` action invokes `scripts/keygen.ts` as a subprocess. `keygen.ts`:

1. Generates a 24-word BIP39 mnemonic (256-bit entropy)
2. Derives the CIP-1852 Cardano wallet (account 0, payment key index 0)
3. Outputs JSON: `{ mnemonic, address, paymentKeyHash, stakeKeyHash, network }`

The root agent writes the mnemonic to `/etc/blockhost/<name>.key` (chmod 600, `blockhost` group) and adds the bech32 address to `addressbook.json`.

```bash
# keygen usage (called by root agent, not directly)
keygen [--network preprod|mainnet|preview]
```

## What Does NOT Go Through the Root Agent

- Reading keyfiles and `addressbook.json` — works via group permission (`blockhost` group, mode 0640)
- ECIES decryption — `blockhost` user can read `server.key` via group permission
- VM provisioning scripts — provisioner runs as `blockhost`
- Process checks (`pgrep`) — no privilege needed
- Blockfrost API queries — no privilege needed

## Systemd

The monitor service declares a dependency on `blockhost-root-agent.service` and runs with `NoNewPrivileges=true` and `ProtectSystem=strict`. See `examples/blockhost-monitor.service`.
