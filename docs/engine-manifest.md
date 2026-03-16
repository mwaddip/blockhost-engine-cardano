# Engine Manifest

`engine.json` declares engine identity, wizard plugin module, finalization steps, and chain-specific `constraints` used by consumers (installer, admin panel) for input validation and UI rendering.

## Schema

```json
{
  "name": "cardano",
  "version": "0.1.0",
  "display_name": "Cardano",
  "accent_color": "#0033AD",
  "setup": {
    "first_boot_hook": "/usr/share/blockhost/engine-hooks/first-boot.sh",
    "wizard_module": "blockhost.engine_cardano.wizard",
    "finalization_steps": ["wallet", "contracts", "chain_config"],
    "post_finalization_steps": ["mint_nft", "plan", "revenue_share"]
  },
  "config_keys": {
    "session_key": "blockchain"
  },
  "constraints": { ... }
}
```

## Constraints

| Field | Description | Cardano value |
|-------|-------------|---------------|
| `address_pattern` | Regex for valid addresses | `^(addr1[a-z0-9]{53,}\|addr_test1[a-z0-9]{53,}\|[0-9a-fA-F]{56})$` |
| `native_token` | Native currency keyword for CLIs | `ada` |
| `native_token_label` | Display label for native currency | `ADA` |
| `token_pattern` | Regex for valid token identifiers | `^[0-9a-fA-F]{56}(\.[0-9a-fA-F]+)?$` |
| `address_placeholder` | Placeholder for address inputs | `addr1...` |

Address pattern accepts:
- Mainnet bech32 enterprise addresses (`addr1...`, 56+ chars after prefix)
- Testnet bech32 enterprise addresses (`addr_test1...`, 56+ chars after prefix)
- Raw payment key hashes (56 hex chars, used internally)

Token pattern accepts:
- Bare policy IDs (`<56 hex chars>`) — for the `ada` / `stable` shorthands
- Policy ID + asset name (`<56 hex>.<hex asset name>`) — for native assets

All patterns are anchored regexes. If `constraints` is absent, consumers skip format validation and let CLIs reject invalid input.

## Differences from OPNet Manifest

| Aspect | OPNet | Cardano |
|--------|-------|---------|
| `name` | `opnet` | `cardano` |
| `accent_color` | `#F97900` | `#0033AD` |
| `wizard_module` | `blockhost.engine_opnet.wizard` | `blockhost.engine_cardano.wizard` |
| `address_pattern` | `0x` + 64 hex chars (or bech32 BTC) | bech32 Cardano addresses |
| `native_token` | `btc` | `ada` |
| `token_pattern` | `0x` + 64 hex chars | `<56 hex>.<hex asset name>` |
| `address_placeholder` | `0x...` | `addr1...` |

## Theming

The `accent_color` field (`#0033AD`, Cardano blue) is used as the primary brand color by the signup page generator and signing page template (as the `--primary` CSS variable).

## Installer Integration

The installer discovers `engine.json` at `/usr/share/blockhost/engine.json`. It reads:
- `wizard_module` — Python module to load as the blockchain configuration wizard page
- `finalization_steps` — Steps run before VMs can be provisioned
- `post_finalization_steps` — Steps run after finalization (plan creation, NFT minting, revenue share setup)
- `constraints` — Used for address/token format validation in the installer UI and admin panel
