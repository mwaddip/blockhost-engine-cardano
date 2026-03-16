# Page Templating

The signing and signup pages are split into replaceable HTML/CSS templates and engine-owned JS bundles. Anyone forking the engine can drop in their own HTML/CSS without touching the wallet/chain JavaScript.

## Architecture

```
template (HTML/CSS)     — layout, branding, copy, styles
engine bundle (JS)      — CIP-30 wallet connection, signing, Blockfrost queries
generator (Python)      — injects config variables, combines template + bundle → output
```

The template never contains wallet or chain logic. The bundle never contains layout or styling. The generator is the glue.

## Files

### Signing Page

| File | Role |
|------|------|
| `auth-svc/signing-page/template.html` | Replaceable HTML/CSS template |
| `auth-svc/signing-page/engine.js` | Engine-owned CIP-30 wallet + Ed25519 signing logic |
| `auth-svc/signing-page/index.html` | Generated output (served by auth-svc) |

### Signup Page

| File | Role |
|------|------|
| `scripts/signup-template.html` | Replaceable HTML/CSS template |
| `scripts/signup-engine.js` | Engine-owned CIP-30 wallet + subscription + ECIES logic |
| `scripts/generate-signup-page` | Generator script (Python) |

## Template Variables

Injected as `{{VARIABLE}}` placeholders by the generator.

| Variable | Type | Description |
|----------|------|-------------|
| `PAGE_TITLE` | string | Page heading text |
| `PRIMARY_COLOR` | CSS color | Accent color (from `engine.json` → `accent_color`, default `#0033AD`) |
| `PUBLIC_SECRET` | string | Challenge message prefix the user signs |
| `SERVER_PUBLIC_KEY` | hex string | secp256k1 public key for ECIES encryption of user data |
| `NFT_POLICY_ID` | hex string | CIP-68 NFT minting policy ID (56 chars) |
| `SUBSCRIPTION_VALIDATOR_ADDRESS` | bech32 | Validator address where subscriptions are locked |
| `BEACON_POLICY_ID` | hex string | Beacon minting policy ID (56 chars) |
| `BLOCKFROST_PROJECT_ID` | string | Blockfrost project ID for client-side chain queries |
| `NETWORK` | string | `mainnet`, `preprod`, or `preview` |

The accent color is applied via a CSS variable in the template's `<style>` block:

```css
:root {
  --primary: {{PRIMARY_COLOR}};
}
```

## CONFIG Object

The template includes a `<script>` block with the CONFIG object, followed by the engine bundle:

```html
<script>
var CONFIG = {
  publicSecret:                  "{{PUBLIC_SECRET}}",
  serverPublicKey:               "{{SERVER_PUBLIC_KEY}}",
  nftPolicyId:                   "{{NFT_POLICY_ID}}",
  subscriptionValidatorAddress:  "{{SUBSCRIPTION_VALIDATOR_ADDRESS}}",
  beaconPolicyId:                "{{BEACON_POLICY_ID}}",
  blockfrostProjectId:           "{{BLOCKFROST_PROJECT_ID}}",
  network:                       "{{NETWORK}}"
};
</script>
<script src="signup-engine.js"></script>
```

## Required DOM Elements

The engine JS finds elements by `id`. Templates must include all of these.

### Signing Page

`btn-connect`, `btn-sign`, `wallet-address`, `status-message`, `step-connect`, `step-sign`

### Signup Page

`btn-connect`, `btn-sign`, `btn-purchase`, `wallet-address`, `plan-select`, `days-input`, `total-cost`, `status-message`, `step-connect`, `step-sign`, `step-purchase`, `step-servers`, `server-list`

## CSS Class Contract

The engine JS adds/removes these classes. The template defines their appearance.

| Class | Applied to | Meaning |
|-------|-----------|---------|
| `hidden` | any step container | Step not yet active |
| `active` | step container | Currently active step |
| `completed` | step container | Step finished |
| `disabled` | button | Button not yet clickable |
| `loading` | button | Operation in progress |
| `error` | `#status-message` | Error state |
| `success` | `#status-message` | Success state |

## Generating the Signup Page

```bash
blockhost-generate-signup --output /var/www/signup.html
blockhost-generate-signup --config /etc/blockhost/blockhost.yaml \
                          --web3-config /etc/blockhost/web3-defaults.yaml \
                          --output /var/www/html/signup.html
blockhost-generate-signup --serve 8080   # Generate then serve on port 8080 for testing
```

The generator reads `blockhost.yaml` + `web3-defaults.yaml`, reads `accent_color` from `engine.json`, replaces `{{VARIABLE}}` placeholders in the template, and copies `signup-engine.js` alongside the output HTML.

## Creating a Custom Template

1. Copy the default `template.html` or `signup-template.html`
2. Modify HTML structure, CSS, copy, images — anything visual
3. Keep all required DOM element IDs intact
4. Keep the `CONFIG` script block and engine bundle include
5. Rebuild: run `blockhost-generate-signup` or restart auth-svc

The template can add any extra elements, sections, or styling. It must not remove or rename the required IDs.
