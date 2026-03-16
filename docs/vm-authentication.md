# VM Authentication

VMs use NFT-based web3 authentication via CIP-30 wallets instead of passwords or SSH keys.

## Flow

1. VM serves the signing page on port 8443 via `web3-auth-svc` (HTTPS, self-signed TLS)
2. User connects a CIP-30 wallet that holds the NFT user token (Eternl, Nami, etc.)
3. User signs a challenge message via `api.signData()` — produces a `COSE_Sign1` structure + `COSE_Key`
4. Signing page submits `{ signature, key, otp, machineId }` to the auth-svc callback endpoint
5. Auth-svc verifies OTP (timing-safe), validates hex fields, writes a structured `.sig` file
6. PAM module picks up the `.sig` file, performs full Ed25519 / COSE_Sign1 verification, authenticates the user

## CIP-30 Wallet Connection

The signing page uses `window.cardano.<wallet>.enable()` to request a CIP-30 API handle, then calls `api.signData(address, payload)`. The wallet returns:

```json
{
  "signature": "<hex-encoded COSE_Sign1>",
  "key": "<hex-encoded COSE_Key>"
}
```

The challenge payload is UTF-8: `"Authenticate to {machineId} with code: {otp}"`.

Supported wallets: any CIP-30-compliant wallet (Eternl, Nami, Flint, Vespr, Lace, etc.).

## .sig File Format

The auth-svc writes a JSON `.sig` file to `/run/libpam-web3/pending/<session_id>.sig`:

```json
{
  "chain":      "cardano",
  "signature":  "<hex-encoded COSE_Sign1>",
  "public_key": "<hex-encoded COSE_Key>",
  "otp":        "<OTP code>",
  "machine_id": "<machine identifier>"
}
```

The `chain: "cardano"` field tells the PAM verifier plugin which cryptographic verification path to use (Ed25519 over the COSE SigStructure).

**Cryptographic verification note:** The auth-svc currently performs OTP timing-safe comparison and structural validation of hex fields. Full COSE_Sign1 Ed25519 verification (CBOR decode → protected header check → Sig_Structure reconstruction → signature verify) is deferred to the PAM verifier plugin on the VM, pending cbor/cose library availability in the esbuild bundle.

## Auth Service (`web3-auth-svc`)

HTTPS signing server, esbuild-bundled for deployment on VMs.

### Routes

| Method | Path | Description |
|--------|------|-------------|
| GET | `/` | Serve signing page HTML |
| GET | `/engine.js` | Serve signing page engine bundle |
| GET | `/auth/pending/:session_id` | Return session JSON from pending dir |
| POST | `/auth/callback/:session_id` | Verify OTP, write `.sig` file |

### Config

Reads `/etc/web3-auth/config.toml`:

```toml
[https]
port = 8443
bind = ["::"]
cert_path = "/etc/libpam-web3/tls/cert.pem"
key_path = "/etc/libpam-web3/tls/key.pem"
signing_page_path = "/usr/share/blockhost/signing-page/index.html"
pending_dir = "/run/libpam-web3/pending"
```

## GECOS Format

VMs store the current NFT owner in the GECOS field, set by the provisioner at creation and updated by the reconciler on ownership transfer:

```
wallet=addr1qxyz...,nft=42
```

The PAM module reads the GECOS field to determine which wallet address and NFT token ID to expect. It does not query the blockchain directly — ownership changes propagate through the reconciler (see [reconciler.md](reconciler.md)).

## Auth-svc Callback Flow (from PAM perspective)

1. PAM module creates a session: writes `<session_id>.json` to the pending dir with `{ "otp": "...", "machine_id": "..." }`
2. PAM prompts user with the session ID and OTP
3. User visits `https://<vm>:8443/`, connects wallet, signs, submits
4. Auth-svc writes `<session_id>.sig` atomically (tmp → rename, first-claim-wins)
5. PAM polls for `<session_id>.sig`, reads it, verifies COSE_Sign1 + NFT ownership, grants access

## Template Package

Ships as `blockhost-auth-svc_<version>_all.deb`, installed on VM templates (not the host):

| File | Purpose |
|------|---------|
| `/usr/share/blockhost/auth-svc.js` | Bundled JS |
| `/usr/bin/web3-auth-svc` | Node wrapper script |
| `/usr/share/blockhost/signing-page/index.html` | Signing page (generated from template) |
| `/usr/share/blockhost/signing-page/template.html` | Signing page template (replaceable) |
| `/usr/share/blockhost/signing-page/engine.js` | Signing page engine bundle (CIP-30 wallet logic) |
| `/lib/systemd/system/web3-auth-svc.service` | Systemd unit |
| `/usr/lib/tmpfiles.d/web3-auth-svc.conf` | Creates pending dir on boot |

The auth-svc is engine-owned — it is compiled and packaged by this engine, then installed on VMs via the template. See [templating.md](templating.md) for how to customize the signing page.
