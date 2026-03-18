# VM Authentication

VMs use NFT-based web3 authentication via CIP-30 wallets instead of passwords or SSH keys.

## Flow

1. VM serves the signing page on port 8443 via `web3-auth-svc` (HTTPS, self-signed TLS)
2. User connects a CIP-30 wallet that holds the NFT user token (Eternl, Nami, etc.)
3. User signs a challenge message via `api.signData()` — produces a `COSE_Sign1` structure + `COSE_Key`
4. Signing page submits `{ signature, key, otp, machineId }` to the auth-svc callback endpoint
5. Auth-svc verifies structural validity (OTP match, Ed25519 signature), writes `.sig` file
6. PAM Cardano plugin reads `.sig`, verifies identity (public key matches GECOS wallet), grants access

## Ownership

Authentication (auth-svc, signing page, PAM plugin) is maintained by the **libpam-web3 Cardano plugin**, not this engine. The engine defines the interface; the plugin implements it.

See [auth-plugin-interface.md](auth-plugin-interface.md) for the full specification.

## GECOS Format

VMs store the current NFT owner in the GECOS field, set by the provisioner at creation and updated by the reconciler on ownership transfer:

```
wallet=addr_test1qxyz...,nft=42
```

The PAM plugin reads the GECOS field to determine which wallet address to expect. It does not query the blockchain directly — ownership changes propagate through the reconciler (see [reconciler.md](reconciler.md)).

## .sig File Format

```json
{
  "chain":      "cardano",
  "signature":  "<hex-encoded COSE_Sign1>",
  "public_key": "<hex-encoded COSE_Key>",
  "otp":        "<OTP code>",
  "machine_id": "<machine identifier>"
}
```

The `chain: "cardano"` field routes to the Cardano verification plugin in PAM.

## Callback Flow

1. PAM creates a session: writes `<session_id>.json` to `/run/libpam-web3/pending/`
2. PAM prompts user with the session ID and OTP
3. User visits `https://<vm>:8443/`, connects wallet, signs, submits
4. Auth-svc writes `<session_id>.sig` atomically
5. PAM reads `.sig`, Cardano plugin verifies identity, grants access
