# Cardano Auth Plugin Interface

> Specification for the libpam-web3 Cardano authentication plugin.
> The engine defines this interface; the plugin implements it.

---

## 1. `.sig` File Format

The auth-svc writes structured JSON to `/run/libpam-web3/pending/<session_id>.sig`:

```json
{
  "chain": "cardano",
  "signature": "<hex-encoded COSE_Sign1>",
  "public_key": "<hex-encoded COSE_Key>",
  "otp": "<OTP code>",
  "machine_id": "<machine identifier>"
}
```

| Field | Type | Description |
|-------|------|-------------|
| `chain` | `"cardano"` | Mandatory. Routes to the Cardano verification plugin. |
| `signature` | hex string | COSE_Sign1 structure from CIP-30 `api.signData()` |
| `public_key` | hex string | COSE_Key structure from CIP-30 `api.signData()` |
| `otp` | string | The OTP code the user entered |
| `machine_id` | string | The machine identifier the user entered |

The `signature` and `public_key` fields are hex-encoded CBOR. The CIP-30 `signData(address, hexPayload)` method returns both as a `DataSignature` object.

---

## 2. Auth-svc Verification (structural)

The auth-svc performs structural verification before writing the `.sig` file:

1. Timing-safe OTP comparison against session file
2. CBOR-decode COSE_Sign1, verify protected header contains `alg = -8` (EdDSA)
3. Extract Ed25519 public key from COSE_Key (key `-2`, 32 bytes)
4. Verify payload matches expected OTP message: `"Authenticate to {machine_id} with code: {otp}"`
5. Verify Ed25519 signature over COSE Sig_structure

This confirms the signature is real (not forged/garbage). It does NOT verify identity.

---

## 3. PAM Plugin Verification (identity)

After reading the `.sig` file, the PAM Cardano plugin verifies the signer is the account holder:

1. Parse `.sig` JSON, check `chain === "cardano"`
2. CBOR-decode `public_key` as COSE_Key map
3. Extract Ed25519 public key bytes (key `-2`)
4. Derive the Cardano payment key hash: `blake2b_224(public_key_bytes)`
5. Construct the expected bech32 address from the key hash
6. Compare against `wallet=<addr>` from the GECOS field
7. Pass if they match, fail otherwise

### COSE_Key Structure

CIP-30 returns a COSE_Key as a CBOR map:

```
{
  1: 1,      // kty = OKP (Octet Key Pair)
  3: -8,     // alg = EdDSA
  -1: 6,     // crv = Ed25519
  -2: <bytes> // x = 32-byte Ed25519 public key
}
```

### COSE_Sign1 Structure

```
[
  protected_headers,    // CBOR bstr containing { 1: -8 } (alg = EdDSA)
  unprotected_headers,  // CBOR map (usually empty)
  payload,              // CBOR bstr = the signed message bytes
  signature             // 64-byte Ed25519 signature
]
```

### Sig_structure for Verification

To verify, reconstruct the COSE Sig_structure and verify the Ed25519 signature over its CBOR encoding:

```
Sig_structure = [
  "Signature1",         // context string
  protected_headers,    // raw bytes (as-is from COSE_Sign1[0])
  b"",                  // external_aad (empty)
  payload               // raw bytes (as-is from COSE_Sign1[2])
]
```

`Ed25519.verify(signature, CBOR(Sig_structure), public_key)` must return true.

---

## 4. GECOS Format

The provisioner writes GECOS on the VM's Linux user account:

```
wallet=<bech32_address>,nft=<token_id>
```

| Field | Format | Example |
|-------|--------|---------|
| `wallet` | Cardano bech32 address | `addr_test1qr...` or `addr1q...` |
| `nft` | Integer token ID | `3` |

The `wallet` value is the subscriber's payment address (bech32). The plugin derives the expected address from the COSE_Key public key and compares.

---

## 5. Signing Page

The signing page connects to CIP-30 wallets and produces the signature:

1. Detect available wallets via `window.cardano` (with retry for async injection)
2. User selects wallet → `api = await window.cardano[name].enable()`
3. Get address: `api.getUsedAddresses()` (returns hex-encoded addresses)
4. Sign message: `api.signData(address, hexPayload)` where `hexPayload` = hex-encoded UTF-8 of `"Authenticate to {machine_id} with code: {otp}"`
5. Returns `{ signature: hexCOSE_Sign1, key: hexCOSE_Key }`

In callback mode (`?session=<id>` URL parameter):
- POST `{ signature, key, otp, machineId }` to `/auth/callback/<session_id>`
- Auth-svc writes `.sig` file, user presses Enter in terminal

In manual mode:
- Display JSON for copy-paste into terminal

### Supported Wallets

Any CIP-30 compatible wallet. Tested with: Eternl, Nami, Lace, Flint, Typhon.

### Colors

Cardano brand: `#0033AD` primary, `#0CBCF5` teal accents on wallet buttons.

---

## 6. Deployment

The auth plugin ships as a template package installed on VMs:

```
/usr/bin/web3-auth-svc                          — Node.js wrapper
/usr/share/blockhost/auth-svc.js                — Bundled auth server
/usr/share/blockhost/signing-page/index.html    — CIP-30 signing page
/usr/share/blockhost/signing-page/engine.js     — Wallet interaction JS
/lib/systemd/system/web3-auth-svc.service       — Systemd unit
/usr/lib/tmpfiles.d/libpam-web3.conf            — Creates /run/libpam-web3/pending/
/etc/web3-auth/config.toml                      — Written by cloud-init template
```

### Config (TOML)

```toml
[https]
port = 8443
bind = ["::","0.0.0.0"]
cert_path = "/etc/libpam-web3/tls/cert.pem"
key_path = "/etc/libpam-web3/tls/key.pem"
signing_page_path = "/usr/share/blockhost/signing-page/index.html"
pending_dir = "/run/libpam-web3/pending"
```

### Build

```bash
npx esbuild auth-svc-src/index.ts \
  --bundle --platform=node --target=node22 --minify \
  --outfile=auth-svc.js
```

### Dependencies

- `cbor` — CBOR encoding/decoding
- `@noble/ed25519` — Ed25519 signature verification
- `@noble/curves` — secp256k1 (for ECIES in crypto.ts)
- `@noble/hashes` — blake2b, sha256, shake256, hkdf
