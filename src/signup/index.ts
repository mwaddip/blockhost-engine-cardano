/// <reference lib="DOM" />
/// <reference lib="DOM.Iterable" />

/**
 * Signup page engine for Cardano (BlockHost) — cmttk-based port.
 *
 * Browser-loaded via <script src="signup-engine.js">. Bundled by esbuild
 * to an IIFE and served as a static file by nginx next to signup.html.
 *
 * Loaded after an inline CONFIG block injected by generate-signup-page.
 * Handles:
 *   1. CIP-30 wallet detection and connection
 *   2. Plan fetching from plan reference UTXOs via Koios REST API
 *   3. Cost calculation
 *   4. Subscription transaction building (inline CBOR + CIP-30 + Koios)
 *
 * Expected global: CONFIG (set by the inline script block in signup-template.html)
 *
 * CBOR + hex primitives are imported from cmttk/cbor. Plutus Data encoding
 * is kept local because the signup path requires indefinite-length Constr
 * fields (0x9f..0xff) for wallet/CSL compatibility, whereas cmttk's
 * Data.to / encodeConstr emits definite-length arrays.
 */

import {
    hexToBytes,
    bytesToHex,
} from "@mwaddip/cmttk/cbor";
import {
    parseCip30Utxos,
    buildUnsignedScriptTx,
    mergeCip30Witness,
    type TxOutput,
    type MintEntry,
    type Assets,
} from "@mwaddip/cmttk/tx";
import { getProvider } from "@mwaddip/cmttk/provider";
import type { CardanoNetwork } from "@mwaddip/cmttk";
import { bech32 } from "bech32";
import {
    plutusConstr,
    encodePlutusSubscriptionDatum,
} from "./encoder.js";

declare const CONFIG: {
    network: string;
    publicSecret: string;
    serverPublicKey: string;
    validatorAddress: string;
    subscriptionValidatorHash: string;
    beaconPolicyId: string;
    beaconScriptCbor: string;
    nftPolicyId: string;
    deployerAddress: string;
};

declare global {
    interface Window {
        cardano: Record<string, any> | undefined;
        switchTab: (tab: string) => void;
        _offlineNftData?: { tokenId: string; userEncrypted: string };
    }
}

// ── Koios provider ─────────────────────────────────────────────────
//
// cmttk's KoiosProvider handles all chain queries with retry + JSON parsing.
// We pass `/api/v1` as the base URL so requests go through our local nginx
// proxy (forwards to https://{network}.koios.rest/api/v1/*), avoiding CORS.

const provider = getProvider(CONFIG.network as CardanoNetwork, undefined, '/api/v1');

// ── ECIES encryption (secp256k1 ECDH + HKDF-SHA256 + AES-GCM) ───────
// Wire format: ephemeralPub(65) || IV(12) || ciphertext+tag
// Matches the server-side eciesDecrypt() in src/crypto.ts.
//
// Uses the noble-curves and noble-hashes ES module builds loaded from esm.run.
// These are the same library versions the OPNet signing page uses, so they
// are already known-good in browser environments.

let _eciesReady = false;
let _secp256k1: any = null;
let _hkdf: any = null;
let _sha256: any = null;
let _randomBytes: any = null;

/**
 * Lazy-load noble crypto libraries from CDN (esm.run → jsDelivr).
 * Called once before the first ECIES encrypt.
 */
async function ensureEcies(): Promise<void> {
    if (_eciesReady) return;
    // CDN imports resolved by the browser at runtime; esbuild treats them as external.
    const dynImport = (url: string): Promise<any> => (0, eval)(`import(${JSON.stringify(url)})`);
    let mod: any;
    mod = await dynImport('https://esm.run/@noble/curves@1.4.0/secp256k1');
    _secp256k1 = mod.secp256k1;
    mod = await dynImport('https://esm.run/@noble/hashes@1.4.0/hkdf');
    _hkdf = mod.hkdf;
    mod = await dynImport('https://esm.run/@noble/hashes@1.4.0/sha256');
    _sha256 = mod.sha256;
    mod = await dynImport('https://esm.run/@noble/hashes@1.4.0/utils');
    _randomBytes = mod.randomBytes;
    _eciesReady = true;
}

/**
 * ECIES encrypt plaintext with the server's secp256k1 public key.
 */
async function eciesEncrypt(serverPubKeyHex: string, plaintext: string): Promise<string> {
    await ensureEcies();
    const serverPubBytes = hexToBytes(serverPubKeyHex);
    const ephPriv = _randomBytes(32);
    const ephPub = _secp256k1.getPublicKey(ephPriv, false); // uncompressed, 65 bytes
    const shared = _secp256k1.getSharedSecret(ephPriv, serverPubBytes, false);
    const sharedX = shared.slice(1, 33);
    const encKey = _hkdf(_sha256, sharedX, new Uint8Array(0), new Uint8Array(0), 32);
    const iv = _randomBytes(12);
    const cryptoKey = await crypto.subtle.importKey('raw', encKey, { name: 'AES-GCM' }, false, ['encrypt']);
    const ptBytes = new TextEncoder().encode(plaintext);
    const ctWithTag = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: iv }, cryptoKey, ptBytes);
    const result = new Uint8Array(ephPub.length + iv.length + ctWithTag.byteLength);
    result.set(ephPub, 0);
    result.set(iv, ephPub.length);
    result.set(new Uint8Array(ctWithTag), ephPub.length + iv.length);
    return bytesToHex(result);
}

// ── COSE_Sign1 signature extraction ────────────────────────────────────
//
// CIP-30 signData returns { signature: COSE_Sign1_hex, key: COSE_Key_hex }.
// COSE_Sign1 is CBOR: Tag(18) Array(4) [ protected, unprotected, payload, signature ].
// We need the raw Ed25519 signature (element 3, 64 bytes).

/** Skip one CBOR item starting at pos. Returns new pos, or -1 on error. */
function cborSkip(b: Uint8Array, pos: number): number {
    if (pos >= b.length) return -1;
    const major = b[pos]! >> 5;
    const info = b[pos]! & 0x1F;
    pos++;
    let arg = 0;
    if (info < 24) arg = info;
    else if (info === 24) { arg = b[pos++]!; }
    else if (info === 25) { arg = (b[pos]! << 8) | b[pos + 1]!; pos += 2; }
    else if (info === 26) { arg = ((b[pos]! << 24) >>> 0) | (b[pos + 1]! << 16) | (b[pos + 2]! << 8) | b[pos + 3]!; pos += 4; }
    else if (info === 31) {
        if (major === 7) return pos;
        while (b[pos] !== 0xFF) { pos = cborSkip(b, pos); if (pos < 0) return -1; }
        return pos + 1;
    }
    else return -1;
    switch (major) {
        case 0: case 1: return pos;
        case 2: case 3: return pos + arg;
        case 4: for (let i = 0; i < arg; i++) { pos = cborSkip(b, pos); if (pos < 0) return -1; } return pos;
        case 5: for (let i = 0; i < arg * 2; i++) { pos = cborSkip(b, pos); if (pos < 0) return -1; } return pos;
        case 6: return cborSkip(b, pos);
        case 7: return pos;
    }
    return -1;
}

/** Extract the raw Ed25519 signature (64 bytes hex) from a COSE_Sign1 CBOR hex string. */
function extractCoseSignature(coseHex: string): string | null {
    const b = hexToBytes(coseHex);
    let pos = 0;
    // Skip optional CBOR tag 18
    if (b[pos] === 0xD8 && b[pos + 1] === 0x12) pos += 2;
    // Must be definite array(4)
    if (b[pos] !== 0x84) return null;
    pos++;
    // Skip protected, unprotected, payload
    for (let i = 0; i < 3; i++) { pos = cborSkip(b, pos); if (pos < 0) return null; }
    // Read signature (byte string)
    if ((b[pos]! >> 5) !== 2) return null;
    const info = b[pos]! & 0x1F;
    pos++;
    let len = 0;
    if (info < 24) len = info;
    else if (info === 24) { len = b[pos++]!; }
    else if (info === 25) { len = (b[pos]! << 8) | b[pos + 1]!; pos += 2; }
    else return null;
    return bytesToHex(b.slice(pos, pos + len));
}

// ── SHAKE256 + AES-GCM symmetric decryption ────────────────────────────
//
// Matches the server-side symmetricEncrypt() in src/crypto.ts.
// Key derivation: SHAKE256(signatureBytes, 32 bytes)
// Wire format:    IV(12) + ciphertext + authTag(16)

let _shake256: any = null;

/** Lazy-load SHAKE256 from noble-hashes CDN. */
async function ensureShake256(): Promise<void> {
    if (_shake256) return;
    const dynImport = (url: string): Promise<any> => (0, eval)(`import(${JSON.stringify(url)})`);
    const mod: any = await dynImport('https://esm.run/@noble/hashes@1.4.0/sha3');
    _shake256 = mod.shake256;
}

/** Derive a 32-byte AES key from signature bytes using SHAKE256. */
function deriveSymmetricKey(signatureBytes: Uint8Array): Uint8Array {
    return _shake256(signatureBytes, { dkLen: 32 });
}

/** Decrypt AES-256-GCM ciphertext using a SHAKE256-derived key. */
async function decryptAesGcm(keyBytes: Uint8Array, ciphertextHex: string): Promise<string> {
    const data = hexToBytes(ciphertextHex);
    if (data.length < 28) throw new Error('Ciphertext too short');
    const iv = data.slice(0, 12);
    const ct = data.slice(12);
    const key = await crypto.subtle.importKey('raw', keyBytes as BufferSource, { name: 'AES-GCM' }, false, ['decrypt']);
    const decrypted = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: iv }, key, ct);
    return new TextDecoder().decode(decrypted);
}

// ── CIP-68 NFT helpers ──────────────────────────────────────────────────

const CIP68_USER_PREFIX = '000de140';
const CIP68_REF_PREFIX = '000643b0';

/** Extract token ID (integer) from a CIP-68 user token asset name hex. */
function tokenIdFromAssetName(assetNameHex: string): number | null {
    if (assetNameHex.startsWith(CIP68_USER_PREFIX)) {
        return parseInt(assetNameHex.slice(CIP68_USER_PREFIX.length), 16);
    }
    return null;
}

/** Build the (100) reference token asset name for a given user token asset name. */
function refAssetName(userAssetNameHex: string): string {
    return CIP68_REF_PREFIX + userAssetNameHex.slice(CIP68_USER_PREFIX.length);
}

// ── State for View My Servers / Admin ────────────────────────────────────

let userNfts: Array<{ tokenId: number; name: string; userAssetName: string }> = [];
let selectedNft: { tokenId: number; name: string; userAssetName: string } | null = null;

// ── Plan data (fetched from Koios) ─────────────────────────────────────

interface Plan { planId: number; name: string; pricePerDay: bigint; paymentAsset: string }

let plans: Plan[] = [];

/**
 * Parse a plan datum from a Koios UTXO's inline_datum JSON.
 *
 * The on-chain plan datum structure (set by blockhost-bw plan create) is:
 *   Constr(0, [plan_id, name, price_per_day, payment_assets, active])
 */
function parsePlanDatum(utxo: any): Plan | null {
    try {
        // Koios wraps inline datum in { value: {...}, bytes: "..." }
        const rawDatum = utxo.inline_datum;
        const datum = rawDatum && rawDatum.value ? rawDatum.value : rawDatum;
        if (!datum || !datum.fields || !Array.isArray(datum.fields)) return null;
        const fields = datum.fields;
        // fields[0] = planId (int)
        // fields[1] = name (bytes / string)
        // fields[2] = pricePerDay (int)
        // fields[3] = paymentAssets (list)
        // fields[4] = active (int: 1 = true)
        const planId = Number(fields[0] && fields[0].int != null ? fields[0].int : fields[0]);
        const nameRaw = fields[1];
        let name = '';
        if (nameRaw) {
            if (typeof nameRaw === 'string') name = nameRaw;
            else if (nameRaw.bytes) name = decodeHexString(nameRaw.bytes);
            else if (nameRaw.string) name = nameRaw.string;
        }
        const pricePerDay = BigInt(
            fields[2] && fields[2].int != null ? fields[2].int : (fields[2] || 0)
        );
        // active: Constr(1,[]) = True, Constr(0,[]) = False in Aiken
        const activeField = fields[4];
        let active = false;
        if (activeField != null) {
            if (typeof activeField === 'number') active = activeField !== 0;
            else if (activeField.constructor != null) active = activeField.constructor === 1;
            else active = Boolean(activeField);
        }
        if (!active) return null;
        // paymentAsset: take first from list, format as "policyId.assetName"
        let paymentAsset = '';
        const assetsList = fields[3];
        if (assetsList && Array.isArray(assetsList.list) && assetsList.list.length > 0) {
            const first = assetsList.list[0];
            if (first && first.fields && first.fields.length >= 2) {
                const pid = first.fields[0] && first.fields[0].bytes ? first.fields[0].bytes : '';
                const aname = first.fields[1] && first.fields[1].bytes ? first.fields[1].bytes : '';
                paymentAsset = pid + (aname ? '.' + aname : '');
            }
        }
        return { planId: planId, name: name || ('Plan ' + planId), pricePerDay: pricePerDay, paymentAsset: paymentAsset };
    } catch (e) {
        console.warn('parsePlanDatum error:', e);
        return null;
    }
}

function decodeHexString(hex: string): string {
    try {
        const bytes = hexToBytes(hex);
        return new TextDecoder().decode(bytes);
    } catch (_) {
        return hex;
    }
}

/**
 * Fetch active plans from the validator address via Koios.
 * Plans are stored as inline-datum UTXOs at CONFIG.validatorAddress.
 */
async function loadPlans(): Promise<void> {
    const sel = document.getElementById('plan-select') as HTMLSelectElement;
    if (!CONFIG.validatorAddress) {
        sel.innerHTML = '<option value="">Validator address not configured</option>';
        return;
    }

    try {
        // Query all UTXOs at the validator address. cmttk's KoiosProvider
        // uses _extended: true, so inline_datum is present on each entry.
        const utxos = await provider.fetchUtxos(CONFIG.validatorAddress) as any[];

        if (!utxos || !Array.isArray(utxos) || utxos.length === 0) {
            sel.innerHTML = '<option value="">No plans available</option>';
            return;
        }

        // Plan UTXOs are identified by their datum structure (5 fields),
        // not by beacon tokens. Try parsing each UTXO as a plan datum.
        plans = [];
        for (let i = 0; i < utxos.length; i++) {
            const plan = parsePlanDatum(utxos[i]);
            if (plan) plans.push(plan);
        }

        sel.innerHTML = '';
        if (plans.length === 0) {
            sel.innerHTML = '<option value="">No active plans found</option>';
            return;
        }

        for (let j = 0; j < plans.length; j++) {
            const opt = document.createElement('option');
            opt.value = String(plans[j]!.planId);
            opt.textContent = plans[j]!.name;
            sel.appendChild(opt);
        }

        // Enable plan selection now that we have data
        sel.disabled = false;
        updateCost();

    } catch (err) {
        console.error('loadPlans error:', err);
        sel.innerHTML = '<option value="">Error loading plans</option>';
    }
}

// ── Cost formatting ─────────────────────────────────────────────────

/**
 * Format a token amount for display.
 */
function formatAmount(baseUnits: bigint, decimals: number, symbol: string): string {
    if (decimals === 0) return baseUnits.toLocaleString() + ' ' + symbol;

    const factor = BigInt(Math.pow(10, decimals));
    let whole = baseUnits / factor;
    let frac = baseUnits % factor;
    if (frac < 0n) frac = -frac;

    const fracStr = frac.toString().padStart(decimals, '0');
    const num = Number(whole.toString() + '.' + fracStr);

    // Smart decimal display:
    //   >= 100:  no decimals (150 ADA)
    //   1-99:   2 decimals  (5.00 ADA)
    //   < 1:    up to 4 significant digits after last leading zero
    let formatted: string;
    if (num >= 100) {
        formatted = Math.round(num).toLocaleString();
    } else if (num >= 1) {
        formatted = num.toFixed(2);
    } else if (num > 0) {
        // Find first non-zero decimal position, show up to 4 more digits
        const s = num.toFixed(decimals);
        const dotIdx = s.indexOf('.');
        let firstNonZero = -1;
        for (let i = dotIdx + 1; i < s.length; i++) {
            if (s[i] !== '0') { firstNonZero = i; break; }
        }
        if (firstNonZero === -1) {
            formatted = '0';
        } else {
            const sigDigits = Math.min(firstNonZero - dotIdx + 3, decimals);
            formatted = num.toFixed(sigDigits);
            // Trim trailing zeros but keep at least one after dot
            formatted = formatted.replace(/(\.\d*?)0+$/, '$1').replace(/\.$/, '.0');
        }
    } else {
        formatted = '0';
    }

    return formatted + ' ' + symbol;
}

/**
 * Get display info for a payment asset.
 * Returns { decimals, symbol }.
 */
function getAssetDisplayInfo(paymentAsset: string): { decimals: number; symbol: string } {
    // Empty policy = ADA (lovelace, 6 decimals)
    if (!paymentAsset || paymentAsset === '' || paymentAsset === '.') {
        return { decimals: 6, symbol: 'ADA' };
    }
    // For native tokens: try to decode the asset name hex as UTF-8
    const parts = paymentAsset.split('.');
    const assetNameHex = parts[1] || '';
    const symbol = assetNameHex ? decodeHexString(assetNameHex) : paymentAsset.slice(0, 8) + '...';
    // Most Cardano native tokens have 0 decimals unless we know otherwise
    return { decimals: 0, symbol: symbol };
}

// ── Cost calculation ──────────────────────────────────────────────────

function updateCost(): void {
    const planId = Number((document.getElementById('plan-select') as HTMLSelectElement).value);
    const days = parseInt((document.getElementById('days-input') as HTMLInputElement).value, 10) || 0;
    const plan = plans.find(function (p) { return p.planId === planId; });
    const costEl = document.getElementById('total-cost')!;
    const detailEl = document.getElementById('plan-detail')!;

    if (plan && days > 0) {
        const total = plan.pricePerDay * BigInt(days);
        const info = getAssetDisplayInfo(plan.paymentAsset);
        costEl.textContent = formatAmount(total, info.decimals, info.symbol);
        detailEl.classList.add('hidden');
    } else {
        costEl.textContent = '-';
        detailEl.classList.add('hidden');
    }

    // Enable subscribe only when wallet connected + plan selected + days valid
    const btnSub = document.getElementById('btn-subscribe') as HTMLButtonElement;
    btnSub.disabled = !(api !== null && plan && days > 0);
}

document.getElementById('days-input')!.addEventListener('input', updateCost);
document.getElementById('plan-select')!.addEventListener('change', updateCost);

// ── UI helpers ────────────────────────────────────────────────────────

function escapeHtml(str: unknown): string {
    return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

function showStatus(elementId: string, message: string, type?: string): void {
    const el = document.getElementById(elementId);
    if (!el) return;
    el.innerHTML = '<div class="status ' + (type || 'info') + '">' + message + '</div>';
}

function updateStep(stepNum: number, state?: string): void {
    const el = document.getElementById('step' + stepNum + '-num');
    if (!el) return;
    el.classList.remove('done', 'error');
    if (state === 'done') { el.classList.add('done'); el.textContent = '\u2713'; }
    else if (state === 'error') { el.classList.add('error'); el.textContent = '!'; }
    else { el.textContent = String(stepNum); }
}

// ── CIP-30 wallet detection and connection ────────────────────────────

/** CIP-30 API handle */
let api: any = null;
/** hex bech32 address */
let usedAddress = '';

const KNOWN_WALLETS = ['eternl', 'nami', 'lace', 'typhon', 'flint', 'yoroi', 'gerowallet', 'nufi'];

function detectWallets(): void {
    const walletList = document.getElementById('wallet-list')!;
    const cardano = window.cardano;

    if (!cardano || typeof cardano !== 'object') {
        document.getElementById('no-wallets')!.classList.remove('hidden');
        return;
    }

    let found = 0;

    function makeBtn(key: string): void {
        const btn = document.createElement('button');
        btn.className = 'wallet-btn';
        const rawName = (cardano![key] && cardano![key].name) ? cardano![key].name : key;
        // Capitalize first letter
        btn.textContent = rawName.charAt(0).toUpperCase() + rawName.slice(1);
        // Add wallet icon if available
        if (cardano![key] && cardano![key].icon) {
            const img = document.createElement('img');
            img.src = cardano![key].icon;
            img.style.cssText = 'width:20px;height:20px;margin-right:8px;vertical-align:middle;border-radius:4px';
            btn.prepend(img);
        }
        btn.addEventListener('click', function () { connectWallet(key); });
        walletList.appendChild(btn);
        found++;
    }

    for (let i = 0; i < KNOWN_WALLETS.length; i++) {
        if (cardano[KNOWN_WALLETS[i]!]) makeBtn(KNOWN_WALLETS[i]!);
    }

    // Catch any other CIP-30 wallets not in the known list
    const keys = Object.keys(cardano);
    for (let k = 0; k < keys.length; k++) {
        const key = keys[k]!;
        if (!KNOWN_WALLETS.includes(key) && cardano[key] && typeof cardano[key].enable === 'function') {
            makeBtn(key);
        }
    }

    if (found === 0) {
        document.getElementById('no-wallets')!.classList.remove('hidden');
    }
}

// ── Bech32 encoding for address display ─────────────────────────────
//
// Cardano addresses exceed the default bech32 90-char limit (base addresses
// encode 57 bytes → ~108 chars including HRP). Pass 256 as the LIMIT argument.

/** Encode raw address bytes (hex) to bech32 using Cardano HRP derived from header byte. */
function hexAddressToBech32(hexAddr: string): string {
    try {
        const bytes = hexToBytes(hexAddr);
        // Header byte: top nibble = type, bottom nibble = network
        const networkId = bytes[0]! & 0x0f;
        const hrp = networkId === 1 ? 'addr' : 'addr_test';
        const words = bech32.toWords(bytes);
        return bech32.encode(hrp, words, 256);
    } catch (e) {
        return hexAddr; // fallback to raw hex
    }
}

async function connectWallet(name: string): Promise<void> {
    try {
        api = await window.cardano![name].enable();
        const addresses = await api.getUsedAddresses();
        if (!addresses || addresses.length === 0) {
            const unused = await api.getUnusedAddresses();
            usedAddress = (unused && unused[0]) ? unused[0] : '';
        } else {
            usedAddress = addresses[0];
        }

        if (!usedAddress) {
            throw new Error('No address returned from wallet');
        }

        // Convert hex address to bech32 for display
        const bech32Addr = hexAddressToBech32(usedAddress);
        const display = bech32Addr.length > 30
            ? bech32Addr.slice(0, 16) + '...' + bech32Addr.slice(-10)
            : bech32Addr;

        document.getElementById('wallet-not-connected')!.classList.add('hidden');
        document.getElementById('wallet-connected')!.classList.remove('hidden');
        document.getElementById('wallet-address')!.textContent = display;
        updateStep(1, 'done');

        // Enable days input and trigger cost recalculation
        (document.getElementById('days-input') as HTMLInputElement).disabled = false;
        updateCost();

        // Also kick off plan loading if it hasn't happened yet
        if (plans.length === 0) loadPlans();

        // Show View My Servers wallet mode and load NFTs
        document.getElementById('servers-not-connected')!.classList.add('hidden');
        loadUserNfts();

        // Show admin commands section
        document.getElementById('admin-not-connected')!.classList.add('hidden');
        document.getElementById('admin-connected')!.classList.remove('hidden');

    } catch (err: any) {
        console.error('connectWallet error:', err);
        showStatus('subscribe-status', 'Wallet connection failed: ' + escapeHtml(err.message || err), 'error');
        updateStep(1, 'error');
    }
}

// Plutus Data encoding lives in ./encoder.ts so it can also be exercised
// from a Node-side regression test (scripts/compare-signup-datum.ts) without
// pulling in DOM.


// ── Step 3: Subscribe ─────────────────────────────────────────────────

document.getElementById('btn-subscribe')!.addEventListener('click', async function () {
    const btn = document.getElementById('btn-subscribe') as HTMLButtonElement;
    btn.disabled = true;
    btn.textContent = 'Working...';

    try {
        // Gather parameters
        const planId = Number((document.getElementById('plan-select') as HTMLSelectElement).value);
        const days = parseInt((document.getElementById('days-input') as HTMLInputElement).value, 10);
        const plan = plans.find(function (p) { return p.planId === planId; });

        if (!plan) throw new Error('Please select a plan');
        if (!days || days < 1) throw new Error('Please enter a valid number of days');
        if (!api) throw new Error('Wallet not connected');
        if (!CONFIG.serverPublicKey) throw new Error('Server public key not configured');
        if (!CONFIG.validatorAddress) throw new Error('Validator address not configured');

        // ── Step A: sign publicSecret to derive user credentials ──────
        showStatus('subscribe-status', '<span class="spinner"></span>Signing credentials with wallet...', 'info');

        // CIP-30 signData takes address (hex) and payload (hex-encoded UTF-8 message)
        const msgHex = bytesToHex(new TextEncoder().encode(CONFIG.publicSecret));
        const signResult = await api.signData(usedAddress, msgHex);
        // signResult = { signature: hex (COSE_Sign1), key: hex (COSE_Key) }

        // ── Step B: ECIES encrypt the raw Ed25519 signature with server pubkey
        showStatus('subscribe-status', '<span class="spinner"></span>Encrypting credentials...', 'info');

        // Extract the raw 64-byte Ed25519 signature from the COSE_Sign1 structure.
        // The server uses this as key material for SHAKE256 → AES-GCM encryption
        // of connection details.  The client uses the same signature to decrypt.
        const rawSigHex = extractCoseSignature(signResult.signature);
        if (!rawSigHex) throw new Error('Failed to extract Ed25519 signature from COSE_Sign1');
        console.log('rawSigHex:', rawSigHex.length, 'chars (' + (rawSigHex.length / 2) + ' bytes)');

        // ECIES-encrypt the raw signature hex so only the server can recover it.
        const userEncryptedHex = await eciesEncrypt(CONFIG.serverPublicKey, rawSigHex);
        console.log('userEncryptedHex length:', userEncryptedHex.length, 'bytes:', userEncryptedHex.length / 2);

        updateStep(3, 'done');
        showStatus('subscribe-status', '<span class="spinner"></span>Building subscription transaction...', 'info');

        // ── Step C: Build and submit subscription transaction ─────────

        if (!CONFIG.beaconScriptCbor) throw new Error('Beacon minting policy not configured');
        if (!CONFIG.subscriptionValidatorHash) throw new Error('Subscription validator hash not configured');

        // C.1  Extract subscriber payment key hash from the CIP-30 address.
        //      CIP-30 getUsedAddresses returns hex-encoded raw address bytes.
        //      Shelley base address: header(1) + payment_key_hash(28) + stake_credential(28)
        const addrBytes = hexToBytes(usedAddress);
        const subscriberKeyHash = bytesToHex(addrBytes.slice(1, 29)); // 28-byte payment key hash

        // C.2  Get current block height for beacon uniqueness salt
        await ensureEcies(); // ensure _sha256 is loaded
        const tip = await provider.fetchTip();
        const creationHeight = tip.block;

        // C.2b Compute beacon token name: sha256(plan_id_4BE ++ subscriber_key_hash ++ creation_height_4BE)
        const planIdBytes = new Uint8Array(4);
        new DataView(planIdBytes.buffer).setInt32(0, planId, false); // big-endian
        const keyHashBytes = hexToBytes(subscriberKeyHash);
        const heightBytes = new Uint8Array(4);
        new DataView(heightBytes.buffer).setUint32(0, creationHeight, false); // big-endian
        const beaconPreimage = new Uint8Array(4 + keyHashBytes.length + 4);
        beaconPreimage.set(planIdBytes, 0);
        beaconPreimage.set(keyHashBytes, 4);
        beaconPreimage.set(heightBytes, 4 + keyHashBytes.length);
        const beaconName = bytesToHex(_sha256(beaconPreimage)); // 32 bytes = 64 hex chars

        console.log('beaconName:', beaconName);
        console.log('subscriberKeyHash:', subscriberKeyHash);

        // C.3  Parse payment asset from plan
        let payPolicyId = '';
        let payAssetName = '';
        if (plan.paymentAsset && plan.paymentAsset.includes('.')) {
            const parts = plan.paymentAsset.split('.');
            payPolicyId = parts[0]!;
            payAssetName = parts[1] || '';
        } else if (plan.paymentAsset && plan.paymentAsset.length === 56) {
            payPolicyId = plan.paymentAsset;
        }
        const isAdaPayment = !payPolicyId;

        // C.4  Compute datum fields
        const totalPayment = plan.pricePerDay * BigInt(days);
        const nowMs = BigInt(Date.now());
        const expiryMs = nowMs + BigInt(days) * 86400000n;
        const intervalMs = 86400000n;  // 1 day in milliseconds
        const ratePerInterval = plan.pricePerDay;

        // C.5  Build SubscriptionDatum as Plutus Data CBOR (inline)
        //      Constr(0, [plan_id, expiry, subscriber_key_hash, amount_remaining,
        //        rate_per_interval, interval_ms, last_collected,
        //        Constr(0, [policy_id, asset_name]), beacon_policy_id, user_encrypted])
        const datumCbor = encodePlutusSubscriptionDatum({
            planId: planId,
            expiry: expiryMs,
            subscriberKeyHash: subscriberKeyHash,
            amountRemaining: totalPayment,
            ratePerInterval: ratePerInterval,
            intervalMs: intervalMs,
            lastCollected: nowMs,
            payPolicyId: payPolicyId,
            payAssetName: payAssetName,
            beaconPolicyId: CONFIG.beaconPolicyId,
            userEncrypted: userEncryptedHex,
            creationHeight: creationHeight,
        });

        console.log('datumCbor length:', datumCbor.length, 'bytes:', datumCbor.length / 2);
        // Verify the datum CBOR starts with d8799f (Constr 0, indef array)
        console.log('datumCbor starts with d8799f:', datumCbor.startsWith('d8799f'));

        // C.6  Build CIP-89 validator address for this subscriber.
        //      CIP-89 = script payment credential + subscriber staking credential.
        //      Payment: script hash = subscriptionValidatorHash (28 bytes)
        //      Staking: from subscriber's original address (bytes 29..57)
        const subscriberStakeCred = addrBytes.length >= 57
            ? addrBytes.slice(29, 57) : null;
        const validatorHash = hexToBytes(CONFIG.subscriptionValidatorHash);
        // CIP-89 address: script payment + KEY staking (subscriber's key)
        // Address type 1 = 0b0001 → header = (1 << 4) | network_id
        // Testnet: 0x10, Mainnet: 0x11
        const networkByte = CONFIG.network === 'mainnet' ? 0x11 : 0x10;
        let scriptAddr: Uint8Array;
        if (subscriberStakeCred) {
            scriptAddr = new Uint8Array(1 + 28 + 28);
            scriptAddr[0] = networkByte;
            scriptAddr.set(validatorHash, 1);
            scriptAddr.set(subscriberStakeCred, 29);
        } else {
            // Enterprise script address (no staking): header = 0x70 (testnet) or 0x71 (mainnet)
            const entByte = CONFIG.network === 'mainnet' ? 0x71 : 0x70;
            scriptAddr = new Uint8Array(1 + 28);
            scriptAddr[0] = entByte;
            scriptAddr.set(validatorHash, 1);
        }
        const scriptAddrHex = bytesToHex(scriptAddr);

        console.log('scriptAddrHex:', scriptAddrHex);

        // C.7  Parse CIP-30 wallet UTXOs / collateral and build the tx via cmttk.
        //      Protocol params, fee, min-UTXO, and script_data_hash are all
        //      computed by cmttk from live chain state — no hardcoded values.
        showStatus('subscribe-status', '<span class="spinner"></span>Fetching wallet UTXOs...', 'info');

        const utxosRaw = await api.getUtxos();
        if (!utxosRaw || utxosRaw.length === 0) {
            throw new Error('No UTXOs in wallet — fund your wallet first');
        }
        const walletUtxos = parseCip30Utxos(utxosRaw);

        const collateralRaw = await api.getCollateral();
        if (!collateralRaw || collateralRaw.length === 0) {
            throw new Error('No collateral set in wallet. Please configure collateral in your wallet settings (typically 5 ADA).');
        }
        const collateralUtxos = parseCip30Utxos(collateralRaw);

        // C.8  Compose script output assets. For ADA payment, lock totalPayment
        //      as lovelace — cmttk bumps to min-UTXO if needed but this already
        //      covers it. For token payment, the token is carried alongside and
        //      cmttk computes lovelace from protocol params.
        const beaconUnit = CONFIG.beaconPolicyId + beaconName;
        const scriptAssets: Assets = isAdaPayment
            ? { lovelace: totalPayment + 5_000_000n, [beaconUnit]: 1n }
            : { lovelace: 0n, [beaconUnit]: 1n, [payPolicyId + payAssetName]: totalPayment };

        const outputs: TxOutput[] = [{
            address: hexAddressToBech32(scriptAddrHex),
            assets: scriptAssets,
            datumCbor: datumCbor,
        }];

        if (CONFIG.deployerAddress) {
            outputs.push({
                address: CONFIG.deployerAddress,      // already bech32 in CONFIG
                assets: { lovelace: 2_500_000n },
            });
        }

        // C.9  Mint one beacon token. The minting policy's CreateSubscription
        //      redeemer is Constr(0, []) — empty fields, so indef vs definite
        //      array encoding is identical (d87980).
        const mints: MintEntry[] = [{
            policyId: CONFIG.beaconPolicyId,
            assets: { [beaconName]: 1n },
            redeemerCbor: bytesToHex(plutusConstr(0, [])),
            scriptCbor: CONFIG.beaconScriptCbor,
        }];

        // C.10 Build unsigned tx via cmttk (provider is module-scope).
        showStatus('subscribe-status', '<span class="spinner"></span>Building transaction...', 'info');

        const unsigned = await buildUnsignedScriptTx({
            provider,
            walletAddress: hexAddressToBech32(usedAddress),
            walletUtxos,
            collateralUtxos,
            scriptInputs: [],
            outputs,
            mints,
            validFrom: Date.now() - 60_000,       // 1 min grace
            validTo: Date.now() + 15 * 60_000,    // 15 min window
            network: CONFIG.network as CardanoNetwork,
            requiredSigners: [subscriberKeyHash],
        });

        console.log('unsigned.fee:', unsigned.fee.toString(), 'lovelace');
        console.log('unsigned.txBody length:', unsigned.txBodyCbor.length, 'bytes');

        // C.11 Sign via CIP-30 wallet (partial = true → returns witness set).
        showStatus('subscribe-status', '<span class="spinner"></span>Awaiting wallet signature...', 'info');
        const walletWitnessHex = await api.signTx(bytesToHex(unsigned.txBodyCbor), true);

        // C.12 Merge wallet witnesses into our partial witness set and submit.
        const signedTxHex = mergeCip30Witness(unsigned, walletWitnessHex);

        showStatus('subscribe-status', '<span class="spinner"></span>Submitting transaction...', 'info');
        const txHash = await provider.submitTx(signedTxHex);

        console.log('Transaction submitted:', txHash);

        // Show success
        const explorerBase = CONFIG.network === 'mainnet'
            ? 'https://cardanoscan.io/transaction/'
            : 'https://preprod.cardanoscan.io/transaction/';
        document.getElementById('result-card')!.classList.remove('hidden');
        document.getElementById('result-content')!.innerHTML =
            'Transaction submitted successfully!<br>' +
            '<a class="tx-link" href="' + explorerBase + txHash + '" target="_blank" rel="noopener">' +
            txHash + '</a>';

        showStatus('subscribe-status', 'Subscription created! Your server will be provisioned shortly.', 'success');

    } catch (err: any) {
        console.error('subscribe error:', err);
        showStatus('subscribe-status', escapeHtml(err.message || 'Subscription failed'), 'error');
        updateStep(3, 'error');
        btn.disabled = false;
        btn.textContent = 'Subscribe';
    }
});

// ── Tab switching ─────────────────────────────────────────────────────

window.switchTab = function (tab: string): void {
    document.getElementById('tab-wallet')!.classList.toggle('active', tab === 'wallet');
    document.getElementById('tab-offline')!.classList.toggle('active', tab === 'offline');
    document.getElementById('mode-wallet')!.classList.toggle('hidden', tab !== 'wallet');
    document.getElementById('mode-offline')!.classList.toggle('hidden', tab !== 'offline');
};

// ── NFT loading (wallet mode) ───────────────────────────────────────

async function loadUserNfts(): Promise<void> {
    if (!CONFIG.nftPolicyId || !usedAddress || !api) return;

    document.getElementById('servers-not-connected')!.classList.add('hidden');
    document.getElementById('servers-loading')!.classList.remove('hidden');
    document.getElementById('server-list')!.classList.add('hidden');
    document.getElementById('servers-empty')!.classList.add('hidden');
    document.getElementById('servers-decrypt')!.classList.add('hidden');
    document.getElementById('connection-result')!.classList.add('hidden');

    try {
        // Query wallet UTXOs for CIP-68 user tokens under the NFT policy.
        // Also check the enterprise address (payment key only, no staking) because
        // the handler mints user tokens to enterprise addresses derived from the
        // subscriber's payment key hash.
        const walletBech32 = hexAddressToBech32(usedAddress);
        const addrBytes = hexToBytes(usedAddress);
        const paymentKeyHash = bytesToHex(addrBytes.slice(1, 29));
        const networkByte = CONFIG.network === 'mainnet' ? '61' : '60';
        const enterpriseHex = networkByte + paymentKeyHash;
        const enterpriseBech32 = hexAddressToBech32(enterpriseHex);

        const addresses = [walletBech32];
        if (enterpriseBech32 !== walletBech32) addresses.push(enterpriseBech32);

        // cmttk fetchUtxos takes a single address; query in parallel and flatten.
        const perAddr = await Promise.all(addresses.map(a => provider.fetchUtxos(a)));
        const rawUtxos = perAddr.flat() as any[];

        userNfts = [];
        for (let u = 0; u < rawUtxos.length; u++) {
            const assetList = rawUtxos[u].asset_list;
            if (!assetList) continue;
            for (let a = 0; a < assetList.length; a++) {
                const asset = assetList[a];
                if (asset.policy_id !== CONFIG.nftPolicyId) continue;
                if (!asset.asset_name || !asset.asset_name.startsWith(CIP68_USER_PREFIX)) continue;
                const tid = tokenIdFromAssetName(asset.asset_name);
                if (tid === null) continue;
                userNfts.push({
                    tokenId: tid,
                    name: 'Server #' + tid,
                    userAssetName: asset.asset_name,
                });
            }
        }

        document.getElementById('servers-loading')!.classList.add('hidden');

        if (userNfts.length > 0) {
            document.getElementById('server-list')!.classList.remove('hidden');
            renderNftList();
        } else {
            document.getElementById('servers-empty')!.classList.remove('hidden');
        }
    } catch (err: any) {
        console.error('Error loading NFTs:', err);
        document.getElementById('servers-loading')!.classList.add('hidden');
        document.getElementById('servers-empty')!.classList.remove('hidden');
        document.getElementById('servers-empty')!.innerHTML =
            '<p class="step-desc">Error loading NFTs: ' + (err.message || err) + '</p>';
    }
}

function renderNftList(): void {
    const container = document.getElementById('server-list')!;
    container.innerHTML = '';
    userNfts.forEach(function (nft, index) {
        const card = document.createElement('div');
        card.className = 'server-card' + (index === 0 ? ' selected' : '');
        card.innerHTML =
            '<div class="server-card-header">' +
                '<span class="server-card-title">' + nft.name + '</span>' +
                '<span class="server-card-id">Token #' + nft.tokenId + '</span>' +
            '</div>';
        card.addEventListener('click', function () { selectNft(index); });
        container.appendChild(card);
    });
    if (userNfts.length > 0) selectNft(0);
}

function selectNft(index: number): void {
    selectedNft = userNfts[index]!;
    document.querySelectorAll('.server-card').forEach(function (card, i) {
        card.classList.toggle('selected', i === index);
    });
    document.getElementById('servers-decrypt')!.classList.remove('hidden');
    document.getElementById('connection-result')!.classList.add('hidden');
    document.getElementById('decrypt-wallet-status')!.innerHTML = '';
}

/** Fetch the userEncrypted field from a CIP-68 reference token's inline datum. */
async function fetchUserEncrypted(userAssetNameHex: string): Promise<string | null> {
    const refName = refAssetName(userAssetNameHex);

    console.log('[fetchUserEncrypted] policy:', CONFIG.nftPolicyId, 'refName:', refName);

    // Find addresses holding the reference token
    const holders = await provider.fetchAssetAddresses(CONFIG.nftPolicyId + refName);
    console.log('[fetchUserEncrypted] holders:', holders);
    if (!holders || holders.length === 0) { console.log('[fetchUserEncrypted] no holders found'); return null; }

    const addr = holders[0]!.address;
    const utxos = await provider.fetchUtxos(addr) as any[];
    console.log('[fetchUserEncrypted] utxos at', addr, ':', utxos ? utxos.length : 0);
    if (!utxos || utxos.length === 0) { console.log('[fetchUserEncrypted] no utxos'); return null; }

    // Find the UTxO carrying this reference token
    for (let i = 0; i < utxos.length; i++) {
        const assets = utxos[i].asset_list || [];
        const hasRef = assets.some(function (a: any) {
            return a.policy_id === CONFIG.nftPolicyId && a.asset_name === refName;
        });
        if (!hasRef) continue;

        console.log('[fetchUserEncrypted] found ref UTxO, inline_datum:', JSON.stringify(utxos[i].inline_datum).slice(0, 200));

        // Extract inline datum
        const rawDatum = utxos[i].inline_datum;
        if (!rawDatum) { console.log('[fetchUserEncrypted] no inline_datum'); continue; }
        const datumValue = rawDatum.value || rawDatum;

        console.log('[fetchUserEncrypted] datumValue keys:', Object.keys(datumValue), 'constructor:', datumValue.constructor);

        // NftReferenceDatum: Constr(0, [userEncrypted: ByteArray])
        if (datumValue.constructor === 0 && datumValue.fields && datumValue.fields.length >= 1) {
            const field = datumValue.fields[0];
            console.log('[fetchUserEncrypted] field[0]:', field ? Object.keys(field) : 'null', 'bytes length:', field && field.bytes ? field.bytes.length : 0);
            if (field && typeof field.bytes === 'string' && field.bytes.length > 0) return field.bytes;
        }
        // Bare bytes fallback
        if (typeof datumValue.bytes === 'string' && datumValue.bytes.length > 0) return datumValue.bytes;
    }
    console.log('[fetchUserEncrypted] no matching datum found');
    return null;
}

// ── Decrypt (wallet mode) ───────────────────────────────────────────

const btnDecryptWallet = document.getElementById('btn-decrypt-wallet');
if (btnDecryptWallet) btnDecryptWallet.addEventListener('click', async function () {
    if (!selectedNft || !api) return;

    const btn = document.getElementById('btn-decrypt-wallet') as HTMLButtonElement;
    const statusEl = document.getElementById('decrypt-wallet-status')!;

    try {
        btn.disabled = true;

        showStatus('decrypt-wallet-status', '<span class="spinner"></span>Fetching NFT data...', 'info');
        const userEncHex = await fetchUserEncrypted(selectedNft.userAssetName);
        if (!userEncHex) throw new Error('No encrypted data found in NFT #' + selectedNft.tokenId);

        showStatus('decrypt-wallet-status', '<span class="spinner"></span>Sign the message in your wallet...', 'info');
        const msgHex = bytesToHex(new TextEncoder().encode(CONFIG.publicSecret));
        const signResult = await api.signData(usedAddress, msgHex);

        const rawSig = extractCoseSignature(signResult.signature);
        if (!rawSig) throw new Error('Failed to extract signature from COSE_Sign1');

        showStatus('decrypt-wallet-status', '<span class="spinner"></span>Decrypting...', 'info');
        await ensureShake256();
        const keyBytes = deriveSymmetricKey(hexToBytes(rawSig));
        const decrypted = await decryptAesGcm(keyBytes, userEncHex);

        document.getElementById('connection-info')!.textContent = decrypted;
        document.getElementById('connection-result')!.classList.remove('hidden');
        statusEl.innerHTML = '';
    } catch (err: any) {
        console.error('Decrypt error:', err);
        showStatus('decrypt-wallet-status', escapeHtml(err.message || 'Decryption failed'), 'error');
    } finally {
        btn.disabled = false;
    }
});

// ── NFT lookup (offline mode) ───────────────────────────────────────

const btnLookupNft = document.getElementById('btn-lookup-nft');
if (btnLookupNft) btnLookupNft.addEventListener('click', async function () {
    const btn = document.getElementById('btn-lookup-nft') as HTMLButtonElement;

    if (!CONFIG.nftPolicyId) {
        showStatus('offline-lookup-status', 'NFT policy not configured', 'error');
        return;
    }

    const tokenId = (document.getElementById('offline-token-id') as HTMLInputElement).value;
    if (!tokenId) {
        showStatus('offline-lookup-status', 'Please enter a token ID', 'error');
        return;
    }

    try {
        btn.disabled = true;
        showStatus('offline-lookup-status', '<span class="spinner"></span>Querying NFT on-chain...', 'info');

        const idPadded = parseInt(tokenId, 10).toString(16).padStart(8, '0');
        const userAssetHex = CIP68_USER_PREFIX + idPadded;

        const userEncHex = await fetchUserEncrypted(userAssetHex);
        if (!userEncHex) {
            showStatus('offline-lookup-status', 'No encrypted data found for token #' + tokenId, 'error');
            return;
        }

        window._offlineNftData = { tokenId: tokenId, userEncrypted: userEncHex };

        showStatus('offline-lookup-status',
            'Found encrypted data for token #' + tokenId + ' (' + userEncHex.length + ' hex chars).', 'success');

        document.getElementById('offline-public-secret')!.textContent = CONFIG.publicSecret;
        document.getElementById('offline-encrypted-data')!.textContent = userEncHex;
        document.getElementById('offline-cli-instructions')!.innerHTML =
            'Sign the publicSecret message with your Ed25519 payment key and paste the 64-byte signature (128 hex chars) below.<br><br>' +
            'Using cardano-cli:<br>' +
            '<code>cardano-cli transaction sign-data \\\n' +
            '  --signing-key-file payment.skey \\\n' +
            '  --data "' + CONFIG.publicSecret + '"</code>';
        document.getElementById('offline-nft-info')!.classList.remove('hidden');
    } catch (err: any) {
        console.error('NFT lookup error:', err);
        showStatus('offline-lookup-status', 'Lookup failed: ' + escapeHtml(err.message || err), 'error');
    } finally {
        btn.disabled = false;
    }
});

// ── Decrypt (offline mode) ──────────────────────────────────────────

const btnDecryptOffline = document.getElementById('btn-decrypt-offline');
if (btnDecryptOffline) btnDecryptOffline.addEventListener('click', async function () {
    const statusEl = document.getElementById('decrypt-offline-status')!;
    const sigInput = (document.getElementById('offline-signature') as HTMLInputElement).value.trim().replace(/^0x/, '');

    if (!sigInput) {
        showStatus('decrypt-offline-status', 'Please paste your Ed25519 signature (hex)', 'error');
        return;
    }
    if (!window._offlineNftData) {
        showStatus('decrypt-offline-status', 'Please lookup an NFT first', 'error');
        return;
    }

    try {
        showStatus('decrypt-offline-status', '<span class="spinner"></span>Decrypting...', 'info');
        await ensureShake256();
        const sigBytes = hexToBytes(sigInput);
        const keyBytes = deriveSymmetricKey(sigBytes);
        const decrypted = await decryptAesGcm(keyBytes, window._offlineNftData.userEncrypted);

        document.getElementById('offline-connection-info')!.textContent = decrypted;
        document.getElementById('offline-connection-result')!.classList.remove('hidden');
        statusEl.innerHTML = '';
    } catch (err) {
        console.error('Decrypt error:', err);
        showStatus('decrypt-offline-status', 'Decryption failed. Make sure you signed the correct message with the correct key.', 'error');
    }
});

// ── Admin Commands ───────────────────────────────────────────────────
//
// Protocol: transaction metadata label 7368
// Payload: UTF-8("{nonce} {command}") + HMAC-SHA256(sharedKey, message)[:16]
// SharedKey: SHAKE256(Ed25519 signature of publicSecret)
//
// The command is submitted as a Cardano transaction with metadata.
// The server scans admin wallet transactions for label 7368.

let _adminNonce = (function () {
    const chars = 'abcdefghijklmnopqrstuvwxyz0123456789';
    let nonce = '';
    const rand = crypto.getRandomValues(new Uint8Array(3));
    for (let i = 0; i < 3; i++) nonce += chars[rand[i]! % chars.length];
    return nonce;
})();

const btnSendCommand = document.getElementById('btn-send-command');
if (btnSendCommand) btnSendCommand.addEventListener('click', async function () {
    const btn = document.getElementById('btn-send-command') as HTMLButtonElement;
    const commandInput = (document.getElementById('command-input') as HTMLInputElement).value.trim();

    if (!commandInput) {
        showStatus('command-status', 'Please enter a command', 'error');
        return;
    }
    if (!api) {
        showStatus('command-status', 'Please connect your wallet first', 'error');
        return;
    }

    try {
        btn.disabled = true;

        const message = _adminNonce + ' ' + commandInput;

        // Sign publicSecret to derive shared key
        showStatus('command-status', '<span class="spinner"></span>Sign the message in your wallet...', 'info');
        const msgHex = bytesToHex(new TextEncoder().encode(CONFIG.publicSecret));
        const signResult = await api.signData(usedAddress, msgHex);

        const rawSig = extractCoseSignature(signResult.signature);
        if (!rawSig) throw new Error('Failed to extract signature from COSE_Sign1');

        await ensureShake256();
        const sharedKey = deriveSymmetricKey(hexToBytes(rawSig));

        // Compute HMAC-SHA256(sharedKey, message)[:16]
        showStatus('command-status', '<span class="spinner"></span>Computing HMAC...', 'info');
        const cryptoKey = await crypto.subtle.importKey(
            'raw', sharedKey as BufferSource, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
        const messageBytes = new TextEncoder().encode(message);
        const hmacFull = await crypto.subtle.sign('HMAC', cryptoKey, messageBytes);
        const hmac16 = new Uint8Array(hmacFull).slice(0, 16);

        // Build payload: message_bytes + hmac_suffix(16)
        const payload = new Uint8Array(messageBytes.length + 16);
        payload.set(messageBytes, 0);
        payload.set(hmac16, messageBytes.length);

        const payloadHex = bytesToHex(payload);

        console.log('Admin command payload:', message, '(' + payload.length + ' bytes)');

        showStatus('command-status',
            'Payload ready (' + payload.length + ' bytes).<br>' +
            'Transaction metadata submission (label 7368) is not yet implemented in the browser.<br>' +
            '<div class="code-block" style="margin-top:0.5rem">' + payloadHex + '</div>', 'info');

        // Rotate nonce for next command
        _adminNonce = (function () {
            const chars = 'abcdefghijklmnopqrstuvwxyz0123456789';
            let nonce = '';
            const rand = crypto.getRandomValues(new Uint8Array(3));
            for (let i = 0; i < 3; i++) nonce += chars[rand[i]! % chars.length];
            return nonce;
        })();

    } catch (err: any) {
        console.error('Command error:', err);
        showStatus('command-status', escapeHtml(err.message || 'Failed to send command'), 'error');
    } finally {
        btn.disabled = false;
    }
});

// ── Initialise ────────────────────────────────────────────────────────

// Wallet extensions inject window.cardano asynchronously after page load.
// Retry detection a few times with increasing delays.
function detectWithRetry(attempt: number): void {
    if (attempt > 5) return; // give up after ~3 seconds
    if (window.cardano && typeof window.cardano === 'object' && Object.keys(window.cardano).length > 0) {
        detectWallets();
    } else {
        setTimeout(function () { detectWithRetry(attempt + 1); }, 300 * attempt);
    }
}

// Try immediately, then retry
if (document.readyState === 'complete') {
    detectWithRetry(0);
} else {
    window.addEventListener('load', function () { detectWithRetry(0); });
}

// Start fetching plans in the background (may show before wallet connects)
loadPlans();

console.log('BlockHost signup engine (Cardano) loaded');
console.log('  network:', CONFIG.network);
console.log('  validatorAddress:', CONFIG.validatorAddress || 'NOT SET');
console.log('  beaconPolicyId:', CONFIG.beaconPolicyId || 'NOT SET');
console.log('  subscriptionValidatorHash:', CONFIG.subscriptionValidatorHash || 'NOT SET');
console.log('  beaconScriptCbor:', CONFIG.beaconScriptCbor ? CONFIG.beaconScriptCbor.slice(0, 16) + '...' : 'NOT SET');
console.log('  serverPublicKey:', CONFIG.serverPublicKey ? CONFIG.serverPublicKey.slice(0, 16) + '...' : 'NOT SET');
