/**
 * Signup page engine for Cardano (BlockHost).
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
 * Required DOM IDs:
 *   step1-num, step2-num, step3-num
 *   wallet-list, no-wallets, wallet-not-connected, wallet-connected, wallet-address
 *   plan-select, plan-detail, days-input, total-cost
 *   btn-subscribe, subscribe-status
 *   result-card, result-content
 *
 * CSS classes toggled: hidden, done, error
 */

(function () {
    'use strict';

    // ── Koios REST base URL ─────────────────────────────────────────────

    function koiosBase(_network) {
        // Use relative path — requests go through our local proxy which
        // forwards to Koios, avoiding CORS issues in the browser.
        // The proxy server maps /api/v1/* → https://{network}.koios.rest/api/v1/*
        return '/api/v1';
    }

    /**
     * Koios fetch helper (POST with JSON body).
     * No API key needed — Koios is free and public.
     * Includes basic retry logic for 429 (rate limit).
     *
     * @param {string} endpoint - API endpoint starting with /
     * @param {object|null} body - JSON body for POST (null for GET requests)
     * @param {object} [opts] - Options: { method, contentType, rawBody }
     * @returns {Promise<unknown>}
     */
    async function koiosFetch(endpoint, body, opts) {
        var base = koiosBase(CONFIG.network);
        opts = opts || {};
        var method = opts.method || (body != null ? 'POST' : 'GET');
        var headers = {};
        var fetchBody;

        if (opts.contentType) {
            headers['Content-Type'] = opts.contentType;
            fetchBody = opts.rawBody;
        } else if (body != null) {
            headers['Content-Type'] = 'application/json';
            fetchBody = JSON.stringify(body);
        }

        async function doFetch() {
            return fetch(base + endpoint, {
                method: method,
                headers: headers,
                body: fetchBody,
            });
        }

        var res = await doFetch();

        // Retry once on 429 (rate limit) after a short delay
        if (res.status === 429) {
            await new Promise(function (r) { setTimeout(r, 1500); });
            res = await doFetch();
        }

        if (!res.ok) {
            if (res.status === 404) return null;
            var errBody = await res.text().catch(function () { return ''; });
            throw new Error('Koios ' + res.status + ': ' + errBody);
        }

        // Koios submittx returns plain text (tx hash)
        if (opts.contentType === 'application/cbor') {
            return res.text();
        }
        return res.json();
    }

    // ── ECIES encryption (secp256k1 ECDH + HKDF-SHA256 + AES-GCM) ───────
    // Wire format: ephemeralPub(65) || IV(12) || ciphertext+tag
    // Matches the server-side eciesDecrypt() in src/crypto.ts.
    //
    // Uses the noble-curves and noble-hashes ES module builds loaded from esm.run.
    // These are the same library versions the OPNet signing page uses, so they
    // are already known-good in browser environments.

    var _eciesReady = false;
    var _secp256k1 = null;
    var _hkdf = null;
    var _sha256 = null;
    var _randomBytes = null;

    /**
     * Lazy-load noble crypto libraries from CDN (esm.run → jsDelivr).
     * Called once before the first ECIES encrypt.
     */
    async function ensureEcies() {
        if (_eciesReady) return;
        var mod;
        mod = await import('https://esm.run/@noble/curves@1.4.0/secp256k1');
        _secp256k1 = mod.secp256k1;
        mod = await import('https://esm.run/@noble/hashes@1.4.0/hkdf');
        _hkdf = mod.hkdf;
        mod = await import('https://esm.run/@noble/hashes@1.4.0/sha256');
        _sha256 = mod.sha256;
        mod = await import('https://esm.run/@noble/hashes@1.4.0/utils');
        _randomBytes = mod.randomBytes;
        _eciesReady = true;
    }

    function hexToBytes(hex) {
        hex = hex.replace(/^0x/, '');
        var out = new Uint8Array(hex.length / 2);
        for (var i = 0; i < out.length; i++) {
            out[i] = parseInt(hex.substr(i * 2, 2), 16);
        }
        return out;
    }

    function bytesToHex(bytes) {
        return Array.from(bytes).map(function (b) {
            return b.toString(16).padStart(2, '0');
        }).join('');
    }

    /**
     * ECIES encrypt plaintext with the server's secp256k1 public key.
     *
     * @param {string} serverPubKeyHex - 33 or 65 byte compressed/uncompressed pubkey hex
     * @param {string} plaintext
     * @returns {Promise<string>} hex-encoded ciphertext
     */
    async function eciesEncrypt(serverPubKeyHex, plaintext) {
        await ensureEcies();
        var serverPubBytes = hexToBytes(serverPubKeyHex);
        var ephPriv = _randomBytes(32);
        var ephPub = _secp256k1.getPublicKey(ephPriv, false); // uncompressed, 65 bytes
        var shared = _secp256k1.getSharedSecret(ephPriv, serverPubBytes, false);
        var sharedX = shared.slice(1, 33);
        var encKey = _hkdf(_sha256, sharedX, new Uint8Array(0), new Uint8Array(0), 32);
        var iv = _randomBytes(12);
        var cryptoKey = await crypto.subtle.importKey('raw', encKey, { name: 'AES-GCM' }, false, ['encrypt']);
        var ptBytes = new TextEncoder().encode(plaintext);
        var ctWithTag = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: iv }, cryptoKey, ptBytes);
        var result = new Uint8Array(ephPub.length + iv.length + ctWithTag.byteLength);
        result.set(ephPub, 0);
        result.set(iv, ephPub.length);
        result.set(new Uint8Array(ctWithTag), ephPub.length + iv.length);
        return bytesToHex(result);
    }

    // ── Plan data (fetched from Koios) ─────────────────────────────────────

    /**
     * Plan record.
     * @typedef {{ planId: number, name: string, pricePerDay: bigint, paymentAsset: string }} Plan
     */

    /** @type {Plan[]} */
    var plans = [];

    /**
     * Parse a plan datum from a Koios UTXO's inline_datum JSON.
     *
     * The on-chain plan datum structure (set by blockhost-bw plan create) is:
     *   Constr(0, [plan_id, name, price_per_day, payment_assets, active])
     *
     * Koios (with _extended: true) returns inline_datum as:
     *   { "value": { "constructor": 0, "fields": [...] }, "bytes": "..." }
     *
     * The inner value uses the generic Plutus data representation:
     *   { "constructor": 0, "fields": [ int, bytes, int, list, int ] }
     *
     * This is a best-effort parser — the exact shape depends on how the
     * datum is serialised by the Aiken validator. Adjust field indices if
     * the validator changes its datum layout.
     *
     * @param {object} utxo - UTXO object from Koios /address_utxos
     * @returns {Plan|null}
     */
    function parsePlanDatum(utxo) {
        try {
            // Koios wraps inline datum in { value: {...}, bytes: "..." }
            var rawDatum = utxo.inline_datum;
            var datum = rawDatum && rawDatum.value ? rawDatum.value : rawDatum;
            if (!datum || !datum.fields || !Array.isArray(datum.fields)) return null;
            var fields = datum.fields;
            // fields[0] = planId (int)
            // fields[1] = name (bytes / string)
            // fields[2] = pricePerDay (int)
            // fields[3] = paymentAssets (list)
            // fields[4] = active (int: 1 = true)
            var planId = Number(fields[0] && fields[0].int != null ? fields[0].int : fields[0]);
            var nameRaw = fields[1];
            var name = '';
            if (nameRaw) {
                if (typeof nameRaw === 'string') name = nameRaw;
                else if (nameRaw.bytes) name = decodeHexString(nameRaw.bytes);
                else if (nameRaw.string) name = nameRaw.string;
            }
            var pricePerDay = BigInt(
                fields[2] && fields[2].int != null ? fields[2].int : (fields[2] || 0)
            );
            // active: Constr(1,[]) = True, Constr(0,[]) = False in Aiken
            var activeField = fields[4];
            var active = false;
            if (activeField != null) {
                if (typeof activeField === 'number') active = activeField !== 0;
                else if (activeField.constructor != null) active = activeField.constructor === 1;
                else active = Boolean(activeField);
            }
            if (!active) return null;
            // paymentAsset: take first from list, format as "policyId.assetName"
            var paymentAsset = '';
            var assetsList = fields[3];
            if (assetsList && Array.isArray(assetsList.list) && assetsList.list.length > 0) {
                var first = assetsList.list[0];
                if (first && first.fields && first.fields.length >= 2) {
                    var pid = first.fields[0] && first.fields[0].bytes ? first.fields[0].bytes : '';
                    var aname = first.fields[1] && first.fields[1].bytes ? first.fields[1].bytes : '';
                    paymentAsset = pid + (aname ? '.' + aname : '');
                }
            }
            return { planId: planId, name: name || ('Plan ' + planId), pricePerDay: pricePerDay, paymentAsset: paymentAsset };
        } catch (e) {
            console.warn('parsePlanDatum error:', e);
            return null;
        }
    }

    function decodeHexString(hex) {
        try {
            var bytes = hexToBytes(hex);
            return new TextDecoder().decode(bytes);
        } catch (_) {
            return hex;
        }
    }

    /**
     * Fetch active plans from the validator address via Koios.
     * Plans are stored as inline-datum UTXOs at CONFIG.validatorAddress.
     */
    async function loadPlans() {
        var sel = document.getElementById('plan-select');
        if (!CONFIG.validatorAddress) {
            sel.innerHTML = '<option value="">Validator address not configured</option>';
            return;
        }

        try {
            // Query all UTXOs at the validator address via Koios POST /address_utxos
            // with _extended: true to get inline datum data.
            var utxos = await koiosFetch('/address_utxos', {
                _addresses: [CONFIG.validatorAddress],
                _extended: true,
            });

            if (!utxos || !Array.isArray(utxos) || utxos.length === 0) {
                sel.innerHTML = '<option value="">No plans available</option>';
                return;
            }

            // Plan UTXOs are identified by their datum structure (5 fields),
            // not by beacon tokens. Try parsing each UTXO as a plan datum.
            plans = [];
            for (var i = 0; i < utxos.length; i++) {
                var plan = parsePlanDatum(utxos[i]);
                if (plan) plans.push(plan);
            }

            sel.innerHTML = '';
            if (plans.length === 0) {
                sel.innerHTML = '<option value="">No active plans found</option>';
                return;
            }

            for (var j = 0; j < plans.length; j++) {
                var opt = document.createElement('option');
                opt.value = String(plans[j].planId);
                opt.textContent = plans[j].name;
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
     *
     * @param {bigint} baseUnits - Amount in smallest denomination
     * @param {number} decimals  - Decimal places (6 for ADA, 0 for most native tokens)
     * @param {string} symbol    - Display symbol ("ADA", token name, etc.)
     * @returns {string}
     */
    function formatAmount(baseUnits, decimals, symbol) {
        if (decimals === 0) return baseUnits.toLocaleString() + ' ' + symbol;

        var factor = BigInt(Math.pow(10, decimals));
        var whole = baseUnits / factor;
        var frac = baseUnits % factor;
        if (frac < 0n) frac = -frac;

        var fracStr = frac.toString().padStart(decimals, '0');
        var num = Number(whole.toString() + '.' + fracStr);

        // Smart decimal display:
        //   >= 100:  no decimals (150 ADA)
        //   1-99:   2 decimals  (5.00 ADA)
        //   < 1:    up to 4 significant digits after last leading zero
        var formatted;
        if (num >= 100) {
            formatted = Math.round(num).toLocaleString();
        } else if (num >= 1) {
            formatted = num.toFixed(2);
        } else if (num > 0) {
            // Find first non-zero decimal position, show up to 4 more digits
            var s = num.toFixed(decimals);
            var dotIdx = s.indexOf('.');
            var firstNonZero = -1;
            for (var i = dotIdx + 1; i < s.length; i++) {
                if (s[i] !== '0') { firstNonZero = i; break; }
            }
            if (firstNonZero === -1) {
                formatted = '0';
            } else {
                var sigDigits = Math.min(firstNonZero - dotIdx + 3, decimals);
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
    function getAssetDisplayInfo(paymentAsset) {
        // Empty policy = ADA (lovelace, 6 decimals)
        if (!paymentAsset || paymentAsset === '' || paymentAsset === '.') {
            return { decimals: 6, symbol: 'ADA' };
        }
        // For native tokens: try to decode the asset name hex as UTF-8
        var parts = paymentAsset.split('.');
        var assetNameHex = parts[1] || '';
        var symbol = assetNameHex ? decodeHexString(assetNameHex) : paymentAsset.slice(0, 8) + '...';
        // Most Cardano native tokens have 0 decimals unless we know otherwise
        return { decimals: 0, symbol: symbol };
    }

    // ── Cost calculation ──────────────────────────────────────────────────

    function updateCost() {
        var planId = Number(document.getElementById('plan-select').value);
        var days = parseInt(document.getElementById('days-input').value, 10) || 0;
        var plan = plans.find(function (p) { return p.planId === planId; });
        var costEl = document.getElementById('total-cost');
        var detailEl = document.getElementById('plan-detail');

        if (plan && days > 0) {
            var total = plan.pricePerDay * BigInt(days);
            var info = getAssetDisplayInfo(plan.paymentAsset);
            costEl.textContent = formatAmount(total, info.decimals, info.symbol);
            detailEl.classList.add('hidden');
        } else {
            costEl.textContent = '-';
            detailEl.classList.add('hidden');
        }

        // Enable subscribe only when wallet connected + plan selected + days valid
        var btnSub = document.getElementById('btn-subscribe');
        btnSub.disabled = !(api !== null && plan && days > 0);
    }

    document.getElementById('days-input').addEventListener('input', updateCost);
    document.getElementById('plan-select').addEventListener('change', updateCost);

    // ── UI helpers ────────────────────────────────────────────────────────

    function showStatus(elementId, message, type) {
        var el = document.getElementById(elementId);
        if (!el) return;
        el.innerHTML = '<div class="status ' + (type || 'info') + '">' + message + '</div>';
    }

    function updateStep(stepNum, state) {
        var el = document.getElementById('step' + stepNum + '-num');
        if (!el) return;
        el.classList.remove('done', 'error');
        if (state === 'done') { el.classList.add('done'); el.textContent = '\u2713'; }
        else if (state === 'error') { el.classList.add('error'); el.textContent = '!'; }
        else { el.textContent = String(stepNum); }
    }

    // ── CIP-30 wallet detection and connection ────────────────────────────

    /** @type {object|null} CIP-30 API handle */
    var api = null;
    /** @type {string} hex bech32 address */
    var usedAddress = '';

    var KNOWN_WALLETS = ['eternl', 'nami', 'lace', 'typhon', 'flint', 'yoroi', 'gerowallet', 'nufi'];

    function detectWallets() {
        var walletList = document.getElementById('wallet-list');
        var cardano = window.cardano;

        if (!cardano || typeof cardano !== 'object') {
            document.getElementById('no-wallets').classList.remove('hidden');
            return;
        }

        var found = 0;

        function makeBtn(key) {
            var btn = document.createElement('button');
            btn.className = 'wallet-btn';
            var rawName = (cardano[key] && cardano[key].name) ? cardano[key].name : key;
            // Capitalize first letter
            btn.textContent = rawName.charAt(0).toUpperCase() + rawName.slice(1);
            // Add wallet icon if available
            if (cardano[key] && cardano[key].icon) {
                var img = document.createElement('img');
                img.src = cardano[key].icon;
                img.style.cssText = 'width:20px;height:20px;margin-right:8px;vertical-align:middle;border-radius:4px';
                btn.prepend(img);
            }
            btn.addEventListener('click', function () { connectWallet(key); });
            walletList.appendChild(btn);
            found++;
        }

        for (var i = 0; i < KNOWN_WALLETS.length; i++) {
            if (cardano[KNOWN_WALLETS[i]]) makeBtn(KNOWN_WALLETS[i]);
        }

        // Catch any other CIP-30 wallets not in the known list
        var keys = Object.keys(cardano);
        for (var k = 0; k < keys.length; k++) {
            var key = keys[k];
            if (!KNOWN_WALLETS.includes(key) && cardano[key] && typeof cardano[key].enable === 'function') {
                makeBtn(key);
            }
        }

        if (found === 0) {
            document.getElementById('no-wallets').classList.remove('hidden');
        }
    }

    // ── Bech32 encoding for address display ─────────────────────────────

    var BECH32_CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';

    function bech32Polymod(values) {
        var GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
        var chk = 1;
        for (var i = 0; i < values.length; i++) {
            var b = chk >> 25;
            chk = ((chk & 0x1ffffff) << 5) ^ values[i];
            for (var j = 0; j < 5; j++) {
                if ((b >> j) & 1) chk ^= GEN[j];
            }
        }
        return chk;
    }

    function bech32HrpExpand(hrp) {
        var ret = [];
        for (var i = 0; i < hrp.length; i++) ret.push(hrp.charCodeAt(i) >> 5);
        ret.push(0);
        for (var i = 0; i < hrp.length; i++) ret.push(hrp.charCodeAt(i) & 31);
        return ret;
    }

    function bech32Encode(hrp, data5bit) {
        var values = bech32HrpExpand(hrp).concat(data5bit).concat([0, 0, 0, 0, 0, 0]);
        var polymod = bech32Polymod(values) ^ 1;
        var checksum = [];
        for (var i = 0; i < 6; i++) checksum.push((polymod >> (5 * (5 - i))) & 31);
        var combined = data5bit.concat(checksum);
        var result = hrp + '1';
        for (var i = 0; i < combined.length; i++) result += BECH32_CHARSET[combined[i]];
        return result;
    }

    function convertBits(data, fromBits, toBits, pad) {
        var acc = 0, bits = 0, ret = [], maxv = (1 << toBits) - 1;
        for (var i = 0; i < data.length; i++) {
            acc = (acc << fromBits) | data[i];
            bits += fromBits;
            while (bits >= toBits) {
                bits -= toBits;
                ret.push((acc >> bits) & maxv);
            }
        }
        if (pad && bits > 0) ret.push((acc << (toBits - bits)) & maxv);
        return ret;
    }

    function hexAddressToBech32(hexAddr) {
        try {
            var bytes = hexToBytes(hexAddr);
            // Header byte: top nibble = type, bottom nibble = network
            var networkId = bytes[0] & 0x0f;
            var hrp = networkId === 1 ? 'addr' : 'addr_test';
            var data5 = convertBits(Array.from(bytes), 8, 5, true);
            return bech32Encode(hrp, data5);
        } catch (e) {
            return hexAddr; // fallback to raw hex
        }
    }

    async function connectWallet(name) {
        try {
            api = await window.cardano[name].enable();
            var addresses = await api.getUsedAddresses();
            if (!addresses || addresses.length === 0) {
                var unused = await api.getUnusedAddresses();
                usedAddress = (unused && unused[0]) ? unused[0] : '';
            } else {
                usedAddress = addresses[0];
            }

            if (!usedAddress) {
                throw new Error('No address returned from wallet');
            }

            // Convert hex address to bech32 for display
            var bech32Addr = hexAddressToBech32(usedAddress);
            var display = bech32Addr.length > 30
                ? bech32Addr.slice(0, 16) + '...' + bech32Addr.slice(-10)
                : bech32Addr;

            document.getElementById('wallet-not-connected').classList.add('hidden');
            document.getElementById('wallet-connected').classList.remove('hidden');
            document.getElementById('wallet-address').textContent = display;
            updateStep(1, 'done');

            // Enable days input and trigger cost recalculation
            document.getElementById('days-input').disabled = false;
            updateCost();

            // Also kick off plan loading if it hasn't happened yet
            if (plans.length === 0) loadPlans();

        } catch (err) {
            console.error('connectWallet error:', err);
            showStatus('subscribe-status', 'Wallet connection failed: ' + (err.message || err), 'error');
            updateStep(1, 'error');
        }
    }

    // ── Step 3: Subscribe ─────────────────────────────────────────────────

    document.getElementById('btn-subscribe').addEventListener('click', async function () {
        var btn = document.getElementById('btn-subscribe');
        btn.disabled = true;
        btn.textContent = 'Working...';

        try {
            // Gather parameters
            var planId = Number(document.getElementById('plan-select').value);
            var days = parseInt(document.getElementById('days-input').value, 10);
            var plan = plans.find(function (p) { return p.planId === planId; });

            if (!plan) throw new Error('Please select a plan');
            if (!days || days < 1) throw new Error('Please enter a valid number of days');
            if (!api) throw new Error('Wallet not connected');
            if (!CONFIG.serverPublicKey) throw new Error('Server public key not configured');
            if (!CONFIG.validatorAddress) throw new Error('Validator address not configured');

            // ── Step A: sign publicSecret to derive user credentials ──────
            showStatus('subscribe-status', '<span class="spinner"></span>Signing credentials with wallet...', 'info');

            // CIP-30 signData takes address (hex) and payload (hex-encoded UTF-8 message)
            var msgHex = bytesToHex(new TextEncoder().encode(CONFIG.publicSecret));
            var signResult = await api.signData(usedAddress, msgHex);
            // signResult = { signature: hex (COSE_Sign1), key: hex (COSE_Key) }

            // ── Step B: ECIES encrypt the COSE signature with server pubkey ─
            showStatus('subscribe-status', '<span class="spinner"></span>Encrypting credentials...', 'info');

            // We encrypt the full COSE_Sign1 structure (hex string) so the server
            // can verify the CIP-30 signature and extract the public key.
            var userEncryptedHex = await eciesEncrypt(
                CONFIG.serverPublicKey,
                JSON.stringify({ signature: signResult.signature, key: signResult.key })
            );

            updateStep(3, 'done');
            showStatus('subscribe-status', '<span class="spinner"></span>Building subscription transaction...', 'info');

            // ── Step C: Build and submit subscription transaction ─────────

            if (!CONFIG.beaconScriptCbor) throw new Error('Beacon minting policy not configured');
            if (!CONFIG.subscriptionValidatorHash) throw new Error('Subscription validator hash not configured');

            // C.1  Extract subscriber payment key hash from the CIP-30 address.
            //      CIP-30 getUsedAddresses returns hex-encoded raw address bytes.
            //      Shelley base address: header(1) + payment_key_hash(28) + stake_credential(28)
            var addrBytes = hexToBytes(usedAddress);
            var subscriberKeyHash = bytesToHex(addrBytes.slice(1, 29)); // 28-byte payment key hash

            // C.2  Compute beacon token name: sha256(plan_id_4bytes_BE ++ subscriber_key_hash)
            await ensureEcies(); // ensure _sha256 is loaded
            var planIdBytes = new Uint8Array(4);
            new DataView(planIdBytes.buffer).setInt32(0, planId, false); // big-endian
            var keyHashBytes = hexToBytes(subscriberKeyHash);
            var beaconPreimage = new Uint8Array(4 + keyHashBytes.length);
            beaconPreimage.set(planIdBytes, 0);
            beaconPreimage.set(keyHashBytes, 4);
            var beaconName = bytesToHex(_sha256(beaconPreimage)); // 32 bytes = 64 hex chars

            console.log('beaconName:', beaconName);
            console.log('subscriberKeyHash:', subscriberKeyHash);

            // C.3  Parse payment asset from plan
            var payPolicyId = '';
            var payAssetName = '';
            if (plan.paymentAsset && plan.paymentAsset.includes('.')) {
                var parts = plan.paymentAsset.split('.');
                payPolicyId = parts[0];
                payAssetName = parts[1] || '';
            } else if (plan.paymentAsset && plan.paymentAsset.length === 56) {
                payPolicyId = plan.paymentAsset;
            }
            var isAdaPayment = !payPolicyId;

            // C.4  Compute datum fields
            var totalPayment = plan.pricePerDay * BigInt(days);
            var nowMs = BigInt(Date.now());
            var expiryMs = nowMs + BigInt(days) * 86400000n;
            var intervalMs = 86400000n;  // 1 day in milliseconds
            var ratePerInterval = plan.pricePerDay;

            // C.5  Build SubscriptionDatum as Plutus Data CBOR (inline)
            //      Constr(0, [plan_id, expiry, subscriber_key_hash, amount_remaining,
            //        rate_per_interval, interval_ms, last_collected,
            //        Constr(0, [policy_id, asset_name]), beacon_policy_id, user_encrypted])
            var datumCbor = encodePlutusSubscriptionDatum({
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
            });

            console.log('datumCbor:', datumCbor);

            // C.6  Build CIP-89 validator address for this subscriber.
            //      CIP-89 = script payment credential + subscriber staking credential.
            //      Payment: script hash = subscriptionValidatorHash (28 bytes)
            //      Staking: from subscriber's original address (bytes 29..57)
            var subscriberStakeCred = addrBytes.length >= 57
                ? addrBytes.slice(29, 57) : null;
            var validatorHash = hexToBytes(CONFIG.subscriptionValidatorHash);
            // CIP-89 address: script payment + KEY staking (subscriber's key)
            // Address type 1 = 0b0001 → header = (1 << 4) | network_id
            // Testnet: 0x10, Mainnet: 0x11
            var networkByte = CONFIG.network === 'mainnet' ? 0x11 : 0x10;
            var scriptAddr;
            if (subscriberStakeCred) {
                scriptAddr = new Uint8Array(1 + 28 + 28);
                scriptAddr[0] = networkByte;
                scriptAddr.set(validatorHash, 1);
                scriptAddr.set(subscriberStakeCred, 29);
            } else {
                // Enterprise script address (no staking): header = 0x70 (testnet) or 0x71 (mainnet)
                var entByte = CONFIG.network === 'mainnet' ? 0x71 : 0x70;
                scriptAddr = new Uint8Array(1 + 28);
                scriptAddr[0] = entByte;
                scriptAddr.set(validatorHash, 1);
            }
            var scriptAddrHex = bytesToHex(scriptAddr);

            console.log('scriptAddrHex:', scriptAddrHex);

            // C.7  Fetch UTXOs for coin selection and protocol parameters
            showStatus('subscribe-status', '<span class="spinner"></span>Fetching UTXOs and protocol parameters...', 'info');

            var utxosRaw = await api.getUtxos();
            if (!utxosRaw || utxosRaw.length === 0) {
                throw new Error('No UTXOs in wallet — fund your wallet first');
            }

            var ppArr = await koiosFetch('/epoch_params?limit=1', null);
            if (!ppArr || !Array.isArray(ppArr) || ppArr.length === 0) throw new Error('Failed to fetch protocol parameters');
            var protocolParams = ppArr[0];

            // C.8  Compute min-UTXO lovelace for the script output
            //      Approximate: 2 ADA is generous for a datum-bearing UTXO with one native token
            var minUtxoLovelace = 2000000n;

            // C.9  Compute required lovelace for the script output
            var scriptOutputLovelace;
            if (isAdaPayment) {
                // For ADA payment, lock totalPayment + minUtxo overhead
                scriptOutputLovelace = totalPayment + minUtxoLovelace;
            } else {
                // For token payment, just need min ADA + the token is carried alongside
                scriptOutputLovelace = minUtxoLovelace;
            }

            // C.10 Build the transaction using the wallet's coin selection.
            //      We build a partial transaction body and let the wallet handle
            //      coin selection, fee estimation, and change via signTx.
            showStatus('subscribe-status', '<span class="spinner"></span>Building transaction...', 'info');

            var txBuildResult = await buildSubscriptionTx({
                utxos: utxosRaw,
                scriptAddrHex: scriptAddrHex,
                scriptOutputLovelace: scriptOutputLovelace,
                totalPayment: totalPayment,
                isAdaPayment: isAdaPayment,
                payPolicyId: payPolicyId,
                payAssetName: payAssetName,
                beaconPolicyId: CONFIG.beaconPolicyId,
                beaconName: beaconName,
                beaconScriptCbor: CONFIG.beaconScriptCbor,
                datumCbor: datumCbor,
                protocolParams: protocolParams,
                subscriberKeyHash: subscriberKeyHash,
                changeAddrHex: usedAddress,
                getCollateral: function() { return api.getCollateral(); },
            });

            // C.11 Sign via CIP-30 wallet (partial = true because script inputs may be present)
            console.log('txBuildResult.txHex length:', txBuildResult.txHex.length / 2, 'bytes');

            // Debug: write tx hex to a file endpoint so it can be retrieved
            try {
                var debugEl = document.getElementById('result-content');
                if (debugEl) {
                    debugEl.innerHTML = '<textarea style="width:100%;height:80px;font-size:10px;background:#111;color:#0f0;border:1px solid #333" onclick="this.select()">' + txBuildResult.txHex + '</textarea><p style="font-size:11px;color:#888">Copy this hex and send it for debugging</p>';
                    document.getElementById('result-card').classList.remove('hidden');
                }
            } catch(e) {}

            showStatus('subscribe-status', '<span class="spinner"></span>Awaiting wallet signature...', 'info');
            // C.11 Sign via CIP-30 wallet (partial=true → returns witness set)
            showStatus('subscribe-status', '<span class="spinner"></span>Awaiting wallet signature...', 'info');
            var walletWitnessHex = await api.signTx(txBuildResult.txHex, true);

            // Merge wallet's vkey witnesses into our original tx
            var walletWitBytes = hexToBytes(walletWitnessHex);
            var vkeyWitnessesRaw;
            if (walletWitBytes[0] === 0xa1 && walletWitBytes[1] === 0x00) {
                vkeyWitnessesRaw = walletWitnessHex.slice(4);
            } else {
                vkeyWitnessesRaw = walletWitnessHex;
            }

            var mergedWitness = cborMap([
                [cborUint(0), hexToBytes(vkeyWitnessesRaw)],
                [cborUint(5), txBuildResult.redeemersCbor],
                [cborUint(7), txBuildResult.plutusV3Scripts],
            ]);

            var signedTx = cborArray([
                txBuildResult.txBody,
                mergedWitness,
                new Uint8Array([0xf5]),
                new Uint8Array([0xf6]),
            ]);
            var signedTxHex = bytesToHex(signedTx);

            // C.12 Submit via Koios
            showStatus('subscribe-status', '<span class="spinner"></span>Submitting transaction...', 'info');
            var txHash = await submitViaKoios(signedTxHex);

            console.log('Transaction submitted:', txHash);

            // Show success
            var explorerBase = CONFIG.network === 'mainnet'
                ? 'https://cardanoscan.io/transaction/'
                : 'https://preprod.cardanoscan.io/transaction/';
            document.getElementById('result-card').classList.remove('hidden');
            document.getElementById('result-content').innerHTML =
                'Transaction submitted successfully!<br>' +
                '<a class="tx-link" href="' + explorerBase + txHash + '" target="_blank" rel="noopener">' +
                txHash + '</a>';

            showStatus('subscribe-status', 'Subscription created! Your server will be provisioned shortly.', 'success');

        } catch (err) {
            console.error('subscribe error:', err);
            showStatus('subscribe-status', (err.message || 'Subscription failed'), 'error');
            updateStep(3, 'error');
            btn.disabled = false;
            btn.textContent = 'Subscribe';
        }
    });

    // ── CBOR encoding helpers ────────────────────────────────────────────
    //
    // Minimal CBOR encoder sufficient for Plutus Data and Cardano transaction
    // bodies.  Only supports the subset used by this page:
    //   - unsigned integers (major 0)
    //   - negative integers (major 1)
    //   - byte strings (major 2)
    //   - text strings (major 3)  -- not currently used but included for completeness
    //   - arrays (major 4)
    //   - maps (major 5)
    //   - tags (major 6)
    //   - simple values / break (major 7)

    /**
     * Encode a single unsigned integer argument header.
     * @param {number} major - CBOR major type (0-7)
     * @param {number|bigint} n - value
     * @returns {Uint8Array}
     */
    function cborHeader(major, n) {
        var mt = major << 5;
        n = typeof n === 'bigint' ? n : BigInt(n);
        if (n < 0n) throw new Error('cborHeader: negative value');
        if (n < 24n) return new Uint8Array([mt | Number(n)]);
        if (n < 256n) return new Uint8Array([mt | 24, Number(n)]);
        if (n < 65536n) {
            var b = new Uint8Array(3);
            b[0] = mt | 25;
            b[1] = Number((n >> 8n) & 0xFFn);
            b[2] = Number(n & 0xFFn);
            return b;
        }
        if (n < 4294967296n) {
            var b = new Uint8Array(5);
            b[0] = mt | 26;
            b[1] = Number((n >> 24n) & 0xFFn);
            b[2] = Number((n >> 16n) & 0xFFn);
            b[3] = Number((n >> 8n) & 0xFFn);
            b[4] = Number(n & 0xFFn);
            return b;
        }
        // 8-byte
        var b = new Uint8Array(9);
        b[0] = mt | 27;
        for (var i = 7; i >= 0; i--) {
            b[8 - i] = Number((n >> BigInt(i * 8)) & 0xFFn);
        }
        return b;
    }

    /** Encode a CBOR unsigned integer (major 0) */
    function cborUint(n) {
        return cborHeader(0, n);
    }

    /** Encode a CBOR negative integer (major 1): represents -1-n */
    function cborNint(n) {
        // CBOR negative: -1 - val, so to encode -x, pass x-1
        if (typeof n !== 'bigint') n = BigInt(n);
        return cborHeader(1, -n - 1n);
    }

    /** Encode a CBOR integer (handles both positive and negative) */
    function cborInt(n) {
        if (typeof n !== 'bigint') n = BigInt(n);
        if (n >= 0n) return cborUint(n);
        return cborNint(n);
    }

    /** Encode a CBOR byte string (major 2) */
    function cborBytes(bytes) {
        if (typeof bytes === 'string') bytes = hexToBytes(bytes);
        return concatBytes([cborHeader(2, bytes.length), bytes]);
    }

    /** Encode a CBOR text string (major 3) */
    function cborText(str) {
        var enc = new TextEncoder().encode(str);
        return concatBytes([cborHeader(3, enc.length), enc]);
    }

    /** Encode a CBOR array header (major 4) then items */
    function cborArray(items) {
        return concatBytes([cborHeader(4, items.length)].concat(items));
    }

    /** Encode a CBOR map (major 5) — items is [[key, value], ...] already encoded */
    function cborMap(entries) {
        var parts = [cborHeader(5, entries.length)];
        for (var i = 0; i < entries.length; i++) {
            parts.push(entries[i][0]); // key
            parts.push(entries[i][1]); // value
        }
        return concatBytes(parts);
    }

    /** Encode a CBOR tag (major 6) */
    function cborTag(tagNum, content) {
        return concatBytes([cborHeader(6, tagNum), content]);
    }

    /** Concatenate multiple Uint8Arrays */
    function concatBytes(arrays) {
        var total = 0;
        for (var i = 0; i < arrays.length; i++) total += arrays[i].length;
        var result = new Uint8Array(total);
        var offset = 0;
        for (var i = 0; i < arrays.length; i++) {
            result.set(arrays[i], offset);
            offset += arrays[i].length;
        }
        return result;
    }

    // ── Plutus Data CBOR encoding ─────────────────────────────────────────
    //
    // Plutus Data uses CBOR constructor tags:
    //   Constr(0, fields)  → tag 121 + array(fields)
    //   Constr(1, fields)  → tag 122 + array(fields)
    //   ...
    //   Constr(6, fields)  → tag 127 + array(fields)
    //   Constr(n>=7, fields) → tag 102 + array([n, array(fields)])

    /** Encode a CBOR indefinite-length array: 0x9f + items + 0xff */
    function cborArrayIndef(items) {
        var parts = [new Uint8Array([0x9f])];
        for (var i = 0; i < items.length; i++) parts.push(items[i]);
        parts.push(new Uint8Array([0xff]));
        return concatBytes(parts);
    }

    /** Encode a Plutus Constr(index, fields) where fields are already CBOR-encoded.
     *  Uses indefinite-length arrays for non-empty fields (wallet compat),
     *  definite empty array for empty fields (Lucid/CSL compat). */
    function plutusConstr(index, fieldsCbor) {
        // Empty fields: use definite empty array 0x80 (matches Lucid's encoding)
        // Non-empty fields: use indefinite array 0x9f...0xff (matches Lucid's encoding)
        var arr = fieldsCbor.length === 0 ? cborArray([]) : cborArrayIndef(fieldsCbor);
        if (index <= 6) {
            return cborTag(121 + index, arr);
        }
        // General case: tag 102 + [index, [fields]]
        return cborTag(102, cborArray([cborUint(index), arr]));
    }

    /**
     * Encode a SubscriptionDatum to Plutus Data CBOR hex.
     *
     * Constr(0, [
     *   plan_id: Int,
     *   expiry: Int,
     *   subscriber_key_hash: Bytes,
     *   amount_remaining: Int,
     *   rate_per_interval: Int,
     *   interval_ms: Int,
     *   last_collected: Int,
     *   payment_asset: Constr(0, [policy_id: Bytes, asset_name: Bytes]),
     *   beacon_policy_id: Bytes,
     *   user_encrypted: Bytes,
     * ])
     */
    function encodePlutusSubscriptionDatum(d) {
        var paymentAsset = plutusConstr(0, [
            cborBytes(d.payPolicyId),
            cborBytes(d.payAssetName),
        ]);

        var fields = [
            cborInt(d.planId),
            cborInt(d.expiry),
            cborBytes(d.subscriberKeyHash),
            cborInt(d.amountRemaining),
            cborInt(d.ratePerInterval),
            cborInt(d.intervalMs),
            cborInt(d.lastCollected),
            paymentAsset,
            cborBytes(d.beaconPolicyId),
            cborBytes(d.userEncrypted),
        ];

        var cbor = plutusConstr(0, fields);
        return bytesToHex(cbor);
    }

    // ── Transaction building ──────────────────────────────────────────────
    //
    // Builds a Cardano transaction CBOR that the CIP-30 wallet can sign.
    // The transaction includes:
    //   - Inputs from wallet UTXOs (for payment)
    //   - Script output at the CIP-89 validator address with inline datum + beacon token
    //   - Minting of beacon token with Plutus V3 script + CreateSubscription redeemer
    //   - Change output back to subscriber
    //   - Fee (estimated, then adjusted)
    //   - Validity range

    /**
     * Build an unsigned subscription transaction CBOR hex.
     *
     * Uses a simplified coin selection (greedy, ADA-only for now) and constructs
     * the full transaction body. The CIP-30 wallet signs via signTx(cbor, true).
     *
     * @param {object} p - Parameters object
     * @returns {Promise<string>} unsigned transaction CBOR hex
     */
    async function buildSubscriptionTx(p) {
        // ── Parse wallet UTXOs from CIP-30 format (CBOR hex) ────────────
        var parsedUtxos = [];
        for (var i = 0; i < p.utxos.length; i++) {
            var parsed = parseCip30Utxo(p.utxos[i]);
            if (parsed) parsedUtxos.push(parsed);
        }

        if (parsedUtxos.length === 0) {
            throw new Error('No usable UTXOs in wallet');
        }

        // ── Get current slot for validity range ─────────────────────────
        var tipArr = await koiosFetch('/tip', null);
        if (!tipArr || !Array.isArray(tipArr) || tipArr.length === 0) throw new Error('Failed to fetch chain tip');
        var tipData = tipArr[0];
        var currentSlot = tipData.abs_slot || 0;

        // Validity range: valid from (current slot - 60) to (current slot + 900)
        // This gives a 15-minute window for submission
        var validFrom = currentSlot - 60;
        var validTo = currentSlot + 900;
        if (validFrom < 0) validFrom = 0;

        // ── Coin selection ──────────────────────────────────────────────
        // For ADA payment: we need scriptOutputLovelace + fee + minUtxo for change
        // For token payment: we need minUtxo for script + token amount + fee
        var estimatedFee = 1000000n; // 1 ADA — generous for Plutus script tx
        var requiredLovelace = p.scriptOutputLovelace + estimatedFee;

        // Sort UTXOs by lovelace descending for greedy selection
        parsedUtxos.sort(function (a, b) {
            if (a.lovelace > b.lovelace) return -1;
            if (a.lovelace < b.lovelace) return 1;
            return 0;
        });

        var selectedUtxos = [];
        var totalInputLovelace = 0n;
        var totalInputTokens = {}; // unit → bigint

        for (var i = 0; i < parsedUtxos.length; i++) {
            selectedUtxos.push(parsedUtxos[i]);
            totalInputLovelace += parsedUtxos[i].lovelace;
            // Track native tokens
            if (parsedUtxos[i].tokens) {
                for (var unit in parsedUtxos[i].tokens) {
                    totalInputTokens[unit] = (totalInputTokens[unit] || 0n) + parsedUtxos[i].tokens[unit];
                }
            }
            if (totalInputLovelace >= requiredLovelace) {
                // For token payment, also ensure we have enough tokens
                if (!p.isAdaPayment) {
                    var tokenUnit = p.payPolicyId + p.payAssetName;
                    if ((totalInputTokens[tokenUnit] || 0n) < p.totalPayment) continue;
                }
                break;
            }
        }

        if (totalInputLovelace < requiredLovelace) {
            throw new Error(
                'Insufficient ADA. Need ' + (requiredLovelace / 1000000n).toString() +
                ' ADA, have ' + (totalInputLovelace / 1000000n).toString() + ' ADA'
            );
        }

        if (!p.isAdaPayment) {
            var tokenUnit = p.payPolicyId + p.payAssetName;
            if ((totalInputTokens[tokenUnit] || 0n) < p.totalPayment) {
                throw new Error('Insufficient tokens for payment');
            }
        }

        // ── Build transaction body fields ───────────────────────────────

        // Field 0: inputs (set of [txHash, index])
        var inputsCbor = buildInputsCbor(selectedUtxos);

        // Field 1: outputs
        // Output 0: script output (validator address + beacon + datum)
        // Output 1: change output (back to subscriber)
        var scriptOutputCbor = buildScriptOutput(p);
        var changeLovelace = totalInputLovelace - p.scriptOutputLovelace - estimatedFee;

        // Build change output — return unused tokens too
        var changeTokens = {};
        for (var unit in totalInputTokens) {
            changeTokens[unit] = totalInputTokens[unit];
        }
        // Subtract any tokens sent to the script output
        if (!p.isAdaPayment) {
            var tokenUnit = p.payPolicyId + p.payAssetName;
            changeTokens[tokenUnit] = (changeTokens[tokenUnit] || 0n) - p.totalPayment;
            if (changeTokens[tokenUnit] <= 0n) delete changeTokens[tokenUnit];
        }

        var changeOutputCbor = buildChangeOutput(p.changeAddrHex, changeLovelace, changeTokens);

        var outputsCbor = cborArray([scriptOutputCbor, changeOutputCbor]);

        // Field 2: fee
        var feeCbor = cborUint(estimatedFee);

        // Field 3: TTL (validTo)
        var ttlCbor = cborUint(validTo);

        // Field 8: validity interval start (validFrom)
        // Field 9: mint
        var mintCbor = buildMintCbor(p.beaconPolicyId, p.beaconName, 1n);

        // Field 11: script_data_hash — computed from redeemers + datums + cost models
        // We will compute this after building the witness set

        // Field 14: required signers (subscriber key hash for minting policy)
        var requiredSignersCbor = cborArray([cborBytes(p.subscriberKeyHash)]);

        // ── Build transaction body as CBOR map ──────────────────────────
        // Transaction body is a map with integer keys
        // Collateral: use the wallet's reserved collateral UTXO (CIP-30 getCollateral)
        var collateralUtxos = await p.getCollateral();
        if (!collateralUtxos || collateralUtxos.length === 0) {
            throw new Error('No collateral set in wallet. Please configure collateral in your wallet settings (typically 5 ADA).');
        }
        console.log('getCollateral returned', collateralUtxos.length, 'UTXOs');
        console.log('Collateral[0] hex length:', collateralUtxos[0].length, 'first 80:', collateralUtxos[0].slice(0, 80));
        var collateralParsed = parseCip30Utxo(collateralUtxos[0]);
        if (!collateralParsed) throw new Error('Could not parse collateral UTXO');
        console.log('Collateral parsed txHash:', collateralParsed.txHash, '(len:', collateralParsed.txHash.length + ') #' + collateralParsed.index, 'lovelace:', collateralParsed.lovelace.toString());

        // Verify collateral txHash is 64 hex chars (32 bytes)
        if (collateralParsed.txHash.length !== 64) {
            console.error('COLLATERAL TXHASH WRONG LENGTH:', collateralParsed.txHash.length, 'expected 64');
        }
        console.log('Spending inputs:', selectedUtxos.map(function(u) { return u.txHash + '#' + u.index + '(len:' + u.txHash.length + ')'; }));
        // Verify collateral is not in spending inputs
        var colKey = collateralParsed.txHash + '#' + collateralParsed.index;
        var spendKeys = selectedUtxos.map(function(u) { return u.txHash + '#' + u.index; });
        if (spendKeys.indexOf(colKey) !== -1) {
            console.warn('WARNING: collateral UTXO is also a spending input!');
        }

        // key 13 = collateral inputs
        var collateralInputsCbor = cborTag(258, cborArray([
            cborArray([cborBytes(collateralParsed.txHash), cborUint(collateralParsed.index)]),
        ]));
        // key 17 = total collateral = how much the node can seize if script fails
        // Must equal: collateral_input_value - collateral_return_value
        // Typical: 150% of fee. With 1 ADA fee → 1.5 ADA collateral.
        var totalCollateral = estimatedFee + estimatedFee / 2n; // 150% of fee
        if (totalCollateral > collateralParsed.lovelace) totalCollateral = collateralParsed.lovelace;

        // key 16 = collateral return (remainder back to subscriber)
        var collateralReturnValue = collateralParsed.lovelace - totalCollateral;
        var collateralReturnCbor = cborMap([
            [cborUint(0), cborBytes(hexToBytes(p.changeAddrHex))],
            [cborUint(1), cborUint(collateralReturnValue)],
        ]);

        var bodyEntries = [
            [cborUint(0), inputsCbor],      // inputs
            [cborUint(1), outputsCbor],      // outputs
            [cborUint(2), feeCbor],          // fee
            [cborUint(3), ttlCbor],          // ttl
            [cborUint(8), cborUint(validFrom)],  // validity interval start
            [cborUint(9), mintCbor],         // mint
            [cborUint(13), collateralInputsCbor], // collateral inputs
            [cborUint(14), requiredSignersCbor],  // required signers
            [cborUint(16), collateralReturnCbor], // collateral return
            [cborUint(17), cborUint(totalCollateral)], // total collateral
        ];
        var txBody = cborMap(bodyEntries);

        // ── Build witness set ───────────────────────────────────────────
        // The witness set needs:
        //   - field 3: plutus_v3_scripts (for the beacon minting policy)
        //   - field 5: redeemers (for the minting action)
        //
        // The wallet will add vkey witnesses via signTx.
        // Script data hash (field 11 in body) = hash of (redeemers, datums, cost_models)

        // Redeemer for the mint: CreateSubscription = Constr(0, [])
        // Redeemers: array of [tag, index, data, ex_units]
        // tag 0 = spend, tag 1 = mint, tag 2 = cert, tag 3 = reward
        // Execution units for CreateSubscription on our beacon validator.
        // Evaluated by Lucid — constant for this script regardless of tx context.
        // Only changes on protocol hard forks (cost model updates).
        var EX_UNITS_MEM = 50317n;
        var EX_UNITS_STEPS = 15491760n;

        var redeemerData = plutusConstr(0, []);  // CreateSubscription = Constr(0, [])
        var redeemerCbor = cborArray([
            cborUint(1),          // tag: mint
            cborUint(0),          // index
            redeemerData,         // redeemer data
            cborArray([           // ex_units [mem, steps]
                cborUint(EX_UNITS_MEM),
                cborUint(EX_UNITS_STEPS),
            ]),
        ]);
        var redeemersCbor = cborArray([redeemerCbor]);

        // Decode the beacon script from hex CBOR (it's a double-encoded CBOR script)
        var beaconScriptBytes = hexToBytes(p.beaconScriptCbor);

        // Plutus V3 scripts in the witness set
        var plutusV3Scripts = cborArray([cborBytes(beaconScriptBytes)]);

        // Script data hash — precomputed for our beacon CreateSubscription redeemer.
        // Computed via Lucid with evaluated ex_units [50317, 15491760].
        // This hash is constant for all subscription transactions because:
        //   - Redeemer is always Constr(0, []) with the same ex_units
        //   - Datums in witness set are always empty (we use inline datums)
        //   - Cost model only changes on protocol hard forks
        // Recompute after hard forks by running: buildSubscriptionTx via Lucid
        var SCRIPT_DATA_HASH = '0fe49daf8971d9bc438ae1f3210f55c55460021c545b9dfdbe815b6f90453ed6';

        // Build witness set as CBOR map
        var witnessEntries = [
            [cborUint(7), plutusV3Scripts], // field 7: plutus_v3_scripts
            [cborUint(5), redeemersCbor],   // field 5: redeemers
        ];
        var witnessSet = cborMap(witnessEntries);

        // Add script_data_hash to body (field 11)
        bodyEntries.push([cborUint(11), cborBytes(SCRIPT_DATA_HASH)]);
        txBody = cborMap(bodyEntries);

        // ── Assemble full transaction ───────────────────────────────────
        // Transaction = [body, witness_set, is_valid, auxiliary_data]
        var txCbor = cborArray([
            txBody,
            witnessSet,
            new Uint8Array([0xF5]),     // true (is_valid)
            new Uint8Array([0xF6]),     // null (no auxiliary data)
        ]);

        return {
            txHex: bytesToHex(txCbor),
            txBody: txBody,
            redeemersCbor: redeemersCbor,
            plutusV3Scripts: plutusV3Scripts,
        };
    }

    /**
     * Parse a CIP-30 UTXO (CBOR hex of a transaction output).
     * CIP-30 getUtxos() returns an array of CBOR-encoded [input, output] pairs.
     *
     * A simplified parser that extracts txHash, index, lovelace, and tokens.
     */
    function parseCip30Utxo(cborHex) {
        try {
            var bytes = hexToBytes(cborHex);
            var decoded = decodeCbor(bytes, 0);
            var pair = decoded.value;

            if (!Array.isArray(pair) || pair.length < 2) return null;

            // pair[0] = input = [txHash (bytes), index (uint)]
            var input = pair[0];
            if (!Array.isArray(input) || input.length < 2) return null;

            var txHash = input[0]; // Uint8Array or hex
            var index = input[1];
            if (txHash instanceof Uint8Array) txHash = bytesToHex(txHash);

            // pair[1] = output = [address, value, ...] or map
            var output = pair[1];
            var lovelace = 0n;
            var tokens = {};

            if (Array.isArray(output)) {
                // Pre-Babbage: [address, value, optional_datum_hash]
                var value = output[1];
                if (typeof value === 'bigint' || typeof value === 'number') {
                    lovelace = BigInt(value);
                } else if (Array.isArray(value)) {
                    // [lovelace, multiasset_map]
                    lovelace = BigInt(value[0]);
                    if (value[1] && typeof value[1] === 'object') {
                        tokens = parseMultiAsset(value[1]);
                    }
                }
            } else if (output && typeof output === 'object' && !(output instanceof Uint8Array)) {
                // Post-Babbage: map { 0: address, 1: value, ... }
                var value = output[1] || output.get?.(1);
                if (typeof value === 'bigint' || typeof value === 'number') {
                    lovelace = BigInt(value);
                } else if (Array.isArray(value)) {
                    lovelace = BigInt(value[0]);
                    if (value[1] && typeof value[1] === 'object') {
                        tokens = parseMultiAsset(value[1]);
                    }
                }
            }

            return {
                txHash: txHash,
                index: Number(index),
                lovelace: lovelace,
                tokens: tokens,
            };
        } catch (e) {
            console.warn('parseCip30Utxo error:', e);
            return null;
        }
    }

    /**
     * Parse a CBOR multiasset map into { "policyId+assetName": bigint }.
     * The multiasset structure is: Map<PolicyId, Map<AssetName, Quantity>>
     */
    function parseMultiAsset(multiasset) {
        var tokens = {};
        if (multiasset instanceof Map) {
            multiasset.forEach(function (assets, policyId) {
                var pid = policyId instanceof Uint8Array ? bytesToHex(policyId) : String(policyId);
                if (assets instanceof Map) {
                    assets.forEach(function (qty, assetName) {
                        var aname = assetName instanceof Uint8Array ? bytesToHex(assetName) : String(assetName);
                        tokens[pid + aname] = BigInt(qty);
                    });
                }
            });
        }
        return tokens;
    }

    /**
     * Minimal CBOR decoder — handles the subset needed for CIP-30 UTXOs.
     * Returns { value, offset } where offset is the position after the decoded item.
     */
    function decodeCbor(bytes, pos) {
        if (pos >= bytes.length) throw new Error('CBOR: unexpected end');
        var initial = bytes[pos];
        var major = initial >> 5;
        var additional = initial & 0x1F;
        pos++;

        // Decode the argument value
        var argVal;
        if (additional < 24) {
            argVal = BigInt(additional);
        } else if (additional === 24) {
            argVal = BigInt(bytes[pos++]);
        } else if (additional === 25) {
            argVal = BigInt(bytes[pos] << 8 | bytes[pos + 1]);
            pos += 2;
        } else if (additional === 26) {
            argVal = BigInt((bytes[pos] << 24 | bytes[pos + 1] << 16 | bytes[pos + 2] << 8 | bytes[pos + 3]) >>> 0);
            pos += 4;
        } else if (additional === 27) {
            argVal = 0n;
            for (var i = 0; i < 8; i++) {
                argVal = (argVal << 8n) | BigInt(bytes[pos + i]);
            }
            pos += 8;
        } else if (additional === 31) {
            // Indefinite length
            argVal = -1n;
        } else {
            throw new Error('CBOR: unsupported additional info ' + additional);
        }

        switch (major) {
            case 0: // unsigned int
                return { value: argVal, offset: pos };
            case 1: // negative int
                return { value: -1n - argVal, offset: pos };
            case 2: // byte string
                if (argVal < 0n) throw new Error('CBOR: indefinite byte strings unsupported');
                var len = Number(argVal);
                var bval = bytes.slice(pos, pos + len);
                return { value: bval, offset: pos + len };
            case 3: // text string
                if (argVal < 0n) throw new Error('CBOR: indefinite text strings unsupported');
                var tlen = Number(argVal);
                var tval = new TextDecoder().decode(bytes.slice(pos, pos + tlen));
                return { value: tval, offset: pos + tlen };
            case 4: // array
                var arr = [];
                if (argVal < 0n) {
                    // indefinite length array
                    while (bytes[pos] !== 0xFF) {
                        var item = decodeCbor(bytes, pos);
                        arr.push(item.value);
                        pos = item.offset;
                    }
                    pos++; // skip break byte
                } else {
                    var count = Number(argVal);
                    for (var i = 0; i < count; i++) {
                        var item = decodeCbor(bytes, pos);
                        arr.push(item.value);
                        pos = item.offset;
                    }
                }
                return { value: arr, offset: pos };
            case 5: // map
                var map = new Map();
                if (argVal < 0n) {
                    while (bytes[pos] !== 0xFF) {
                        var k = decodeCbor(bytes, pos);
                        var v = decodeCbor(bytes, k.offset);
                        map.set(k.value, v.value);
                        pos = v.offset;
                    }
                    pos++;
                } else {
                    var mcount = Number(argVal);
                    for (var i = 0; i < mcount; i++) {
                        var k = decodeCbor(bytes, pos);
                        var v = decodeCbor(bytes, k.offset);
                        map.set(k.value, v.value);
                        pos = v.offset;
                    }
                }
                return { value: map, offset: pos };
            case 6: // tag
                var tagged = decodeCbor(bytes, pos);
                // Return the tagged value (we don't use the tag number for parsing)
                return { value: tagged.value, offset: tagged.offset };
            case 7: // simple / float
                if (argVal === 20n) return { value: false, offset: pos };
                if (argVal === 21n) return { value: true, offset: pos };
                if (argVal === 22n) return { value: null, offset: pos };
                if (argVal === 23n) return { value: undefined, offset: pos };
                return { value: Number(argVal), offset: pos };
            default:
                throw new Error('CBOR: unsupported major type ' + major);
        }
    }

    /**
     * Build CBOR for transaction inputs.
     * Inputs are encoded as a set (CBOR array) of [txHash(bytes32), index(uint)].
     * Inputs MUST be sorted lexicographically by (txHash, index) per Conway.
     */
    function buildInputsCbor(utxos) {
        // Sort by txHash then index
        var sorted = utxos.slice().sort(function (a, b) {
            if (a.txHash < b.txHash) return -1;
            if (a.txHash > b.txHash) return 1;
            return a.index - b.index;
        });

        var items = [];
        for (var i = 0; i < sorted.length; i++) {
            items.push(cborArray([
                cborBytes(sorted[i].txHash),
                cborUint(sorted[i].index),
            ]));
        }
        // Use tag 258 for set semantics (required for Conway era inputs)
        return cborTag(258, cborArray(items));
    }

    /**
     * Build the script output CBOR (post-Babbage format).
     * Post-Babbage output is a map:
     *   { 0: address(bytes), 1: value, 2: datum_option }
     * Where datum_option for inline datum = [1, datum_cbor_tagged]
     */
    function buildScriptOutput(p) {
        // Address as raw bytes
        var addrBytes = hexToBytes(p.scriptAddrHex);

        // Value: for ADA-only, just lovelace uint.
        // For ADA + tokens, [lovelace, { policyId: { assetName: qty } }]
        var valueCbor;
        var beaconAssetMap = cborMap([
            [cborBytes(p.beaconName), cborUint(1n)],
        ]);
        var beaconPolicyMap = cborMap([
            [cborBytes(p.beaconPolicyId), beaconAssetMap],
        ]);

        if (p.isAdaPayment) {
            // ADA payment: value = [lovelace, { beaconPolicy: { beaconName: 1 } }]
            valueCbor = cborArray([cborUint(p.scriptOutputLovelace), beaconPolicyMap]);
        } else {
            // Token payment: value = [lovelace, { beaconPolicy: { beaconName: 1 }, payPolicy: { payAsset: amount } }]
            var payAssetMap = cborMap([
                [cborBytes(p.payAssetName), cborUint(p.totalPayment)],
            ]);
            var multiAsset = cborMap([
                [cborBytes(p.beaconPolicyId), beaconAssetMap],
                [cborBytes(p.payPolicyId), payAssetMap],
            ]);
            valueCbor = cborArray([cborUint(p.scriptOutputLovelace), multiAsset]);
        }

        // Inline datum: [1, tag(24, encoded_datum)]
        // The datum CBOR is wrapped in tag 24 (CBOR-in-CBOR) as a bstr
        var datumBytes = hexToBytes(p.datumCbor);
        var datumOption = cborArray([
            cborUint(1),
            cborTag(24, cborBytes(datumBytes)),
        ]);

        // Build output as map
        return cborMap([
            [cborUint(0), cborBytes(addrBytes)],
            [cborUint(1), valueCbor],
            [cborUint(2), datumOption],
        ]);
    }

    /**
     * Build a change output for the subscriber's wallet.
     */
    function buildChangeOutput(addrHex, lovelace, tokens) {
        var addrBytes = hexToBytes(addrHex);

        // Check if there are any tokens to return
        var hasTokens = false;
        for (var unit in tokens) {
            if (tokens[unit] > 0n) { hasTokens = true; break; }
        }

        var valueCbor;
        if (!hasTokens) {
            valueCbor = cborUint(lovelace);
        } else {
            // Group tokens by policy
            var policies = {};
            for (var unit in tokens) {
                if (tokens[unit] <= 0n) continue;
                var pid = unit.slice(0, 56);
                var aname = unit.slice(56);
                if (!policies[pid]) policies[pid] = [];
                policies[pid].push([aname, tokens[unit]]);
            }

            var policyEntries = [];
            for (var pid in policies) {
                var assetEntries = [];
                for (var j = 0; j < policies[pid].length; j++) {
                    assetEntries.push([
                        cborBytes(policies[pid][j][0]),
                        cborUint(policies[pid][j][1]),
                    ]);
                }
                policyEntries.push([cborBytes(pid), cborMap(assetEntries)]);
            }

            valueCbor = cborArray([cborUint(lovelace), cborMap(policyEntries)]);
        }

        return cborMap([
            [cborUint(0), cborBytes(addrBytes)],
            [cborUint(1), valueCbor],
        ]);
    }

    /**
     * Build mint field CBOR: { policyId: { assetName: quantity } }
     */
    function buildMintCbor(policyId, assetName, quantity) {
        return cborMap([
            [cborBytes(policyId), cborMap([
                [cborBytes(assetName), cborUint(quantity)],
            ])],
        ]);
    }

    /**
     * Submit a signed transaction via Koios REST API.
     * POST /submittx with Content-Type: application/cbor and raw CBOR bytes.
     *
     * @param {string} signedTxHex - Signed transaction CBOR hex
     * @returns {Promise<string>} Transaction hash
     */
    async function submitViaKoios(signedTxHex) {
        var txBytes = hexToBytes(signedTxHex);

        var result = await koiosFetch('/submittx', null, {
            method: 'POST',
            contentType: 'application/cbor',
            rawBody: txBytes,
        });

        // Koios returns the hash as plain text (may have quotes)
        return result.replace(/"/g, '').trim();
    }

    // ── Initialise ────────────────────────────────────────────────────────

    // Wallet extensions inject window.cardano asynchronously after page load.
    // Retry detection a few times with increasing delays.
    function detectWithRetry(attempt) {
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

})();
