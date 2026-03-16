/**
 * Signup page engine for Cardano (BlockHost).
 *
 * Loaded after an inline CONFIG block injected by generate-signup-page.
 * Handles:
 *   1. CIP-30 wallet detection and connection
 *   2. Plan fetching from plan reference UTXOs via Blockfrost REST API
 *   3. Cost calculation
 *   4. Subscription transaction building (MeshJS — stubbed, TODO)
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

    // ── Blockfrost REST base URL ─────────────────────────────────────────

    function blockfrostBase(network) {
        if (network === 'mainnet') return 'https://cardano-mainnet.blockfrost.io/api/v0';
        if (network === 'preview') return 'https://cardano-preview.blockfrost.io/api/v0';
        return 'https://cardano-preprod.blockfrost.io/api/v0';
    }

    /**
     * Blockfrost fetch helper.
     * Uses CONFIG.blockfrostProjectId as the project_id header.
     *
     * @param {string} path - API path starting with /
     * @returns {Promise<unknown>}
     */
    async function bfetch(path) {
        var base = blockfrostBase(CONFIG.network);
        var res = await fetch(base + path, {
            headers: { 'project_id': CONFIG.blockfrostProjectId },
        });
        if (!res.ok) {
            if (res.status === 404) return null;
            var errBody = await res.text().catch(function () { return ''; });
            throw new Error('Blockfrost ' + res.status + ': ' + errBody.slice(0, 120));
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

    // ── Plan data (fetched from Blockfrost) ───────────────────────────────

    /**
     * Plan record.
     * @typedef {{ planId: number, name: string, pricePerDay: bigint, paymentAsset: string }} Plan
     */

    /** @type {Plan[]} */
    var plans = [];

    /**
     * Parse a plan datum from a Blockfrost UTXO's inline_datum JSON.
     *
     * The on-chain plan datum structure (set by blockhost-bw plan create) is:
     *   Constr(0, [plan_id, name, price_per_day, payment_assets, active])
     *
     * Blockfrost exposes inline data as a JSON object under utxo.inline_datum
     * using the generic Plutus data representation:
     *   { "constructor": 0, "fields": [ int, bytes, int, list, int ] }
     *
     * This is a best-effort parser — the exact shape depends on how the
     * datum is serialised by the Aiken validator. Adjust field indices if
     * the validator changes its datum layout.
     *
     * @param {object} utxo - UTXO object from Blockfrost /addresses/{addr}/utxos
     * @returns {Plan|null}
     */
    function parsePlanDatum(utxo) {
        try {
            var datum = utxo.inline_datum;
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
     * Fetch active plans from the validator address via Blockfrost.
     * Plans are stored as inline-datum UTXOs at CONFIG.validatorAddress.
     */
    async function loadPlans() {
        var sel = document.getElementById('plan-select');
        if (!CONFIG.validatorAddress) {
            sel.innerHTML = '<option value="">Validator address not configured</option>';
            return;
        }
        if (!CONFIG.blockfrostProjectId) {
            sel.innerHTML = '<option value="">Blockfrost project ID not configured</option>';
            return;
        }

        try {
            // Query all UTXOs at the validator address; plans carry a beacon token
            // whose policy equals CONFIG.beaconPolicyId (if set).
            var utxos;
            if (CONFIG.beaconPolicyId) {
                utxos = await bfetch('/addresses/' + encodeURIComponent(CONFIG.validatorAddress) + '/utxos/' + encodeURIComponent(CONFIG.beaconPolicyId));
            } else {
                utxos = await bfetch('/addresses/' + encodeURIComponent(CONFIG.validatorAddress) + '/utxos');
            }

            if (!utxos || !Array.isArray(utxos) || utxos.length === 0) {
                sel.innerHTML = '<option value="">No plans available</option>';
                return;
            }

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

    // ── Cost calculation ──────────────────────────────────────────────────

    function updateCost() {
        var planId = Number(document.getElementById('plan-select').value);
        var days = parseInt(document.getElementById('days-input').value, 10) || 0;
        var plan = plans.find(function (p) { return p.planId === planId; });
        var costEl = document.getElementById('total-cost');
        var detailEl = document.getElementById('plan-detail');

        if (plan && days > 0) {
            var total = plan.pricePerDay * BigInt(days);
            // Display in lovelace if no payment asset, or raw units if token
            var unit = plan.paymentAsset ? 'base units' : 'lovelace';
            costEl.textContent = total.toLocaleString() + ' ' + unit;
            if (plan.paymentAsset) {
                detailEl.textContent = 'Asset: ' + plan.paymentAsset;
                detailEl.classList.remove('hidden');
            } else {
                detailEl.classList.add('hidden');
            }
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
            btn.textContent = (cardano[key] && cardano[key].name) ? cardano[key].name : key;
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

            var display = usedAddress.length > 24
                ? usedAddress.slice(0, 14) + '...' + usedAddress.slice(-10)
                : usedAddress;

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
            //
            // TODO: Implement MeshJS transaction building.
            //
            // The subscription transaction must:
            //   1. Compute beacon token name:
            //      beaconName = sha256(plan_id_4bytes_be ++ subscriber_payment_key_hash)
            //      (See src/cardano/beacon.ts: computeBeaconName)
            //
            //   2. Build the SubscriptionDatum:
            //      { planId, expiry: now_ms + days*86400000, subscriber: usedAddress,
            //        amountPaid: plan.pricePerDay * BigInt(days),
            //        paymentAsset: { policyId, assetName },
            //        beaconId: CONFIG.beaconPolicyId,
            //        userEncrypted: userEncryptedHex }
            //      (See src/cardano/types.ts: SubscriptionDatum)
            //
            //   3. Mint beacon token:
            //      policy = CONFIG.beaconPolicyId
            //      asset_name = beaconName (hex)
            //      amount = 1
            //      redeemer = BeaconRedeemer::CreateSubscription
            //
            //   4. Lock output at CONFIG.validatorAddress:
            //      value = payment amount + 2 ADA min-UTXO + 1 beacon token
            //      inline datum = serialised SubscriptionDatum (CBOR/Plutus data)
            //
            //   5. Sign with wallet via api.signTx(txCbor, true)
            //
            //   6. Submit via Blockfrost:
            //      POST /tx/submit with Content-Type: application/cbor
            //
            // Example MeshJS sketch (requires @meshsdk/core loaded from CDN):
            //
            //   const mesh = await import('https://cdn.jsdelivr.net/npm/@meshsdk/core@latest/...');
            //   const tx = new mesh.Transaction({ initiator: wallet });
            //   tx.mintAsset(beaconScript, { assetName: beaconName, assetQuantity: '1', ... });
            //   tx.sendLovelace({ address: CONFIG.validatorAddress, datum: { inline: datumCbor } }, amount);
            //   const txCbor = await tx.build();
            //   const signedCbor = await api.signTx(txCbor, true);
            //   const txHash = await submitViaBlockfrost(signedCbor);
            //
            // References:
            //   - https://meshjs.dev/apis/transaction
            //   - https://docs.blockfrost.io/#tag/Cardano-Transactions/POST/tx/submit

            console.log('TODO: build Cardano subscription transaction');
            console.log('  plan:', plan.name, 'days:', days);
            console.log('  userEncryptedHex length:', userEncryptedHex.length, 'chars');
            console.log('  validatorAddress:', CONFIG.validatorAddress);
            console.log('  beaconPolicyId:', CONFIG.beaconPolicyId);

            // Stub: show a placeholder success so the UI is testable
            document.getElementById('result-card').classList.remove('hidden');
            document.getElementById('result-content').innerHTML =
                '<strong>Transaction building not yet implemented.</strong><br>' +
                'Credentials encrypted successfully. MeshJS integration pending.<br>' +
                '<small style="word-break:break-all;opacity:0.7">userEncrypted: ' +
                userEncryptedHex.slice(0, 40) + '...</small>';

            showStatus('subscribe-status', 'Credentials prepared. Transaction building TODO.', 'info');

        } catch (err) {
            console.error('subscribe error:', err);
            showStatus('subscribe-status', (err.message || 'Subscription failed'), 'error');
            updateStep(3, 'error');
            btn.disabled = false;
            btn.textContent = 'Subscribe';
        }
    });

    // ── Initialise ────────────────────────────────────────────────────────

    // Detect wallets immediately
    detectWallets();

    // Start fetching plans in the background (may show before wallet connects)
    loadPlans();

    console.log('BlockHost signup engine (Cardano) loaded');
    console.log('  network:', CONFIG.network);
    console.log('  validatorAddress:', CONFIG.validatorAddress || 'NOT SET');
    console.log('  beaconPolicyId:', CONFIG.beaconPolicyId || 'NOT SET');
    console.log('  serverPublicKey:', CONFIG.serverPublicKey ? CONFIG.serverPublicKey.slice(0, 16) + '...' : 'NOT SET');

})();
