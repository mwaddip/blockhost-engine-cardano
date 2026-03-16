(function(){
let api = null;  // CIP-30 API handle
let usedAddress = '';

const $ = id => document.getElementById(id);
const show = (id, v=true) => $(id).classList.toggle('hidden', !v);
const status = (msg, type='success') => {
  const s = $('status');
  s.textContent = msg;
  s.className = 'status ' + type;
  show('status');
};

// Parse ?session= query parameter for callback mode
const sessionId = (new URLSearchParams(window.location.search)).get('session');

// Detect available CIP-30 wallets
function detectWallets() {
  const walletList = $('wallet-list');
  const cardano = window.cardano;
  if (!cardano) {
    show('no-wallets');
    return;
  }

  const known = ['eternl', 'nami', 'lace', 'flint', 'typhon', 'yoroi', 'gerowallet', 'nufi'];
  let found = 0;

  for (const name of known) {
    if (cardano[name]) {
      const btn = document.createElement('button');
      btn.className = 'wallet-btn';
      btn.textContent = cardano[name].name || name;
      btn.onclick = () => connectWallet(name);
      walletList.appendChild(btn);
      found++;
    }
  }

  // Also check for any other CIP-30 wallets
  for (const key of Object.keys(cardano)) {
    if (!known.includes(key) && cardano[key] && typeof cardano[key].enable === 'function') {
      const btn = document.createElement('button');
      btn.className = 'wallet-btn';
      btn.textContent = cardano[key].name || key;
      btn.onclick = () => connectWallet(key);
      walletList.appendChild(btn);
      found++;
    }
  }

  if (found === 0) {
    show('no-wallets');
  }
}

async function connectWallet(name) {
  try {
    api = await window.cardano[name].enable();
    const addresses = await api.getUsedAddresses();
    if (addresses.length === 0) {
      const unused = await api.getUnusedAddresses();
      usedAddress = unused[0] || '';
    } else {
      usedAddress = addresses[0];
    }

    // Display truncated address
    const display = usedAddress.length > 20
      ? usedAddress.slice(0, 12) + '...' + usedAddress.slice(-8)
      : usedAddress;
    $('wallet').textContent = 'Connected: ' + display;
    show('connect-section', false);
    show('main-section');
    show('status', false);

    if (sessionId) await loadSession();
  } catch(e) {
    status('Connection rejected: ' + e.message, 'error');
  }
}

async function loadSession() {
  try {
    const res = await fetch('/auth/pending/' + sessionId);
    if (!res.ok) return;
    const data = await res.json();
    if (data.otp) { $('code').value = data.otp; $('code').readOnly = true; }
    if (data.machine_id) { $('machine').value = data.machine_id; $('machine').readOnly = true; }
  } catch(e) { /* fall through to manual mode */ }
}

async function sign() {
  const code = $('code').value.trim();
  const machine = $('machine').value.trim();
  if (!code) { status('Enter OTP code', 'error'); return; }
  if (!machine) { status('Enter machine ID', 'error'); return; }
  if (!api) { status('No wallet connected', 'error'); return; }

  const msg = 'Authenticate to ' + machine + ' with code: ' + code;

  try {
    $('sign').disabled = true;
    $('sign').textContent = 'Signing...';

    // CIP-30 signData: address (hex), payload (hex-encoded message)
    const msgHex = Array.from(new TextEncoder().encode(msg))
      .map(b => b.toString(16).padStart(2, '0')).join('');

    const result = await api.signData(usedAddress, msgHex);
    // result = { signature: hex (COSE_Sign1), key: hex (COSE_Key) }

    // If callback session, POST signature back to server
    if (sessionId) {
      try {
        const cb = await fetch('/auth/callback/' + sessionId, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            signature: result.signature,
            key: result.key,
            otp: code,
            machineId: machine,
          }),
        });
        if (cb.ok) {
          show('sign-form', false);
          show('sign-result', false);
          status('Signature sent! Press Enter in your terminal.', 'success');
          return;
        }
      } catch(e) { /* fall through to manual copy mode */ }
    }

    // Manual mode: show the structured JSON for copy-paste
    const sigData = JSON.stringify({
      chain: 'cardano',
      signature: result.signature,
      public_key: result.key,
      otp: code,
      machine_id: machine,
    });
    $('sig').textContent = sigData;
    show('sign-form', false);
    show('sign-result');
    status('Signed! Copy and paste the JSON below into your terminal.', 'success');
  } catch(e) {
    status('Signing failed: ' + e.message, 'error');
  } finally {
    $('sign').disabled = false;
    $('sign').textContent = 'Sign Message';
  }
}

function resetSign() {
  show('sign-form');
  show('sign-result', false);
  $('code').value = '';
  $('code').readOnly = false;
  $('machine').readOnly = false;
  show('status', false);
  if (sessionId) loadSession();
}

$('sign').onclick = sign;
$('copy-sig').onclick = () => {
  navigator.clipboard.writeText($('sig').textContent).then(() => {
    const btn = $('copy-sig');
    const orig = btn.textContent;
    btn.textContent = 'Copied!';
    setTimeout(() => btn.textContent = orig, 2000);
  });
};
$('reset-sign').onclick = resetSign;
$('code').onkeypress = e => { if (e.key === 'Enter') $('machine').focus(); };
$('machine').onkeypress = e => { if (e.key === 'Enter') sign(); };

// Auto-detect wallets on load
detectWallets();
})();
