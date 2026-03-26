"""
Cardano engine wizard plugin for BlockHost installer.

Provides:
- Flask Blueprint with /wizard/cardano route and blockchain API routes
- Pre-provisioner finalization steps: wallet, contracts, chain_config
- Post-nginx finalization steps: mint_nft, plan, revenue_share
- Summary data and template for the summary page
"""

import grp
import json
import os
import re
import subprocess
from pathlib import Path
from typing import Optional

from flask import (
    Blueprint,
    current_app,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

blueprint = Blueprint(
    "engine_cardano",
    __name__,
    template_folder="templates",
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

NETWORK_NAMES = {
    "preprod": "Pre-production Testnet",
    "preview": "Preview Testnet",
    "mainnet": "Cardano Mainnet",
}

CONFIG_DIR = Path("/etc/blockhost")
TESTING_MODE_FILE = CONFIG_DIR / ".testing-mode"

# Slots per day on Cardano (1 slot = 1 second)
SLOTS_PER_DAY = 86_400

# Testing mode: 5 slots per interval (~5 seconds) instead of 1 day
TESTING_INTERVAL_SLOTS = 5

# Cardano bech32 address prefixes: addr1 (mainnet), addr_test1 (testnet networks)
CARDANO_ADDRESS_RE = re.compile(
    r"^(addr1[a-z0-9]{53,}|addr_test1[a-z0-9]{53,})$"
)

# Blockfrost project ID format: network prefix + 32 alphanumeric chars
BLOCKFROST_PROJECT_ID_RE = re.compile(
    r"^(mainnet|preprod|preview)[0-9A-Za-z]{32}$"
)

# Policy ID: 28-byte hex (56 hex chars)
POLICY_ID_RE = re.compile(r"^[0-9a-fA-F]{56}$")


def validate_cardano_address(address: str) -> bool:
    """Validate a Cardano bech32 address (mainnet or testnet)."""
    if not address or not isinstance(address, str):
        return False
    return bool(CARDANO_ADDRESS_RE.match(address.strip()))


# Alias for installer discovery (app.py calls getattr(module, 'validate_address'))
validate_address = validate_cardano_address


def validate_blockfrost_project_id(project_id: str) -> bool:
    """Validate a Blockfrost project ID format."""
    if not project_id or not isinstance(project_id, str):
        return False
    return bool(BLOCKFROST_PROJECT_ID_RE.match(project_id.strip()))


# ---------------------------------------------------------------------------
# Wizard Route
# ---------------------------------------------------------------------------


@blueprint.route("/wizard/cardano", methods=["GET", "POST"])
def wizard_cardano():
    """Cardano blockchain configuration step."""
    if request.method == "POST":
        network = request.form.get("network", "preprod").strip()
        blockfrost_raw = request.form.get("blockfrost_project_id", "").strip()
        # Auto-prepend network prefix if user entered bare 32-char ID
        if blockfrost_raw and not BLOCKFROST_PROJECT_ID_RE.match(blockfrost_raw):
            blockfrost_project_id = network + blockfrost_raw
        else:
            blockfrost_project_id = blockfrost_raw
        admin_wallet = request.form.get("admin_wallet", "").strip()
        wallet_mode = request.form.get("wallet_mode", "generate")
        deployer_mnemonic = request.form.get("deployer_mnemonic", "").strip()
        deployer_address = request.form.get("deployer_address", "").strip()
        contract_mode = request.form.get("contract_mode", "deploy")
        nft_policy_id = request.form.get("nft_policy_id", "").strip()
        subscription_policy_id = request.form.get("subscription_policy_id", "").strip()
        plan_name = request.form.get("plan_name", "Basic VM").strip()
        try:
            plan_price_cents = int(request.form.get("plan_price_cents", 50))
        except (ValueError, TypeError):
            plan_price_cents = 50
        revenue_share_enabled = request.form.get("revenue_share_enabled") == "on"
        try:
            revenue_share_percent = float(request.form.get("revenue_share_percent", 1.0))
        except (ValueError, TypeError):
            revenue_share_percent = 1.0
        revenue_share_dev = request.form.get("revenue_share_dev") == "on"
        revenue_share_broker = request.form.get("revenue_share_broker") == "on"

        session["blockchain"] = {
            "network": network,
            "blockfrost_project_id": blockfrost_project_id,
            "admin_wallet": admin_wallet,
            "wallet_mode": wallet_mode,
            "deployer_mnemonic": deployer_mnemonic,
            "deployer_address": deployer_address,
            "contract_mode": contract_mode,
            "nft_policy_id": nft_policy_id,
            "subscription_policy_id": subscription_policy_id,
            "plan_name": plan_name,
            "plan_price_cents": plan_price_cents,
            "revenue_share_enabled": revenue_share_enabled,
            "revenue_share_percent": revenue_share_percent,
            "revenue_share_dev": revenue_share_dev,
            "revenue_share_broker": revenue_share_broker,
        }

        # Navigate to next wizard step
        try:
            nav = current_app.jinja_env.globals.get("wizard_nav")
            if nav:
                next_info = nav("cardano")
                if next_info and next_info.get("next"):
                    return redirect(url_for(next_info["next"]))
        except Exception:
            pass
        return redirect(url_for("wizard_ipv6"))

    return render_template(
        "engine_cardano/blockchain.html",
        network_names=NETWORK_NAMES,
        blockchain=session.get("blockchain", {}),
    )


# ---------------------------------------------------------------------------
# API Routes
# ---------------------------------------------------------------------------


@blueprint.route("/api/blockchain/generate-wallet", methods=["POST"])
def api_generate_wallet():
    """Generate a new Cardano wallet (CIP-1852 Ed25519 mnemonic).

    Uses bhcrypt keygen CLI (bundled with engine package).
    Returns mnemonic phrase and Cardano bech32 address.
    """
    blockchain = session.get("blockchain", {})
    network = blockchain.get("network", "preprod")

    try:
        result = subprocess.run(
            ["bhcrypt", "keygen", "--network", network],
            capture_output=True,
            text=True,
            timeout=30,
        )

        if result.returncode != 0:
            return jsonify(
                {"error": f"Wallet generation failed: {result.stderr.strip()}"}
            ), 500

        data = json.loads(result.stdout.strip())
        return jsonify({
            "mnemonic": data["mnemonic"],
            "address": data["address"],
        })
    except json.JSONDecodeError:
        return jsonify({"error": "Could not parse wallet output"}), 500
    except FileNotFoundError:
        return jsonify(
            {"error": "bhcrypt not found — is blockhost-engine-cardano installed?"}
        ), 500
    except subprocess.TimeoutExpired:
        return jsonify({"error": "Wallet generation timed out"}), 500


@blueprint.route("/api/blockchain/validate-mnemonic", methods=["POST"])
def api_validate_mnemonic():
    """Validate a mnemonic phrase and return its Cardano address."""
    data = request.get_json()
    mnemonic_phrase = (data or {}).get("mnemonic", "").strip()

    if not mnemonic_phrase:
        return jsonify({"error": "Mnemonic phrase required"}), 400

    words = mnemonic_phrase.split()
    if len(words) not in (12, 15, 18, 21, 24):
        return jsonify(
            {"error": f"Invalid word count ({len(words)}), expected 12-24"}
        ), 400

    # BIP39: only lowercase words and spaces
    if not re.match(r"^[a-z ]+$", mnemonic_phrase):
        return jsonify({"error": "Mnemonic must contain only lowercase words"}), 400

    blockchain = session.get("blockchain", {})
    network = blockchain.get("network", "preprod")

    try:
        result = subprocess.run(
            ["bhcrypt", "validate-mnemonic", "--network", network],
            capture_output=True,
            text=True,
            timeout=30,
            env={**os.environ, "MNEMONIC": mnemonic_phrase},
        )

        if result.returncode == 0 and result.stdout.strip():
            addr_data = json.loads(result.stdout.strip())
            return jsonify({
                "address": addr_data["address"],
                "mnemonic": mnemonic_phrase,
            })
        else:
            return jsonify(
                {"error": result.stderr.strip() or "Invalid mnemonic"}
            ), 400
    except FileNotFoundError:
        return jsonify(
            {"error": "bhcrypt not found — is blockhost-engine-cardano installed?"}
        ), 500
    except subprocess.TimeoutExpired:
        return jsonify({"error": "Validation timed out"}), 500


@blueprint.route("/api/blockchain/balance", methods=["POST"])
def api_balance():
    """Query ADA balance for an address via Koios (proxied to avoid CORS)."""
    data = request.get_json()
    address = (data or {}).get("address", "").strip()
    if not address:
        return jsonify({"error": "Address required"}), 400

    blockchain = session.get("blockchain", {})
    network = blockchain.get("network", "preprod")
    koios = _koios_url(network)

    try:
        import urllib.request

        req = urllib.request.Request(
            f"{koios}/address_info",
            data=json.dumps({"_addresses": [address]}).encode(),
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=15) as resp:
            result = json.loads(resp.read())
            if result and len(result) > 0 and "balance" in result[0]:
                return jsonify({"balance": result[0]["balance"]})
            return jsonify({"balance": "0"})
    except Exception as e:
        return jsonify({"balance": "0", "error": str(e)})


@blueprint.route("/api/blockchain/tip", methods=["GET"])
def api_tip():
    """Get current slot tip via Koios (proxied to avoid CORS)."""
    blockchain = session.get("blockchain", {})
    network = blockchain.get("network", "preprod")
    koios = _koios_url(network)

    try:
        import urllib.request

        req = urllib.request.Request(
            f"{koios}/tip",
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=15) as resp:
            result = json.loads(resp.read())
            if result and len(result) > 0:
                return jsonify(result[0])
            return jsonify({"error": "No tip data"}), 500
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@blueprint.route("/api/blockchain/submit", methods=["POST"])
def api_submit():
    """Submit a signed transaction via Koios (proxied to avoid CORS)."""
    blockchain = session.get("blockchain", {})
    network = blockchain.get("network", "preprod")
    koios = _koios_url(network)

    try:
        import urllib.request

        cbor_data = request.get_data()
        req = urllib.request.Request(
            f"{koios}/submittx",
            data=cbor_data,
            headers={"Content-Type": "application/cbor"},
        )
        with urllib.request.urlopen(req, timeout=30) as resp:
            tx_hash = resp.read().decode().strip().strip('"')
            return jsonify({"txHash": tx_hash})
    except urllib.error.HTTPError as e:
        body = e.read().decode() if hasattr(e, "read") else str(e)
        return jsonify({"error": body}), e.code
    except Exception as e:
        return jsonify({"error": str(e)}), 500


def _koios_url(network: str) -> str:
    # Check for custom Koios URL from environment or existing config
    custom = os.environ.get("KOIOS_URL", "")
    if not custom:
        cfg_path = CONFIG_DIR / "web3-defaults.yaml"
        if cfg_path.exists():
            try:
                import yaml as _y
                _raw = _y.safe_load(cfg_path.read_text()) or {}
                custom = (_raw.get("blockchain") or {}).get("koios_url", "")
            except Exception:
                pass
    if custom:
        return custom
    if network == "mainnet":
        return "https://api.koios.rest/api/v1"
    if network == "preview":
        return "https://preview.koios.rest/api/v1"
    return "https://preprod.koios.rest/api/v1"


# ---------------------------------------------------------------------------
# Summary & UI
# ---------------------------------------------------------------------------


def get_ui_params(session_data: dict) -> dict:
    """Return Cardano-specific UI parameters for wizard templates."""
    blockchain = session_data.get("blockchain", {})
    network = blockchain.get("network", "preprod")
    return {
        "network_name": NETWORK_NAMES.get(network, network),
        "network": network,
    }


def get_summary_data(session_data: dict) -> dict:
    """Return blockchain summary data for the summary page."""
    blockchain = session_data.get("blockchain", {})
    network = blockchain.get("network", "preprod")
    return {
        "network_name": NETWORK_NAMES.get(network, network),
        "network": network,
        "blockfrost_project_id": blockchain.get("blockfrost_project_id", ""),
        "deployer_address": blockchain.get("deployer_address", ""),
        "contract_mode": blockchain.get("contract_mode", "deploy"),
        "nft_policy_id": blockchain.get("nft_policy_id", ""),
        "subscription_policy_id": blockchain.get("subscription_policy_id", ""),
        "plan_name": blockchain.get("plan_name", "Basic VM"),
        "plan_price_cents": blockchain.get("plan_price_cents", 50),
        "revenue_share_enabled": blockchain.get("revenue_share_enabled", False),
    }


def get_wallet_template() -> str:
    """Return the template name for the engine wallet connection page."""
    return "engine_cardano/wallet.html"


def get_summary_template() -> str:
    """Return the template name for the engine summary section."""
    return "engine_cardano/summary_section.html"


def get_nginx_extra_locations(session_data: dict) -> str:
    """Return extra nginx location blocks for the engine.

    Injected by the installer into the server{} block when building nginx config.
    The Cardano engine needs a Koios reverse proxy so the signup page can
    query the chain without CORS issues.
    """
    blockchain = session_data.get("blockchain", {})
    network = blockchain.get("network", "preprod")
    koios = _koios_url(network)

    return f"""
    # Cardano chain API proxy (Koios) — used by signup page
    location /api/v1/ {{
        proxy_pass {koios}/;
        proxy_set_header Host $proxy_host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_ssl_server_name on;
    }}
"""


def get_progress_steps_meta() -> list[dict]:
    """Return step metadata for the progress UI."""
    pre = [
        {"id": "wallet", "label": "Setting up deployer wallet"},
        {"id": "contracts", "label": "Deploying validators"},
        {"id": "chain_config", "label": "Writing configuration files"},
    ]
    post = [
        {"id": "mint_nft", "label": "Minting admin credential NFT"},
        {"id": "plan", "label": "Creating subscription plan"},
        {"id": "revenue_share", "label": "Configuring revenue sharing"},
    ]
    return pre + post


# ---------------------------------------------------------------------------
# Finalization Steps (pre-provisioner)
# ---------------------------------------------------------------------------


def get_finalization_steps() -> list[tuple]:
    """Return pre-provisioner finalization steps.

    Each tuple: (step_id, display_name, callable[, hint])
    """
    return [
        ("wallet", "Setting up deployer wallet", finalize_wallet),
        (
            "contracts",
            "Deploying validators",
            finalize_contracts,
            "(deploys Aiken validators to Cardano — requires funded wallet)",
        ),
        ("chain_config", "Writing configuration files", finalize_chain_config),
    ]


def get_post_finalization_steps() -> list[tuple]:
    """Return post-nginx finalization steps.

    These run after provisioner, ipv6, https, signup, and nginx steps.
    """
    return [
        ("revenue_share", "Configuring revenue sharing", finalize_revenue_share),
        ("collateral", "Setting up Plutus collateral UTxO", finalize_collateral),
        ("mint_nft", "Minting admin credential NFT", finalize_mint_nft),
        ("plan", "Creating subscription plan", finalize_plan),
    ]


# ---------------------------------------------------------------------------
# Helpers (private)
# ---------------------------------------------------------------------------


def _set_blockhost_ownership(path, mode=0o640):
    """Set file to root:blockhost with given mode."""
    try:
        from installer.web.utils import set_blockhost_ownership

        set_blockhost_ownership(path, mode)
    except ImportError:
        os.chmod(str(path), mode)
        try:
            gid = grp.getgrnam("blockhost").gr_gid
            os.chown(str(path), 0, gid)
        except KeyError:
            pass


def _write_yaml(path: Path, data: dict):
    """Write data to YAML file."""
    try:
        from installer.web.utils import write_yaml

        write_yaml(path, data)
    except ImportError:
        try:
            import yaml

            path.write_text(yaml.safe_dump(data, default_flow_style=False))
        except ImportError:
            lines: list[str] = []
            _dict_to_yaml(data, lines, 0)
            path.write_text("\n".join(lines) + "\n")


def _dict_to_yaml(data: dict, lines: list, indent: int):
    """Simple dict to YAML converter (fallback when PyYAML unavailable)."""
    prefix = "  " * indent
    for key, value in data.items():
        if isinstance(value, dict):
            lines.append(f"{prefix}{key}:")
            _dict_to_yaml(value, lines, indent + 1)
        elif isinstance(value, list):
            lines.append(f"{prefix}{key}:")
            for item in value:
                if isinstance(item, dict):
                    lines.append(f"{prefix}  -")
                    _dict_to_yaml(item, lines, indent + 2)
                else:
                    lines.append(f"{prefix}  - {item}")
        elif value is None:
            lines.append(f"{prefix}{key}: null")
        elif isinstance(value, bool):
            lines.append(f"{prefix}{key}: {str(value).lower()}")
        elif isinstance(value, (int, float)):
            lines.append(f"{prefix}{key}: {value}")
        else:
            lines.append(f'{prefix}{key}: "{value}"')


def _discover_bridge() -> str:
    """Read bridge name from first-boot marker or scan /sys/class/net."""
    bridge_file = Path("/run/blockhost/bridge")
    if bridge_file.exists():
        name = bridge_file.read_text().strip()
        if name:
            return name
    for p in Path("/sys/class/net").iterdir():
        if (p / "bridge").is_dir():
            return p.name
    return "br0"


def _script_address(script_hash: str, network: str) -> str:
    """Build a bech32 enterprise script address from a script hash."""
    header = 0x71 if network == "mainnet" else 0x70
    data = bytes([header]) + bytes.fromhex(script_hash)
    # Bech32 encoding (inline — no external dependency)
    CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

    def _bech32_polymod(values: list[int]) -> int:
        GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
        chk = 1
        for v in values:
            b = chk >> 25
            chk = ((chk & 0x1FFFFFF) << 5) ^ v
            for i in range(5):
                chk ^= GEN[i] if ((b >> i) & 1) else 0
        return chk

    def _bech32_hrp_expand(hrp: str) -> list[int]:
        return [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]

    def _convertbits(data: bytes, frombits: int, tobits: int) -> list[int]:
        acc, bits, ret = 0, 0, []
        for value in data:
            acc = (acc << frombits) | value
            bits += frombits
            while bits >= tobits:
                bits -= tobits
                ret.append((acc >> bits) & ((1 << tobits) - 1))
        if bits:
            ret.append((acc << (tobits - bits)) & ((1 << tobits) - 1))
        return ret

    hrp = "addr" if network == "mainnet" else "addr_test"
    words = _convertbits(data, 8, 5)
    polymod = _bech32_polymod(
        _bech32_hrp_expand(hrp) + words + [0, 0, 0, 0, 0, 0]
    ) ^ 1
    checksum = [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]
    return hrp + "1" + "".join(CHARSET[w] for w in words + checksum)


def _bw_env(blockchain: dict) -> dict:
    """Build environment for bw CLI calls."""
    return {
        **os.environ,
        "BLOCKHOST_CONFIG_DIR": str(CONFIG_DIR),
    }


# ---------------------------------------------------------------------------
# Pre-finalization step functions
# ---------------------------------------------------------------------------


def finalize_wallet(config: dict) -> tuple[bool, Optional[str]]:
    """Generate server wallet via bhcrypt keygen and save mnemonic to deployer.key.

    For wallet_mode == 'generate': runs bhcrypt keygen and writes key file.
    For wallet_mode == 'import': validates and writes the provided mnemonic.
    Idempotent: skips write if file exists with matching content.
    """
    try:
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        blockchain = config.get("blockchain", {})
        wallet_mode = blockchain.get("wallet_mode", "generate")
        mnemonic = blockchain.get("deployer_mnemonic", "")
        network = blockchain.get("network", "preprod")

        mnemonic_file = CONFIG_DIR / "deployer.key"

        if wallet_mode == "generate" and not mnemonic:
            # Generate wallet via bhcrypt keygen
            result = subprocess.run(
                ["bhcrypt", "keygen", "--network", network],
                capture_output=True,
                text=True,
                timeout=30,
            )
            if result.returncode != 0:
                return False, f"Wallet generation failed: {result.stderr.strip()}"
            try:
                keygen_data = json.loads(result.stdout.strip())
                mnemonic = keygen_data["mnemonic"]
                blockchain["deployer_mnemonic"] = mnemonic
                blockchain["deployer_address"] = keygen_data.get("address", "")
                config["blockchain"] = blockchain
            except (json.JSONDecodeError, KeyError) as e:
                return False, f"Could not parse keygen output: {e}"

        if not mnemonic:
            return False, "No deployer mnemonic in configuration"

        words = mnemonic.split()
        if len(words) not in (12, 15, 18, 21, 24):
            return False, f"Invalid mnemonic word count ({len(words)})"

        # Idempotent: skip if same mnemonic already written
        if mnemonic_file.exists() and mnemonic_file.read_text().strip() == mnemonic:
            config["_step_result_wallet"] = {
                "address": blockchain.get("deployer_address", ""),
            }
            return True, None

        mnemonic_file.write_text(mnemonic)
        _set_blockhost_ownership(mnemonic_file, 0o640)

        config["_step_result_wallet"] = {
            "address": blockchain.get("deployer_address", ""),
        }
        return True, None
    except FileNotFoundError:
        return False, "bhcrypt not found — is blockhost-engine-cardano installed?"
    except subprocess.TimeoutExpired:
        return False, "Wallet generation timed out"
    except Exception as e:
        return False, str(e)


def finalize_contracts(config: dict) -> tuple[bool, Optional[str]]:
    """Deploy or verify Cardano validators.

    For contract_mode == 'deploy': use blockhost-deploy-contracts.
    For contract_mode == 'existing': verify policy IDs are present.

    Idempotent: skips deployment if policy IDs already recorded in config.
    """
    try:
        blockchain = config.get("blockchain", {})
        contract_mode = blockchain.get("contract_mode", "deploy")
        blockfrost_project_id = blockchain.get("blockfrost_project_id", "")
        network = blockchain.get("network", "preprod")


        if contract_mode == "existing":
            nft = blockchain.get("nft_policy_id", "")
            sub = blockchain.get("subscription_policy_id", "")

            if not nft or not sub:
                return False, "Policy IDs required for existing mode"

            if not POLICY_ID_RE.match(nft):
                return False, f"Invalid NFT policy ID: {nft}"
            if not POLICY_ID_RE.match(sub):
                return False, f"Invalid subscription policy ID: {sub}"

            blockchain["nft_contract"] = nft
            blockchain["subscription_contract"] = sub
            config["blockchain"] = blockchain
            config["_step_result_contracts"] = {
                "nft_policy_id": nft,
                "subscription_policy_id": sub,
            }
            return True, None

        # Deploy mode — idempotent if already have policy IDs
        nft = blockchain.get("nft_policy_id", "")
        sub = blockchain.get("subscription_policy_id", "")
        if nft and sub:
            blockchain["nft_contract"] = nft
            blockchain["subscription_contract"] = sub
            config["blockchain"] = blockchain
            config["_step_result_contracts"] = {
                "nft_policy_id": nft,
                "subscription_policy_id": sub,
            }
            return True, None

        # Need deployer key to be present
        mnemonic_file = CONFIG_DIR / "deployer.key"
        if not mnemonic_file.exists():
            mnemonic = blockchain.get("deployer_mnemonic", "")
            if mnemonic:
                mnemonic_file.write_text(mnemonic)
                _set_blockhost_ownership(mnemonic_file, 0o640)
            else:
                return False, "Deployer mnemonic not available"

        env = {
            **os.environ,
            "CARDANO_NETWORK": network,
        }
        if blockfrost_project_id:
            env["BLOCKFROST_PROJECT_ID"] = blockfrost_project_id

        deploy_script = Path("/usr/bin/blockhost-deploy-contracts")
        if not deploy_script.exists():
            dev_script = Path("/opt/blockhost/scripts/deploy-contracts")
            if dev_script.exists():
                deploy_script = dev_script
            else:
                return False, "blockhost-deploy-contracts not found"

        result = subprocess.run(
            [str(deploy_script)],
            capture_output=True,
            text=True,
            timeout=600,  # 10 min — Cardano tx confirmation
            env=env,
        )

        if result.returncode != 0:
            return False, f"Validator deployment failed: {result.stderr or result.stdout}"

        # Parse key=value output from deploy script
        # Format: subscription_validator_hash=XXXX, beacon_policy_id=XXXX, nft_policy_id=XXXX
        kv: dict[str, str] = {}
        for line in result.stdout.strip().split("\n"):
            line = line.strip()
            if "=" in line:
                key, _, val = line.partition("=")
                val = val.strip()
                if POLICY_ID_RE.match(val) or key.strip() == "beacon_script_cbor":
                    kv[key.strip()] = val
            elif POLICY_ID_RE.match(line):
                # Bare hex line (legacy format)
                kv[f"_bare_{len(kv)}"] = line

        # Extract policy IDs by key name or fall back to positional
        sub = kv.get("subscription_validator_hash", "")
        nft = kv.get("nft_policy_id", "")
        beacon = kv.get("beacon_policy_id", "")

        # Fallback: positional bare hex lines
        if not sub or not nft:
            bare = [v for k, v in kv.items() if k.startswith("_bare_")]
            if len(bare) >= 2:
                sub = sub or bare[0]
                nft = nft or bare[1]

        if sub and nft:
            blockchain["nft_policy_id"] = nft
            blockchain["nft_contract"] = nft               # interface convention
            blockchain["subscription_policy_id"] = sub
            blockchain["subscription_contract"] = sub       # interface convention
            if beacon:
                blockchain["beacon_policy_id"] = beacon
            beacon_cbor = kv.get("beacon_script_cbor", "")
            if beacon_cbor:
                blockchain["beacon_script_cbor"] = beacon_cbor
            ref_store = kv.get("reference_store_hash", "")
            if ref_store:
                blockchain["reference_store_hash"] = ref_store
            config["blockchain"] = blockchain
            config["_step_result_contracts"] = {
                "nft_policy_id": nft,
                "subscription_policy_id": sub,
            }
            return True, None

        return False, f"Expected 2 policy IDs, got {len(kv)}"

    except subprocess.TimeoutExpired:
        return False, "Validator deployment timed out (10 minutes)"
    except Exception as e:
        return False, str(e)


def finalize_chain_config(config: dict) -> tuple[bool, Optional[str]]:
    """Write all blockchain configuration files.

    Files written:
    - web3-defaults.yaml (Blockfrost project ID, network, policy IDs)
    - blockhost.yaml (server, admin, provisioner config)
    """
    try:
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        var_dir = Path("/var/lib/blockhost")
        var_dir.mkdir(parents=True, exist_ok=True)

        blockchain = config.get("blockchain", {})
        provisioner = config.get("provisioner", {})
        blockfrost_project_id = blockchain.get("blockfrost_project_id", "")
        network = blockchain.get("network", "preprod")
        nft_policy_id = blockchain.get("nft_policy_id", "")
        sub_policy_id = blockchain.get("subscription_policy_id", "")
        admin_wallet = config.get("admin_wallet", "") or blockchain.get("admin_wallet", "")
        deployer_address = blockchain.get("deployer_address", "")

        # Read server public key if present
        server_pubkey = ""
        pubkey_file = CONFIG_DIR / "server.pubkey"
        if pubkey_file.exists():
            server_pubkey = pubkey_file.read_text().strip()

        bridge = provisioner.get("bridge") or _discover_bridge()

        # --- web3-defaults.yaml ---
        beacon_policy_id = blockchain.get("beacon_policy_id", "")
        beacon_script_cbor = blockchain.get("beacon_script_cbor", "")

        # Compute subscription validator bech32 address (enterprise script address)
        sub_validator_address = ""
        if sub_policy_id:
            sub_validator_address = _script_address(sub_policy_id, network)

        # Compute reference store bech32 address (enterprise script address)
        ref_store_hash = blockchain.get("reference_store_hash", "")
        ref_store_address = ""
        if ref_store_hash:
            ref_store_address = _script_address(ref_store_hash, network)

        web3_blockchain: dict = {
            "network": network,
            "nft_policy_id": nft_policy_id,
            "nft_contract": nft_policy_id,              # interface convention
            "subscription_policy_id": sub_policy_id,
            "subscription_contract": sub_policy_id,      # interface convention
            "subscription_validator_hash": sub_policy_id, # engine config expects this name
            "subscription_validator_address": sub_validator_address,
            "beacon_policy_id": beacon_policy_id,
            "beacon_script_cbor": beacon_script_cbor,
            "server_public_key": server_pubkey,
            "reference_store_address": ref_store_address,
        }
        if blockfrost_project_id:
            web3_blockchain["blockfrost_project_id"] = blockfrost_project_id
        web3_config: dict = {
            "blockchain": web3_blockchain,
        }

        web3_path = CONFIG_DIR / "web3-defaults.yaml"
        if web3_path.exists():
            try:
                import yaml

                existing = yaml.safe_load(web3_path.read_text()) or {}
                # Replace the blockchain section entirely — don't merge with
                # stale fields from other engines (e.g. EVM chain_id, rpc_url)
                existing["blockchain"] = web3_blockchain
                for section, values in web3_config.items():
                    if section == "blockchain":
                        continue  # already replaced above
                    if isinstance(values, dict) and isinstance(
                        existing.get(section), dict
                    ):
                        existing[section].update(values)
                    else:
                        existing[section] = values
                web3_config = existing
            except ImportError:
                pass
        _write_yaml(web3_path, web3_config)
        _set_blockhost_ownership(web3_path, 0o640)

        # --- blockhost.yaml ---
        public_secret = config.get("admin_public_secret", "blockhost-access")
        bh_config: dict = {
            "server": {
                "address": deployer_address,
                "key_file": "/etc/blockhost/deployer.key",
            },
            "server_public_key": server_pubkey,
            "public_secret": public_secret,
            "subscription_policy_id": sub_policy_id,
        }

        if provisioner:
            bh_config["provisioner"] = {
                "node": provisioner.get("node", ""),
                "bridge": provisioner.get("bridge", bridge),
                "vmid_start": provisioner.get("vmid_start", 100),
                "vmid_end": provisioner.get("vmid_end", 999),
                "gc_grace_days": provisioner.get("gc_grace_days", 7),
            }

        bh_config["admin"] = {
            "wallet_address": admin_wallet,
            "credential_nft_id": 0,
            "max_command_age": 300,
        }

        admin_commands = config.get("admin_commands", {})
        if admin_commands.get("enabled"):
            bh_config["admin"]["destination_mode"] = admin_commands.get(
                "destination_mode", "self"
            )

        bh_path = CONFIG_DIR / "blockhost.yaml"
        _write_yaml(bh_path, bh_config)
        _set_blockhost_ownership(bh_path, 0o640)

        # --- admin-commands.json ---
        if admin_commands.get("enabled") and admin_commands.get("knock_command"):
            commands_db = {
                "commands": {
                    admin_commands["knock_command"]: {
                        "action": "knock",
                        "description": "Open configured ports temporarily",
                        "params": {
                            "allowed_ports": admin_commands.get("knock_ports", [22]),
                            "default_duration": admin_commands.get(
                                "knock_timeout", 300
                            ),
                        },
                    }
                }
            }
            cmd_path = CONFIG_DIR / "admin-commands.json"
            cmd_path.write_text(json.dumps(commands_db, indent=2) + "\n")
            _set_blockhost_ownership(cmd_path, 0o640)

        # --- admin-signature.key ---
        admin_signature = config.get("admin_signature", "")
        if admin_signature:
            sig_file = CONFIG_DIR / "admin-signature.key"
            sig_file.write_text(admin_signature)
            _set_blockhost_ownership(sig_file, 0o640)

        # --- .env ---
        opt_dir = Path("/opt/blockhost")
        opt_dir.mkdir(parents=True, exist_ok=True)
        env_lines = [
            f"CARDANO_NETWORK={network}",
            f"NFT_POLICY_ID={nft_policy_id}",
            f"SUBSCRIPTION_POLICY_ID={sub_policy_id}",
            "DEPLOYER_KEY_FILE=/etc/blockhost/deployer.key",
        ]
        if blockfrost_project_id:
            env_lines.insert(0, f"BLOCKFROST_PROJECT_ID={blockfrost_project_id}")
        env_path = opt_dir / ".env"
        env_path.write_text("\n".join(env_lines) + "\n")
        _set_blockhost_ownership(env_path, 0o640)

        # --- Initialize vms.json if missing ---
        vms_path = var_dir / "vms.json"
        if not vms_path.exists():
            vms_path.write_text(
                json.dumps(
                    {
                        "vms": {},
                        "next_vmid": provisioner.get("vmid_start", 100),
                        "allocated_ips": [],
                        "allocated_ipv6": [],
                    },
                    indent=2,
                )
            )

        config["_step_result_chain_config"] = {
            "message": "Configuration files written"
        }
        return True, None
    except Exception as e:
        return False, str(e)


# ---------------------------------------------------------------------------
# Post-finalization step functions
# ---------------------------------------------------------------------------


def finalize_collateral(config: dict) -> tuple[bool, Optional[str]]:
    """Create an ADA-only UTxO for Plutus script collateral.

    Sends 5 ADA from the deployer wallet to itself, producing a clean
    UTxO with no native tokens.  This UTxO is required as collateral
    for any Plutus validator interaction (minting, collecting, etc.).

    Runs after the addressbook is initialized (revenue_share step) so
    the "server" role is available for bw send.
    """
    try:
        blockchain = config.get("blockchain", {})
        env = _bw_env(blockchain)

        result = subprocess.run(
            ["bw", "send", "5", "ada", "server", "server"],
            capture_output=True,
            text=True,
            timeout=600,  # 10 min — Cardano tx confirmation
            env=env,
        )

        if result.returncode != 0:
            return False, f"Collateral creation failed: {result.stderr or result.stdout}"

        tx_hash = result.stdout.strip()
        config["_step_result_collateral"] = {"tx_hash": tx_hash}

        # Wait for Koios to index the new UTxO so the next step
        # (mint_nft) doesn't query stale inputs.
        import time
        time.sleep(25)

        return True, None
    except FileNotFoundError:
        return False, "bw CLI not found"
    except subprocess.TimeoutExpired:
        return False, "Collateral creation timed out (waited for Cardano confirmation)"
    except Exception as e:
        return False, str(e)


def finalize_mint_nft(config: dict) -> tuple[bool, Optional[str]]:
    """Mint admin credential NFT.

    Calls blockhost-mint-nft with the admin wallet address as owner.
    Idempotent: if NFT already minted (existing contract mode), logs and returns.
    """
    try:
        blockchain = config.get("blockchain", {})
        admin_wallet = (
            config.get("admin_wallet", "")
            or blockchain.get("admin_wallet", "")
        )

        if not admin_wallet:
            return False, "Admin wallet address not configured"

        if not validate_cardano_address(admin_wallet):
            return False, f"Invalid admin wallet address (expected bech32): {admin_wallet}"

        # Build encrypted connection details for the NFT
        user_encrypted = ""
        admin_signature = config.get("admin_signature", "")
        https_cfg = config.get("https", {})
        if not https_cfg:
            https_file = CONFIG_DIR / "https.json"
            if https_file.exists():
                try:
                    https_cfg = json.loads(https_file.read_text())
                except Exception:
                    pass
        server_addr = https_cfg.get("ipv6_address") or https_cfg.get("hostname", "")

        if server_addr and admin_signature:
            connection_details = json.dumps({
                "hostname": server_addr,
                "port": 22,
                "username": "admin",
            })
            try:
                result = subprocess.run(
                    [
                        "bhcrypt", "encrypt-symmetric",
                        "--signature", admin_signature,
                        "--plaintext", connection_details,
                    ],
                    capture_output=True,
                    text=True,
                    timeout=30,
                )
                if result.returncode == 0 and result.stdout.strip():
                    user_encrypted = result.stdout.strip()
                    if user_encrypted.startswith("0x"):
                        user_encrypted = user_encrypted[2:]
            except (FileNotFoundError, subprocess.TimeoutExpired):
                pass

        cmd = [
            "blockhost-mint-nft",
            "--owner-wallet", admin_wallet,
        ]
        if user_encrypted:
            cmd.extend(["--user-encrypted", user_encrypted])

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=600,  # 10 min — Cardano tx confirmation
        )

        if result.returncode != 0:
            return False, f"NFT minting failed: {result.stderr or result.stdout}"

        # stdout is the token ID / asset name
        token_id = result.stdout.strip()
        config["_step_result_mint_nft"] = {
            "token_id": token_id,
            "owner": admin_wallet,
        }
        return True, None
    except subprocess.TimeoutExpired:
        return False, "NFT minting timed out (waited for Cardano confirmation)"
    except Exception as e:
        return False, str(e)


def _is_testing_mode() -> bool:
    """Check if testing mode is enabled (/etc/blockhost/.testing-mode exists)."""
    return TESTING_MODE_FILE.exists()


def _get_interval_slots() -> int:
    """Get the collection interval in slots.

    Testing mode: 5 slots (~5 seconds) for rapid iteration.
    Production:   86400 slots (~1 day).
    """
    if _is_testing_mode():
        return TESTING_INTERVAL_SLOTS
    return SLOTS_PER_DAY


def finalize_plan(config: dict) -> tuple[bool, Optional[str]]:
    """Create default subscription plan via bw CLI.

    In testing mode (/etc/blockhost/.testing-mode exists), the plan uses
    massively shorter intervals (5 slots instead of 86400) so the monitor
    can collect funds every few seconds instead of daily.
    """
    try:
        blockchain = config.get("blockchain", {})
        plan_name = blockchain.get("plan_name", "Basic VM")
        plan_price = blockchain.get("plan_price_cents", 50)
        testing = _is_testing_mode()
        interval_slots = _get_interval_slots()

        if testing:
            plan_name = f"{plan_name} (TEST)"

        env = _bw_env(blockchain)

        cmd = [
            "bw", "plan", "create",
            plan_name,
            str(plan_price),
            "--interval-slots", str(interval_slots),
        ]

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=600,  # 10 min — Cardano tx confirmation
            env=env,
        )

        if result.returncode != 0:
            return False, f"Plan creation failed: {result.stderr or result.stdout}"

        mode_label = f"TESTING MODE: {interval_slots} slots/interval" if testing else f"{interval_slots} slots/interval (~1 day)"
        config["_step_result_plan"] = {
            "plan_name": plan_name,
            "price": f"{plan_price} cents/day",
            "interval_slots": interval_slots,
            "mode": mode_label,
        }
        return True, None
    except FileNotFoundError:
        return False, "bw CLI not found"
    except subprocess.TimeoutExpired:
        return False, "Plan creation timed out (waited for Cardano confirmation)"
    except Exception as e:
        return False, str(e)


def finalize_revenue_share(config: dict) -> tuple[bool, Optional[str]]:
    """Write addressbook.json and revenue-share.json. Enable blockhost-monitor."""
    try:
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        blockchain = config.get("blockchain", {})
        admin_wallet = (
            config.get("admin_wallet", "")
            or blockchain.get("admin_wallet", "")
        )
        deployer_address = blockchain.get("deployer_address", "")

        # Build addressbook entries (Cardano bech32 addresses)
        addressbook: dict = {}

        if admin_wallet:
            addressbook["admin"] = {"address": admin_wallet}

        if deployer_address:
            addressbook["server"] = {
                "address": deployer_address,
                "keyfile": "/etc/blockhost/deployer.key",
            }

        if blockchain.get("revenue_share_dev"):
            addressbook["dev"] = {"address": admin_wallet}

        if blockchain.get("revenue_share_broker"):
            addressbook["broker"] = {"address": admin_wallet}

        # Try ab --init CLI first
        ab_init_used = False
        if admin_wallet and deployer_address:
            try:
                cmd = ["ab", "--init", admin_wallet, deployer_address]
                if blockchain.get("revenue_share_dev"):
                    cmd.append(admin_wallet)
                if blockchain.get("revenue_share_broker"):
                    cmd.append(admin_wallet)
                cmd.append("/etc/blockhost/deployer.key")

                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=30,
                )
                ab_init_used = result.returncode == 0
            except FileNotFoundError:
                pass

        if not ab_init_used:
            ab_path = CONFIG_DIR / "addressbook.json"
            if not ab_path.exists() or not json.loads(ab_path.read_text() or "{}"):
                ab_path.write_text(json.dumps(addressbook, indent=2) + "\n")
                _set_blockhost_ownership(ab_path, 0o640)

        # Write revenue-share.json
        rev_enabled = blockchain.get("revenue_share_enabled", False)
        rev_percent = blockchain.get("revenue_share_percent", 1.0)
        recipients: list[dict] = []

        if rev_enabled:
            active_roles = [
                r for r in ["dev", "broker"]
                if blockchain.get(f"revenue_share_{r}")
            ]
            share_each = rev_percent / max(len(active_roles), 1)
            for role in active_roles:
                recipients.append({"role": role, "percent": share_each})

        rev_config = {
            "enabled": rev_enabled,
            "total_percent": rev_percent if rev_enabled else 0.0,
            "recipients": recipients,
        }

        rev_path = CONFIG_DIR / "revenue-share.json"
        rev_path.write_text(json.dumps(rev_config, indent=2) + "\n")
        _set_blockhost_ownership(rev_path, 0o640)

        # Install and enable blockhost-monitor service
        svc_src = Path("/usr/share/blockhost/examples/blockhost-monitor.service")
        svc_dst = Path("/etc/systemd/system/blockhost-monitor.service")
        if svc_src.exists() and not svc_dst.exists():
            import shutil
            shutil.copy2(str(svc_src), str(svc_dst))
            subprocess.run(["systemctl", "daemon-reload"], capture_output=True, timeout=30)
        subprocess.run(
            ["systemctl", "enable", "blockhost-monitor"],
            capture_output=True,
            timeout=30,
        )

        config["_step_result_revenue_share"] = {
            "message": "Addressbook initialized"
        }
        return True, None
    except Exception as e:
        return False, str(e)
