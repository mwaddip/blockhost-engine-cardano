"""Root agent action: generate Cardano wallet."""

import subprocess
import json
import os

ACTIONS = {}

def generate_wallet(params):
    """Generate a new Cardano wallet and save the key."""
    name = params.get("name")
    if not name:
        return {"ok": False, "error": "missing name parameter"}

    # Security: validate name
    import re
    if not re.match(r'^[a-z0-9-]{1,32}$', name):
        return {"ok": False, "error": f"invalid wallet name: {name}"}

    # Deny reserved names
    DENY_NAMES = frozenset({'admin', 'server', 'dev', 'broker'})
    if name in DENY_NAMES:
        return {"ok": False, "error": f"reserved name: {name}"}

    key_path = f"/etc/blockhost/{name}.key"
    if os.path.exists(key_path):
        return {"ok": False, "error": f"key already exists: {key_path}"}

    # Generate wallet using keygen.js
    try:
        network = os.environ.get("CARDANO_NETWORK", "preprod")
        result = subprocess.run(
            ["node", "/usr/share/blockhost/keygen.js", "--network", network],
            capture_output=True,
            text=True,
            timeout=30,
        )
        if result.returncode != 0:
            return {"ok": False, "error": f"keygen failed: {result.stderr}"}

        wallet = json.loads(result.stdout)
        mnemonic = wallet["mnemonic"]
        address = wallet["address"]

        # Save mnemonic to key file (root:blockhost 0640, same as deployer.key)
        import grp
        with open(key_path, "w") as f:
            f.write(mnemonic)
        gid = grp.getgrnam("blockhost").gr_gid
        os.chown(key_path, 0, gid)
        os.chmod(key_path, 0o640)

        return {"ok": True, "address": address}
    except Exception as e:
        return {"ok": False, "error": str(e)}

ACTIONS["generate-wallet"] = generate_wallet
