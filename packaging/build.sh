#!/bin/bash
# Build blockhost-engine-cardano .deb packages
set -e

VERSION="0.1.0"
PKG_NAME="blockhost-engine-cardano_${VERSION}_all"
# Auth-svc template package removed — now maintained by libpam-web3 plugin
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
PKG_DIR="$SCRIPT_DIR/$PKG_NAME"

echo "Building blockhost-engine-cardano v${VERSION}..."

# Clean up build artifacts on exit (success or failure)
cleanup() {
  rm -rf "$PKG_DIR"
  # auth-svc cleanup removed — package now maintained by libpam-web3 plugin
}
trap cleanup EXIT

# Clean and recreate package directory
rm -rf "$PKG_DIR"
mkdir -p "$PKG_DIR"/{DEBIAN,usr/bin,usr/share/blockhost/contracts,lib/systemd/system}

# ============================================
# Install production dependencies
# ============================================
echo ""
echo "Installing production dependencies..."
cp "$PROJECT_DIR/package.json" "$PKG_DIR/usr/share/blockhost/"
cp "$PROJECT_DIR/package-lock.json" "$PKG_DIR/usr/share/blockhost/" 2>/dev/null || true
(cd "$PKG_DIR/usr/share/blockhost" && npm install --production --ignore-scripts --silent)

MODULES_SIZE=$(du -sh "$PKG_DIR/usr/share/blockhost/node_modules" | cut -f1)
echo "  node_modules: $MODULES_SIZE"

# Patch libsodium-wrappers-sumo: remove broken ESM export
# The ESM dist is missing libsodium-sumo.mjs — force CJS fallback
find "$PKG_DIR/usr/share/blockhost/node_modules" -path "*/libsodium-wrappers-sumo/package.json" | while read pkg; do
    python3 -c "
import json, sys
p = json.load(open(sys.argv[1]))
if 'exports' in p and '.' in p['exports']:
    p['exports']['.'].pop('import', None)
    p['exports']['.'].pop('module', None)
    json.dump(p, open(sys.argv[1], 'w'), indent=2)
    print('  Patched: ' + sys.argv[1])
" "$pkg"
done

# ============================================
# Copy TypeScript source
# ============================================
echo ""
echo "Copying TypeScript source..."
cp -r "$PROJECT_DIR/src" "$PKG_DIR/usr/share/blockhost/src"
cp "$PROJECT_DIR/tsconfig.json" "$PKG_DIR/usr/share/blockhost/"

# Scripts (keygen, mint_nft)
mkdir -p "$PKG_DIR/usr/share/blockhost/scripts"
cp "$PROJECT_DIR/scripts/keygen.ts" "$PKG_DIR/usr/share/blockhost/scripts/"
cp "$PROJECT_DIR/scripts/mint_nft.ts" "$PKG_DIR/usr/share/blockhost/scripts/"

# ============================================
# Create CLI wrapper scripts
# ============================================
echo ""
echo "Creating CLI wrappers..."
TSX=/usr/share/blockhost/node_modules/.bin/tsx

cat > "$PKG_DIR/usr/bin/bw" << EOF
#!/bin/sh
exec $TSX /usr/share/blockhost/src/bw/index.ts "\$@"
EOF

cat > "$PKG_DIR/usr/bin/ab" << EOF
#!/bin/sh
exec $TSX /usr/share/blockhost/src/ab/index.ts "\$@"
EOF

cat > "$PKG_DIR/usr/bin/is" << EOF
#!/bin/sh
exec $TSX /usr/share/blockhost/src/is/index.ts "\$@"
EOF

cat > "$PKG_DIR/usr/bin/bhcrypt" << EOF
#!/bin/sh
exec $TSX /usr/share/blockhost/src/bhcrypt.ts "\$@"
EOF

cat > "$PKG_DIR/usr/bin/blockhost-mint-nft" << EOF
#!/bin/sh
exec $TSX /usr/share/blockhost/scripts/mint_nft.ts "\$@"
EOF

# ============================================
# Copy Aiken contract artifacts (plutus.json)
# ============================================
echo ""
echo "Copying Aiken contract artifacts..."

PLUTUS_JSON="$PROJECT_DIR/plutus.json"
if [ -f "$PLUTUS_JSON" ]; then
    cp "$PLUTUS_JSON" "$PKG_DIR/usr/share/blockhost/contracts/plutus.json"
    echo "  Copied: plutus.json"
else
    echo "  WARNING: Not found: $PLUTUS_JSON"
fi

# ============================================
# Create DEBIAN control files
# ============================================
echo ""
echo "Creating DEBIAN control files..."

# Create DEBIAN/control
cat > "$PKG_DIR/DEBIAN/control" << EOF
Package: blockhost-engine-cardano
Version: ${VERSION}
Section: admin
Priority: optional
Architecture: all
Depends: blockhost-common (>= 0.1.0), nodejs (>= 22), python3 (>= 3.10)
Provides: bhcrypt, blockhost-engine
Conflicts: blockhost-engine
Recommends: blockhost-provisioner-proxmox (>= 0.1.0) | blockhost-provisioner-libvirt (>= 0.1.0)
Maintainer: Blockhost <admin@blockhost.io>
Description: Cardano engine for Blockhost VM hosting
 Blockhost Engine provides the core subscription management system on Cardano:
 - Aiken smart contract artifacts (plutus.json)
 - Blockchain event monitor service (TypeScript, runs via tsx on Node.js)
 - Event handlers for VM provisioning and NFT minting
 - CLI tools: bw (wallet), ab (addressbook), is (identity), bhcrypt (crypto)
 - Installer wizard plugin for blockchain configuration
 .
 Ships TypeScript source with production node_modules. Runs via tsx.
EOF

# Create DEBIAN/postinst
cat > "$PKG_DIR/DEBIAN/postinst" << 'EOF'
#!/bin/bash
set -e

case "$1" in
    configure)
        if [ -d /run/systemd/system ]; then
            systemctl daemon-reload || true
        fi

        echo ""
        echo "=========================================="
        echo "  blockhost-engine-cardano installed"
        echo "=========================================="
        echo ""
        echo "Next steps:"
        echo "1. Run the installer wizard, or manually:"
        echo "   blockhost-deploy-contracts"
        echo "2. Update /etc/blockhost/blockhost.yaml with contract addresses"
        echo "3. sudo systemctl enable --now blockhost-monitor"
        echo ""
        ;;
esac
exit 0
EOF

# Create DEBIAN/prerm
cat > "$PKG_DIR/DEBIAN/prerm" << 'EOF'
#!/bin/bash
set -e
case "$1" in
    remove|upgrade|deconfigure)
        if [ -d /run/systemd/system ]; then
            systemctl stop blockhost-monitor 2>/dev/null || true
            systemctl disable blockhost-monitor 2>/dev/null || true
        fi
        ;;
esac
exit 0
EOF

# Create DEBIAN/postrm
cat > "$PKG_DIR/DEBIAN/postrm" << 'EOF'
#!/bin/bash
set -e
case "$1" in
    purge)
        rm -rf /var/lib/blockhost/cardano 2>/dev/null || true
        ;;
esac
if [ -d /run/systemd/system ]; then
    systemctl daemon-reload || true
fi
exit 0
EOF

chmod 755 "$PKG_DIR/DEBIAN/postinst" "$PKG_DIR/DEBIAN/prerm" "$PKG_DIR/DEBIAN/postrm"

# ============================================
# Copy application files
# ============================================
echo "Copying files..."

# Bin scripts
cp "$PROJECT_DIR/scripts/deploy-contracts" "$PKG_DIR/usr/bin/blockhost-deploy-contracts"
cp "$PROJECT_DIR/scripts/generate-signup-page" "$PKG_DIR/usr/bin/blockhost-generate-signup"
chmod 755 "$PKG_DIR/usr/bin/"*

# Install root agent action plugins
mkdir -p "$PKG_DIR/usr/share/blockhost/root-agent-actions"
cp "$PROJECT_DIR/root-agent-actions/wallet.py" "$PKG_DIR/usr/share/blockhost/root-agent-actions/"

# Install engine wizard plugin (Python module + templates)
WIZARD_SRC="$PROJECT_DIR/blockhost/engine_cardano"
WIZARD_DST="$PKG_DIR/usr/lib/python3/dist-packages/blockhost/engine_cardano"
mkdir -p "$WIZARD_DST/templates/engine_cardano"
cp "$WIZARD_SRC/__init__.py" "$WIZARD_DST/"
cp "$WIZARD_SRC/wizard.py" "$WIZARD_DST/"
if ls "$WIZARD_SRC/templates/engine_cardano/"*.html &>/dev/null; then
    cp "$WIZARD_SRC/templates/engine_cardano/"*.html "$WIZARD_DST/templates/engine_cardano/"
fi
if [ -d "$WIZARD_SRC/static" ] && ls "$WIZARD_SRC/static/"* &>/dev/null; then
    mkdir -p "$WIZARD_DST/static"
    cp "$WIZARD_SRC/static/"* "$WIZARD_DST/static/"
fi

# Install engine manifest
cp "$PROJECT_DIR/engine.json" "$PKG_DIR/usr/share/blockhost/engine.json"

# Install first-boot hook (if present)
mkdir -p "$PKG_DIR/usr/share/blockhost/engine-hooks"
if [ -f "$PROJECT_DIR/scripts/first-boot-hook.sh" ]; then
    cp "$PROJECT_DIR/scripts/first-boot-hook.sh" "$PKG_DIR/usr/share/blockhost/engine-hooks/first-boot.sh"
    chmod 755 "$PKG_DIR/usr/share/blockhost/engine-hooks/first-boot.sh"
fi

# Static resources (signup page template + engine)
cp "$PROJECT_DIR/scripts/signup-template.html" "$PKG_DIR/usr/share/blockhost/"
cp "$PROJECT_DIR/scripts/signup-engine.js" "$PKG_DIR/usr/share/blockhost/"

# Systemd service
cp "$PROJECT_DIR/examples/blockhost-monitor.service" "$PKG_DIR/lib/systemd/system/blockhost-monitor.service"

# ============================================
# Build host package
# ============================================
echo ""
echo "Building package..."
dpkg-deb --build "$PKG_DIR"

echo ""
echo "=========================================="
echo "Package built: $SCRIPT_DIR/${PKG_NAME}.deb"
echo "=========================================="
dpkg-deb --info "$SCRIPT_DIR/${PKG_NAME}.deb"

# Show what's included
echo ""
echo "Package contents:"
echo "  /usr/share/blockhost/src/          - TypeScript source"
echo "  /usr/share/blockhost/scripts/      - keygen.ts, mint_nft.ts"
echo "  /usr/share/blockhost/node_modules/ - Production dependencies ($MODULES_SIZE)"
echo "  /usr/bin/bw                        - Blockwallet CLI wrapper (tsx)"
echo "  /usr/bin/ab                        - Addressbook CLI wrapper (tsx)"
echo "  /usr/bin/is                        - Identity predicate CLI wrapper (tsx)"
echo "  /usr/bin/bhcrypt                   - Crypto tool CLI wrapper (tsx)"
echo "  /usr/bin/blockhost-deploy-contracts - Contract deployer script"
echo "  /usr/bin/blockhost-mint-nft        - NFT minting CLI wrapper (tsx)"
echo "  /usr/bin/blockhost-generate-signup  - Signup page generator"
echo "  /usr/share/blockhost/signup-engine.js - Signup page engine bundle"
echo "  /usr/lib/python3/dist-packages/blockhost/engine_cardano/ - Engine wizard plugin"
echo "  /usr/share/blockhost/engine.json   - Engine manifest"
echo "  /usr/share/blockhost/contracts/    - Aiken contract artifacts"
echo "  /lib/systemd/system/               - Systemd service unit"

# Contract artifacts status
echo ""
echo "Contract artifacts:"
for f in "$PKG_DIR/usr/share/blockhost/contracts/"*; do
    [ -f "$f" ] && echo "  $(basename "$f") ($(du -h "$f" | cut -f1))"
done

# Copy to packages/host/ if the parent project structure exists
PACKAGES_HOST_DIR="$(dirname "$PROJECT_DIR")/blockhost-installer/packages/host"
if [ -d "$(dirname "$PACKAGES_HOST_DIR")" ]; then
    mkdir -p "$PACKAGES_HOST_DIR"
    cp "$SCRIPT_DIR/${PKG_NAME}.deb" "$PACKAGES_HOST_DIR/"
    echo ""
    echo "Copied to: $PACKAGES_HOST_DIR/${PKG_NAME}.deb"
fi

# Auth-svc template package (blockhost-auth-svc) removed.
# Now maintained by the libpam-web3 Cardano plugin submodule.
# See: cardano-auth-plugin.zip for the reference implementation.
