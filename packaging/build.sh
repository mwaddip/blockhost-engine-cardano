#!/bin/bash
# Build blockhost-engine-cardano .deb packages
set -e

VERSION="0.1.0"
PKG_NAME="blockhost-engine-cardano_${VERSION}_all"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
PKG_DIR="$SCRIPT_DIR/$PKG_NAME"

echo "Building blockhost-engine-cardano v${VERSION}..."

# Clean up build artifacts on exit (success or failure)
cleanup() {
  rm -rf "$PKG_DIR"
}
trap cleanup EXIT

# Clean and recreate package directory
rm -rf "$PKG_DIR"
mkdir -p "$PKG_DIR"/{DEBIAN,usr/bin,usr/share/blockhost/contracts,lib/systemd/system}

# ============================================
# Bundle TypeScript with esbuild
# ============================================
echo ""
echo "Bundling TypeScript with esbuild..."

# Install dependencies first (needed for bundling)
(cd "$PROJECT_DIR" && npm install --silent)

# Common esbuild flags
ESBUILD_COMMON=(
    --bundle
    --platform=node
    --target=node22
    --minify
    --alias:libsodium-wrappers-sumo=noble-bip32ed25519/sodium
)

# Bundle the monitor
npx esbuild "$PROJECT_DIR/src/monitor/index.ts" \
    "${ESBUILD_COMMON[@]}" \
    --outfile="$PKG_DIR/usr/share/blockhost/monitor.js"

if [ ! -f "$PKG_DIR/usr/share/blockhost/monitor.js" ]; then
    echo "ERROR: Failed to create monitor bundle"
    exit 1
fi
echo "  monitor.js ($(du -h "$PKG_DIR/usr/share/blockhost/monitor.js" | cut -f1))"

# Bundle bw CLI
npx esbuild "$PROJECT_DIR/src/bw/index.ts" \
    "${ESBUILD_COMMON[@]}" \
    --outfile="$PKG_DIR/usr/share/blockhost/bw.js"

if [ ! -f "$PKG_DIR/usr/share/blockhost/bw.js" ]; then
    echo "ERROR: Failed to create bw CLI bundle"
    exit 1
fi
echo "  bw.js ($(du -h "$PKG_DIR/usr/share/blockhost/bw.js" | cut -f1))"

cat > "$PKG_DIR/usr/bin/bw" << 'EOF'
#!/bin/sh
exec node /usr/share/blockhost/bw.js "$@"
EOF

# Bundle ab CLI
npx esbuild "$PROJECT_DIR/src/ab/index.ts" \
    "${ESBUILD_COMMON[@]}" \
    --outfile="$PKG_DIR/usr/share/blockhost/ab.js"

if [ ! -f "$PKG_DIR/usr/share/blockhost/ab.js" ]; then
    echo "ERROR: Failed to create ab CLI bundle"
    exit 1
fi
echo "  ab.js ($(du -h "$PKG_DIR/usr/share/blockhost/ab.js" | cut -f1))"

cat > "$PKG_DIR/usr/bin/ab" << 'EOF'
#!/bin/sh
exec node /usr/share/blockhost/ab.js "$@"
EOF

# Bundle is CLI
npx esbuild "$PROJECT_DIR/src/is/index.ts" \
    "${ESBUILD_COMMON[@]}" \
    --outfile="$PKG_DIR/usr/share/blockhost/is.js"

if [ ! -f "$PKG_DIR/usr/share/blockhost/is.js" ]; then
    echo "ERROR: Failed to create is CLI bundle"
    exit 1
fi
echo "  is.js ($(du -h "$PKG_DIR/usr/share/blockhost/is.js" | cut -f1))"

cat > "$PKG_DIR/usr/bin/is" << 'EOF'
#!/bin/sh
exec node /usr/share/blockhost/is.js "$@"
EOF

# Bundle bhcrypt CLI
npx esbuild "$PROJECT_DIR/src/bhcrypt.ts" \
    "${ESBUILD_COMMON[@]}" \
    --outfile="$PKG_DIR/usr/share/blockhost/bhcrypt.js"

if [ ! -f "$PKG_DIR/usr/share/blockhost/bhcrypt.js" ]; then
    echo "ERROR: Failed to create bhcrypt CLI bundle"
    exit 1
fi
echo "  bhcrypt.js ($(du -h "$PKG_DIR/usr/share/blockhost/bhcrypt.js" | cut -f1))"

cat > "$PKG_DIR/usr/bin/bhcrypt" << 'EOF'
#!/bin/sh
exec node /usr/share/blockhost/bhcrypt.js "$@"
EOF

# Bundle mint_nft CLI
npx esbuild "$PROJECT_DIR/scripts/mint_nft.ts" \
    "${ESBUILD_COMMON[@]}" \
    --outfile="$PKG_DIR/usr/share/blockhost/mint_nft.js"

if [ -f "$PKG_DIR/usr/share/blockhost/mint_nft.js" ]; then
    echo "  mint_nft.js ($(du -h "$PKG_DIR/usr/share/blockhost/mint_nft.js" | cut -f1))"
    cat > "$PKG_DIR/usr/bin/blockhost-mint-nft" << 'EOF'
#!/bin/sh
exec node /usr/share/blockhost/mint_nft.js "$@"
EOF
else
    echo "WARNING: Failed to bundle mint_nft CLI"
fi

# Bundle keygen helper
npx esbuild "$PROJECT_DIR/scripts/keygen.ts" \
    "${ESBUILD_COMMON[@]}" \
    --format=cjs \
    --outfile="$PKG_DIR/usr/share/blockhost/keygen.js"

if [ -f "$PKG_DIR/usr/share/blockhost/keygen.js" ]; then
    echo "  keygen.js ($(du -h "$PKG_DIR/usr/share/blockhost/keygen.js" | cut -f1))"
else
    echo "WARNING: Failed to bundle keygen.js"
fi

chmod 755 "$PKG_DIR/usr/bin/"*

# ============================================
# Copy WASM files required by Lucid (CML)
# ============================================
echo ""
echo "Copying WASM dependencies..."

WASM_FILES=(
    "node_modules/@anastasia-labs/cardano-multiplatform-lib-nodejs/cardano_multiplatform_lib_bg.wasm"
    "node_modules/@lucid-evolution/uplc/dist/node/uplc_tx_bg.wasm"
    "node_modules/@emurgo/cardano-message-signing-nodejs/cardano_message_signing_bg.wasm"
)
for wasm in "${WASM_FILES[@]}"; do
    SRC="$PROJECT_DIR/$wasm"
    if [ -f "$SRC" ]; then
        cp "$SRC" "$PKG_DIR/usr/share/blockhost/"
        echo "  $(basename "$SRC") ($(du -h "$SRC" | cut -f1))"
    else
        echo "  WARNING: Not found: $(basename "$wasm")"
    fi
done

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
 - Blockchain event monitor service (bundled JS, runs on Node.js)
 - Event handlers for VM provisioning and NFT minting
 - CLI tools: bw (wallet), ab (addressbook), is (identity), bhcrypt (crypto)
 - Installer wizard plugin for blockchain configuration
 .
 All TypeScript is bundled into self-contained JS files via esbuild.
EOF

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
echo "  /usr/share/blockhost/monitor.js  - Bundled monitor"
echo "  /usr/share/blockhost/bw.js       - Bundled bw CLI"
echo "  /usr/share/blockhost/ab.js       - Bundled ab CLI"
echo "  /usr/share/blockhost/is.js       - Bundled is CLI"
echo "  /usr/share/blockhost/bhcrypt.js  - Bundled bhcrypt CLI"
echo "  /usr/share/blockhost/mint_nft.js - Bundled mint_nft CLI"
echo "  /usr/share/blockhost/keygen.js   - Bundled keygen helper"
echo "  /usr/bin/bw                      - Blockwallet CLI wrapper"
echo "  /usr/bin/ab                      - Addressbook CLI wrapper"
echo "  /usr/bin/is                      - Identity predicate CLI wrapper"
echo "  /usr/bin/bhcrypt                 - Crypto tool CLI wrapper"
echo "  /usr/bin/blockhost-deploy-contracts - Contract deployer"
echo "  /usr/bin/blockhost-mint-nft      - NFT minting CLI wrapper"
echo "  /usr/bin/blockhost-generate-signup - Signup page generator"
echo "  /usr/share/blockhost/signup-engine.js - Signup page engine"
echo "  /usr/lib/python3/dist-packages/blockhost/engine_cardano/ - Wizard plugin"
echo "  /usr/share/blockhost/engine.json - Engine manifest"
echo "  /usr/share/blockhost/contracts/  - Aiken contract artifacts"
echo "  /lib/systemd/system/             - Systemd service unit"

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
