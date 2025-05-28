#!/usr/bin/env bash
set -euo pipefail

#--------------------------------------------------
# Detect platform and architecture
#--------------------------------------------------
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)
# Normalize architecture
if [[ "$ARCH" == "x86_64" ]]; then
    ARCH="amd64"
fi

echo "Detected OS: $OS, ARCH: $ARCH"

#--------------------------------------------------
# Determine packaging extension and binary name
#--------------------------------------------------
if [[ "$OS" == "linux" ]]; then
    PACKAGE_EXT="tar.gz"
elif [[ "$OS" == "darwin" ]]; then
    PACKAGE_EXT="tar.gz"
elif [[ "$OS" == *"mingw"* || "$OS" == *"cygwin"* || "$OS" == *"msys"* ]]; then
    OS="windows"
    PACKAGE_EXT="zip"
else
    echo "Unsupported OS: $OS"
    exit 1
fi

BINARY_NAME="vault-${OS}-${ARCH}"

#--------------------------------------------------
# Define Base URL and download URL (update BASE_URL accordingly)
#--------------------------------------------------
BASE_URL="https://example.com/vault"  # change to your build hosting URL
DOWNLOAD_URL="${BASE_URL}/${BINARY_NAME}.${PACKAGE_EXT}"

#--------------------------------------------------
# Create temporary directory and download artifact
#--------------------------------------------------
TMP_DIR=$(mktemp -d)
echo "Downloading ${DOWNLOAD_URL} ..."
if ! curl -fLo "${TMP_DIR}/${BINARY_NAME}.${PACKAGE_EXT}" "$DOWNLOAD_URL"; then
    echo "Download failed. Check URL: ${DOWNLOAD_URL}"
    exit 1
fi

#--------------------------------------------------
# Extract the downloaded artifact
#--------------------------------------------------
echo "Extracting package..."
if [[ "$PACKAGE_EXT" == "tar.gz" ]]; then
    tar -xzf "${TMP_DIR}/${BINARY_NAME}.${PACKAGE_EXT}" -C "${TMP_DIR}"
elif [[ "$PACKAGE_EXT" == "zip" ]]; then
    unzip -q "${TMP_DIR}/${BINARY_NAME}.${PACKAGE_EXT}" -d "${TMP_DIR}"
fi

#--------------------------------------------------
# Locate executable in extracted files
#--------------------------------------------------
EXE="${TMP_DIR}/${BINARY_NAME}"
if [[ "$OS" == "windows" ]]; then
    EXE="${TMP_DIR}/${BINARY_NAME}.exe"
fi

if [[ ! -f "$EXE" ]]; then
    echo "Error: Executable not found"
    exit 1
fi

#--------------------------------------------------
# Install the executable
#--------------------------------------------------
if [[ "$OS" != "windows" ]]; then
    echo "Installing vault to /usr/local/bin (sudo may be required)"
    sudo install -m 755 "$EXE" /usr/local/bin/vault
else
    echo "For Windows, please move ${EXE} to a folder in your PATH."
fi

#--------------------------------------------------
# Create Desktop/Icon shortcut as applicable
#--------------------------------------------------
if [[ "$OS" == "linux" ]]; then
    DESKTOP_FILE="$HOME/.local/share/applications/vault.desktop"
    echo "Creating desktop entry at ${DESKTOP_FILE}"
    mkdir -p "$(dirname "$DESKTOP_FILE")"
    cat > "$DESKTOP_FILE" <<EOF
[Desktop Entry]
Version=1.0
Type=Application
Name=Vault
Exec=/usr/local/bin/vault
Icon=${TMP_DIR}/vault.png
Terminal=false
EOF
    # Download icon from assets directory "vault.png"
    ICON_URL="${BASE_URL}/assets/vault.png"
    if curl -fLo "${TMP_DIR}/vault.png" "$ICON_URL"; then
        echo "Icon downloaded successfully."
    else
        echo "Warning: Icon download failed."
    fi
elif [[ "$OS" == "darwin" ]]; then
    echo "Installing vault to /usr/local/bin (sudo may be required)"
    sudo install -m 755 "$EXE" /usr/local/bin/vault
    echo "Creating Vault.app in ~/Applications..."
    APP_DIR="$HOME/Applications/Vault.app/Contents/MacOS"
    mkdir -p "$APP_DIR"
    cat > "$HOME/Applications/Vault.app/Contents/Info.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleExecutable</key>
    <string>vault</string>
    <key>CFBundleIdentifier</key>
    <string>com.example.vault</string>
    <key>CFBundleName</key>
    <string>Vault</string>
    <key>CFBundleVersion</key>
    <string>1.0</string>
    <key>LSUIElement</key>
    <true/>
</dict>
</plist>
EOF
    cp /usr/local/bin/vault "$APP_DIR/vault"
    echo "Vault.app created at ~/Applications/Vault.app"
else
    echo "For Windows, please move ${EXE} to a folder in your PATH."
fi

#--------------------------------------------------
# Cleanup
#--------------------------------------------------
rm -rf "${TMP_DIR}"
echo "Installation complete."
