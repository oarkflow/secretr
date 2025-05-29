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

BINARY_NAME="secretr-${OS}-${ARCH}"

#--------------------------------------------------
# Define Base URL and download URL (update BASE_URL accordingly)
#--------------------------------------------------
BASE_URL="https://example.com/secretr"  # change to your build hosting URL
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
    echo "Installing secretr to /usr/local/bin (sudo may be required)"
    sudo install -m 755 "$EXE" /usr/local/bin/secretr
else
    echo "For Windows, please move ${EXE} to a folder in your PATH."
fi

#--------------------------------------------------
# Create Desktop/Icon shortcut as applicable
#--------------------------------------------------
if [[ "$OS" == "linux" ]]; then
    DESKTOP_FILE="$HOME/.local/share/applications/secretr.desktop"
    echo "Creating desktop entry at ${DESKTOP_FILE}"
    mkdir -p "$(dirname "$DESKTOP_FILE")"
    cat > "$DESKTOP_FILE" <<EOF
[Desktop Entry]
Version=1.0
Type=Application
Name=Secretr
Exec=/usr/local/bin/secretr
Icon=${TMP_DIR}/secretr.png
Terminal=false
EOF
    # Download icon from assets directory "secretr.png"
    ICON_URL="${BASE_URL}/assets/secretr.png"
    if curl -fLo "${TMP_DIR}/secretr.png" "$ICON_URL"; then
        echo "Icon downloaded successfully."
    else
        echo "Warning: Icon download failed."
    fi
elif [[ "$OS" == "darwin" ]]; then
    echo "Installing secretr to /Applications/Secretr.app"
    # Optionally install binary to /usr/local/bin for terminal usage
    sudo install -m 755 "$EXE" /usr/local/bin/secretr
    APP_BUNDLE="/Applications/Secretr.app"
    mkdir -p "${APP_BUNDLE}/Contents/MacOS"
    mkdir -p "${APP_BUNDLE}/Contents/Resources"
    cp "$EXE" "${APP_BUNDLE}/Contents/MacOS/Secretr"
    cat > "${APP_BUNDLE}/Contents/Info.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleName</key>
    <string>Secretr</string>
    <key>CFBundleExecutable</key>
    <string>Secretr</string>
    <key>CFBundleIdentifier</key>
    <string>com.example.Secretr</string>
    <key>CFBundleVersion</key>
    <string>1.0</string>
</dict>
</plist>
EOF
    echo "Secretr.app created at ${APP_BUNDLE}"
else
    echo "For Windows, please move ${EXE} to a folder in your PATH."
fi

#--------------------------------------------------
# Cleanup
#--------------------------------------------------
rm -rf "${TMP_DIR}"
echo "Installation complete."
