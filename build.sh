#!/usr/bin/env bash
# Add a check at the top to prevent running the script with sudo
if [ "$(id -u)" -eq 0 ]; then
    echo "Please run this script as a normal user; it will use sudo as needed."
    exit 1
fi
set -euo pipefail
export CGO_ENABLED=1
#--------------------------------------------------
# Configuration (override via env)
#--------------------------------------------------
# Auto-detect platform and architecture if not provided
PLATFORMS=${PLATFORMS:-$(uname -s | tr '[:upper:]' '[:lower:]')}
ARCH_RAW=$(uname -m)
if [[ "$ARCH_RAW" == "x86_64" ]]; then
    ARCH_RAW="amd64"
fi
ARCHS=${ARCHS:-"$ARCH_RAW"}
# output folder
OUTDIR=${OUTDIR:-"bin"}
# package artifacts? set to "true" or "false"
PACKAGE=${PACKAGE:-"true"}
# detect version
if git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    VERSION=$(git describe --tags --dirty --always 2>/dev/null || echo "")
fi
VERSION=${VERSION:-$(date +%Y%m%d%H%M%S)}

#--------------------------------------------------
# Prepare arrays for iteration
#--------------------------------------------------
# Split space-separated lists into arrays
read -r -a PLATFORMS_ARR <<< "$PLATFORMS"
read -r -a ARCHS_ARR <<< "$ARCHS"

#--------------------------------------------------
# Helpers
#--------------------------------------------------
function build() {
    local os=$1
    local arch=$2
    local name="vault-${os}-${arch}"
    local ext=""
    local pkgflag=""
    if [[ "$os" == "windows" ]]; then
        ext=".exe"
        pkgflag=".zip"
    elif [[ "$os" == "darwin" ]]; then
        pkgflag=".tar.gz"
    else
        pkgflag=".tar.gz"
    fi

    echo "→ Building ${name}${ext} (version=${VERSION})"
    env GOOS=$os GOARCH=$arch \
        go build \
        -trimpath \
        -ldflags "-s -w -X main.Version=${VERSION}" \
        -o "${OUTDIR}/${name}${ext}" \
        ./cmd

    if [[ "${PACKAGE}" == "true" ]]; then
        if [[ "$os" == "windows" ]]; then
            echo "  Packaging ${name}${pkgflag}"
            pushd "${OUTDIR}" >/dev/null
            zip -qr "${name}.zip" "${name}.exe"
            popd >/dev/null
            mkdir -p "/c/Program Files/Vault"
            mv "${OUTDIR}/${name}.zip" "/c/Program Files/Vault/"
        elif [[ "$os" == "darwin" ]]; then
            local appName="Vault"
            echo "  Packaging ${appName}.app"
            mkdir -p "${OUTDIR}/${appName}.app/Contents/MacOS"
            mkdir -p "${OUTDIR}/${appName}.app/Contents/Resources"
            cp "${OUTDIR}/${name}" "${OUTDIR}/${appName}.app/Contents/MacOS/${appName}"
            cp -R "./assets/." "${OUTDIR}/${appName}.app/Contents/Resources/"
            cat > "${OUTDIR}/${appName}.app/Contents/Info.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleName</key>
    <string>${appName}</string>
    <key>CFBundleExecutable</key>
    <string>${appName}</string>
    <key>CFBundleIdentifier</key>
    <string>com.example.${appName}</string>
    <key>CFBundleVersion</key>
    <string>${VERSION}</string>
</dict>
</plist>
EOF
            mv "${OUTDIR}/${appName}.app" "/Applications/"
        elif [[ "$os" == "linux" ]]; then
            if [[ "${DISTRO:-}" == "deb" ]]; then
                echo "  Packaging ${name} as deb file"
                STAGING_DIR=$(mktemp -d)
                mkdir -p "${STAGING_DIR}/usr/local/bin"
                cp "${OUTDIR}/${name}" "${STAGING_DIR}/usr/local/bin/Vault"
                mkdir -p "${STAGING_DIR}/DEBIAN"
                # Strip leading 'v' from version if present
                local version="${VERSION#v}"
                cat > "${STAGING_DIR}/DEBIAN/control" <<EOF
Package: vault
Version: ${version}
Section: utils
Priority: optional
Architecture: ${arch}
Maintainer: Your Name <you@example.com>
Description: Vault utility
EOF
                dpkg-deb --build "${STAGING_DIR}" "${OUTDIR}/${name}.deb"
                rm -rf "${STAGING_DIR}"
            elif [[ "${DISTRO:-}" == "rpm" ]]; then
                echo "  Packaging ${name} as rpm file"
                if ! command -v fpm >/dev/null 2>&1; then
                    echo "fpm not found. Attempting to install dependencies and fpm..."
                    if [[ -f /etc/debian_version ]]; then
                        sudo apt-get update
                        sudo apt-get install -y ruby ruby-dev build-essential
                    fi
                    gem install --no-document fpm
                fi
                # Using fpm to build rpm; fpm should now be installed
                fpm -s dir -t rpm -n vault -v "${VERSION}" -a "${arch}" -C "${OUTDIR}" --prefix=/usr/local/bin Vault
            else
                echo "  Default packaging for Linux"
                sudo mkdir -p "/usr/local/bin"
                sudo install -m 755 "${OUTDIR}/${name}" /usr/local/bin/Vault
                mkdir -p "$HOME/.local/share/applications"
                cat > "$HOME/.local/share/applications/Vault.desktop" <<EOF
[Desktop Entry]
Name=Vault
Exec=Vault
Icon=${OUTDIR}/${name}.png
Type=Application
Categories=Utility;
EOF
            fi
        else
            echo "  Packaging ${name}${pkgflag}"
            pushd "${OUTDIR}" >/dev/null
            tar czf "${name}.tar.gz" "${name}"
            popd >/dev/null
        fi
    fi
}

#--------------------------------------------------
# Main
#--------------------------------------------------
echo "Building vault (version=${VERSION}) for: ${PLATFORMS_ARR[*]} × ${ARCHS_ARR[*]}"
mkdir -p "${OUTDIR}"

for os in "${PLATFORMS_ARR[@]}"; do
    for arch in "${ARCHS_ARR[@]}"; do
        build "$os" "$arch"
    done
done

echo -e "\nAll builds complete. Binaries (and packages) can be found under ./${OUTDIR}/"
