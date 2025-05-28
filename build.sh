#!/usr/bin/env bash
set -euo pipefail
export CGO_ENABLED=1
#--------------------------------------------------
# Configuration (override via env)
#--------------------------------------------------
# default platforms & architectures (space-separated)
PLATFORMS=${PLATFORMS:-"darwin"}
ARCHS=${ARCHS:-"amd64"}
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
        elif [[ "$os" == "darwin" ]]; then
            local appName="Vault"  # use "Vault" for the app bundle name
            echo "  Packaging ${appName}.app"
            # Create .app bundle structure
            mkdir -p "${OUTDIR}/${appName}.app/Contents/MacOS"
            mkdir -p "${OUTDIR}/${appName}.app/Contents/Resources"
            # Copy binary into the app bundle
            cp "${OUTDIR}/${name}" "${OUTDIR}/${appName}.app/Contents/MacOS/${appName}"
            # Copy assets (expects an existing ./assets folder)
            cp -R "./assets/." "${OUTDIR}/${appName}.app/Contents/Resources/"
            # Create minimal Info.plist
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
