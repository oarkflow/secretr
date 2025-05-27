#!/usr/bin/env bash
set -euo pipefail
#--------------------------------------------------
# Configuration (override via env)
#--------------------------------------------------
# default platforms & architectures (space-separated)
PLATFORMS=${PLATFORMS:-"linux darwin windows"}
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
        echo "  Packaging ${name}${pkgflag}"
        pushd "${OUTDIR}" >/dev/null
        if [[ "$os" == "windows" ]]; then
            zip -qr "${name}.zip" "${name}.exe"
        else
            tar czf "${name}.tar.gz" "${name}"
        fi
        popd >/dev/null
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
