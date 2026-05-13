#!/bin/bash
set -euo pipefail
# Anchor every operation to the script's own directory (CWE-73).
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT_DIR="${SCRIPT_DIR}/html/build"
CSS="${SCRIPT_DIR}/html/style.css"

mkdir -p "${OUT_DIR}"

# Copy static sources into the build directory
cp "${SCRIPT_DIR}/html/index.html" "${OUT_DIR}/index.html"
cp "${CSS}" "${OUT_DIR}/style.css"

# Options common to all pages (images and CSS are embedded for self-contained HTML)
COMMON_OPTIONS=(
    "--standalone"
    "--embed-resources"
    "--toc"
    "--toc-depth=3"
    "--number-sections"
    "--to=html5"
    "--css=${CSS}"
    "--metadata=lang:en"
    "--lua-filter=${SCRIPT_DIR}/admonitions.lua"
)

echo "Generating app-openpgp.html..."
pandoc "${COMMON_OPTIONS[@]}" \
    --from=rst \
    --resource-path="${SCRIPT_DIR}/user" \
    --output="${OUT_DIR}/app-openpgp.html" \
    --metadata title="App OpenPGP User Guide" \
    "${SCRIPT_DIR}/user/app-openpgp.rst"

echo "Generating gpgcard-addon.html..."
pandoc "${COMMON_OPTIONS[@]}" \
    --from=rst \
    --resource-path="${SCRIPT_DIR}/developer" \
    --output="${OUT_DIR}/gpgcard-addon.html" \
    --metadata title="GPG Card Add-on Developer Guide" \
    "${SCRIPT_DIR}/developer/gpgcard-addon.rst"

echo "Generating quick-test.html..."
pandoc "${COMMON_OPTIONS[@]}" \
    --from=markdown \
    --resource-path="${SCRIPT_DIR}/developer" \
    --output="${OUT_DIR}/quick-test.html" \
    --metadata title="App OpenPGP Quick Test" \
    "${SCRIPT_DIR}/developer/quick-test.md"

echo "Done. Output in ${OUT_DIR}/"
