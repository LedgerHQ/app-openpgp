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

# Options common to all pages (images and CSS are embedded for self-contained HTML).
# The sources are read in a sandbox; source.lua limits the embedded images to the doc directory.
COMMON_OPTIONS=(
    "--standalone"
    "--embed-resources"
    "--toc"
    "--toc-depth=3"
    "--number-sections"
    "--to=html5"
    "--css=${CSS}"
    "--metadata=lang:en"
    "--lua-filter=${SCRIPT_DIR}/source.lua"
    "--lua-filter=${SCRIPT_DIR}/admonitions.lua"
)

# Convert a source page: read it in a sandbox (no included file), then write the HTML.
# Usage: convert <format> <source, relative to the doc directory> <title>
convert() {
    local format="$1" src="${SCRIPT_DIR}/$2" title="$3"
    local name
    name="$(basename -- "${src%.*}")"

    echo "Generating ${name}.html..."
    pandoc --sandbox --fail-if-warnings --from="${format}" --to=json "${src}" |
        pandoc "${COMMON_OPTIONS[@]}" \
            --from=json \
            --resource-path="$(dirname -- "${src}")" \
            --output="${OUT_DIR}/${name}.html" \
            --metadata title="${title}"
}

convert rst user/app-openpgp.rst "App OpenPGP User Guide"
convert rst developer/gpgcard-addon.rst "GPG Card Add-on Developer Guide"
convert markdown developer/quick-test.md "App OpenPGP Quick Test"

echo "Done. Output in ${OUT_DIR}/"
