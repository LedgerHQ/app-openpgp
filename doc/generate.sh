#!/bin/bash
set -euo pipefail
# Anchor every operation to the script's own directory so that invoking
# the script from an attacker-controlled CWD cannot feed arbitrary RST or
# template files to Pandoc (CWE-73).
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

NAMES=(user/app-openpgp developer/gpgcard-addon)

OPTIONS=(
    "--standalone"
    "--sandbox"
    "--from=rst"
    "--to=latex"
    "--variable=papersize:A4"
    "--variable=geometry:margin=1in"
    "--variable=fontsize:10pt"
    "--toc"
    "--number-sections"
    "--template=template.latex"
)

for name in "${NAMES[@]}"; do
    dir="${SCRIPT_DIR}/$(dirname -- "${name}")"
    file="$(basename -- "${name}")"
    rm -f "${dir}/${file}.pdf"
    (cd "${dir}"; pandoc "${OPTIONS[@]}" --output="${file}.pdf" "${file}.rst")
done
