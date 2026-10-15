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
    "--lua-filter=${SCRIPT_DIR}/source.lua"
    "--lua-filter=${SCRIPT_DIR}/admonitions.lua"
)

# pandoc --sandbox does not cover the LaTeX run: keep pdflatex in the doc directory, without shell.
# The shared files of the doc directory (logo) are found through the TeX search path.
export openin_any=p openout_any=p shell_escape=f
export TEXINPUTS="${SCRIPT_DIR}:"

for name in "${NAMES[@]}"; do
    dir="${SCRIPT_DIR}/$(dirname -- "${name}")"
    file="$(basename -- "${name}")"
    rm -f "${dir}/${file}.pdf"
    (cd "${dir}"; pandoc "${OPTIONS[@]}" --output="${file}.pdf" "${file}.rst")
done
