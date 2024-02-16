#!/bin/bash

NAMES=()
NAMES+=(user/app-openpgp)
NAMES+=(developer/gpgcard-addon)

OPTIONS=()
OPTIONS+=("--standalone")
OPTIONS+=("--from=rst")
OPTIONS+=("--to=latex")
OPTIONS+=("--variable=papersize:A4")
OPTIONS+=("--variable=geometry:margin=1in")
OPTIONS+=("--variable=fontsize:10pt")
OPTIONS+=("--toc")
OPTIONS+=("--number-sections")
OPTIONS+=("--template=template.latex")

for name in "${NAMES[@]}"; do
    rm -f "${name}.pdf"
    dir=$(dirname "${name}")
    file=$(basename "${name}")

    (cd "${dir}"; pandoc ${OPTIONS[@]} --output="${file}.pdf" "${file}.rst")
done
