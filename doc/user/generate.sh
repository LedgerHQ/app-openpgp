#!/bin/bash

rm -f blue-app-monero.pdf blue-app-monero.latex

pandoc -s --template=blue-app-openpgp-card.template -f rst+raw_tex+line_blocks+citations -V geometry:a4paper -V geometry:margin=1in -V fontsize=10pt -t latex --toc -N -o blue-app-openpgp-card.pdf blue-app-openpgp-card.rst