#!/bin/bash

rm -f blue-app-monero.pdf blue-app-monero.latex

OUTPUT_FORMAT=rst+raw_tex+line_blocks+citations
if [ "$( uname -s )" = "Darwin" ]; then
    ## `pandoc` on OSX does not support those `rst` extensions but seems to generate the same PDF.
    ## I don't know if it's related to `pandoc` installed with `brew` or recent updates of `pandoc`
    ## For now, only use this on OSX and adapt if necessary.
    OUTPUT_FORMAT=rst
fi
pandoc -s --template=blue-app-openpgp-card.template -f ${OUTPUT_FORMAT} -V geometry:a4paper -V geometry:margin=1in -V fontsize=10pt -t latex --toc -N -o blue-app-openpgp-card.pdf blue-app-openpgp-card.rst
