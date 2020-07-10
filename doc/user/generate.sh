#!/bin/bash

NAME=blue-app-openpgp-card

rm -f ${NAME}.pdf

OUTPUT_FORMAT=rst+smart

pandoc -s --template=${NAME}.template -f ${OUTPUT_FORMAT} -V geometry:a4paper -V geometry:margin=1in -V fontsize=10pt -t latex --toc -N -o ${NAME}.pdf ${NAME}.rst
