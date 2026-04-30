#!/bin/bash
set -e

if [ -f /corsaro/swiftcreds ]; then
        source /corsaro/swiftcreds
fi

if [ ! -f /corsaro/baseconfig.yaml ]; then
        echo "Please mount a corsarotrace config file at /corsaro/baseconfig.yaml"
        exit 1
fi

cp /corsaro/baseconfig.yaml /corsaro/config.yaml
if [[ $# -gt 0 ]]; then
        sed -i "s#PCAPURI#${1}#" /corsaro/config.yaml
fi

exec /usr/local/bin/corsarotrace -c /corsaro/config.yaml
