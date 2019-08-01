#!/usr/bin/env bash
set -ueo pipefail

usage="usage: $0 <serialized API key>"

if [[ $# -ne 1 ]]; then
    echo ${usage}
    exit 1
fi

export TMPDIR=/tmp/
export SATELLITE_0_ADDR=127.0.0.1:10000
export GATEWAY_0_API_KEY=$1

make tests && ./tests && rm ./tests
