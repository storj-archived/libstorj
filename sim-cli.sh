#!/usr/bin/env bash
set -ueo pipefail

export STORJ_BRIDGE=127.0.0.1:10000
export STORJ_DEFAULTS=dev

if [[ ! -f ./storj-cli ]]; then
    make storj-cli
fi

./storj-cli $@