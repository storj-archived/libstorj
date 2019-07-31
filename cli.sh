#!/usr/bin/env bash
set -ueo pipefail

export STORJ_BRIDGE=127.0.0.1:10000

if [[ ! -f ./cli ]]; then
    make cli
fi

./cli $@