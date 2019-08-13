#!/usr/bin/env bash
set -ueo pipefail

###
# sim-cli.sh:
#   + build libstorj cli at ./storj-cli if it doesn't exist
#   + set environment variables for using development defaults
#       and storj-sim satellite address
#   + forwards all cli arguments to libstorj cli
#
#  (see: ./storj-cli --help)
###

export STORJ_BRIDGE=127.0.0.1:10000
export STORJ_DEFAULTS=dev

if [[ ! -f ./storj-cli ]]; then
    make storj-cli
fi

./storj-cli $@