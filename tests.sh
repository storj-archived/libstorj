#!/usr/bin/env bash
set -ueo pipefail

export TMPDIR=/tmp/
export SATELLITE_0_ADDR=127.0.0.1:10000
export GATEWAY_0_API_KEY=$(storj-sim network env | grep GATEWAY_0_API_KEY | sed 's,GATEWAY_0_API_KEY=,,')

make tests && ./tests && rm ./tests
