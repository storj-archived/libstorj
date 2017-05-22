#!/usr/bin/env bash

source /usr/src/emscripten/emsdk_env.sh

emcc -v
cd ./src
emcc rs.c -o rs.js -s EXPORTED_FUNCTIONS="['_reed_solomon_new', '_reed_solomon_encode', '_reed_solomon_decode', '_fec_init', '_reed_solomon_release']"

# Force node environment, even in the browser (since we are using browserify)
sed -i 's/var Module;//g' rs.js
