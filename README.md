_**Notice**: Development on libstorj is currently on pause during our v3 rearchitecture. Please see https://github.com/storj/storj for ongoing v3 development._

libstorj
=======

[![storj.io](https://storj.io/img/storj-badge.svg)](https://storj.io)
[![Build Status](https://travis-ci.org/storj/libstorj.svg?branch=master)](https://travis-ci.org/storj/libstorj)
[![GitHub version](https://badge.fury.io/gh/storj%2Flibstorj.svg)](https://badge.fury.io/gh/storj%2Flibstorj)
[![Chat on rocket.chat](https://img.shields.io/badge/chat-rocket.chat-red.svg)](https://community.storj.io/channel/dev)

Asynchronous multi-platform C library and CLI for encrypted file transfer on the Storj network.

_Note: this branch is for compatibility with the V3 storj network (see: [storj/storj](https://github.com/storj/storj))._

## Build

This version of libstorj depends on the libuplink api from [storj/storj](https://github.com/storj/storj).
To build this dependency, make sure you have at least the version of golang that's listed in the [storj/storj readme](https://github.com/storj/storj#install-required-packages) installed.

First, update the storj git submodule:
```bash
git submodule update --init storj
```

Build the cli:
```bash
make storj-cli
```

To run tests:
```bash
(cd storj && go install ./cmd/...)
storj-sim setup
# ...
storj-sim run

# new terminal session
./tests.sh <serialized API key> # generate one from 127.0.0.1:10002
```

To run command line utility:
```bash
./storj-cli --help

# You need to set STORJ_BRIDGE to the satellite address you want to talk
#   to (e.g.: storj-sim satellite, below)
# export STORJ_BRIDGE=127.0.0.1:10000
#
# For convenience, ./sim-cli.sh will call the cli binary with all arguments and
# the STORJ_BRIDGE env var set to work with storj-sim. If the cli binary doesn't
# exists, it is built.
#
# ./sim-cli.sh --help

# You can set STORJ_KEYPASS to your cli settings file passphrase to avoid
#   having to type it in every time.
# export STORJ_KEYPASS=

```


### Debian / Ubuntu (16.04) Dependencies:

Development tools:
```bash
apt-get install build-essential bsdmainutils
```

Dependencies:
```bash
apt-get install nettle-dev libjson-c-dev libuv1-dev
```

### OS X Dependencies (w/ homebrew):

Dependencies:
```bash
brew install curl nettle json-c libuv
```

------
