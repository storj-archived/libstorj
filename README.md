_**Notice**: Development on libstorj is currently on pause during our v3 rearchitecture. Please see https://github.com/storj/storj for ongoing v3 development._

libstorj
=======

[![storj.io](https://storj.io/img/storj-badge.svg)](https://storj.io)
[![Build Status](https://travis-ci.org/storj/libstorj.svg?branch=master)](https://travis-ci.org/storj/libstorj)
[![GitHub version](https://badge.fury.io/gh/storj%2Flibstorj.svg)](https://badge.fury.io/gh/storj%2Flibstorj)
[![Chat on rocket.chat](https://img.shields.io/badge/chat-rocket.chat-red.svg)](https://community.storj.io/channel/dev)

Asynchronous multi-platform C library and CLI for encrypted file transfer on the Storj network.

## Feature Highlights

- Asynchronous I/O with concurrent peer-to-peer network requests for shards
- Erasure encoding with reed solomon for data durability
- Robust handling of shard transfers by selecting alternative sources
- File integrity and authenticity verified with HMAC-SHA512
- File encryption with AES-256-CTR
- File name and bucket name encryption with AES-256-GCM
- Proxy support with SOCKS5, SOCKS4, SOCKS4a
- Asynchronous progress updates in bytes per file
- Transfers can be cleanly canceled per file
- Seed based file encryption key for portability between devices
- Reference implementation for [SIP5](https://github.com/Storj/sips/blob/master/sip-0005.md) file standard

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
storj-sim run &
./tests.sh <serialized API key> # generate one from 127.0.0.1:10002
```

To run command line utility:
```bash
./storj-cli --help
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
