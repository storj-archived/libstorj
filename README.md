Storj C
=======

[![Build Status](https://travis-ci.org/Storj/libstorj-c.svg?branch=master)](https://travis-ci.org/Storj/libstorj-c)

Asynchronous multi-platform C library and CLI for encrypted file transfer on the Storj network.

## Build

```bash
./autogen.sh
./configure
make
```

To run tests:
```bash
./test/tests
```

To run command line utility:
```bash
./src/storj --help
```

And to install locally:
```
sudo make install
```

### Debian / Ubuntu (16.04) Dependencies:

Development tools:
```bash
apt-get install build-essential libtool autotools-dev automake libmicrohttpd-dev
```

Dependencies:
```bash
apt-get install libcurl4-gnutls-dev nettle-dev libjson-c-dev libuv1-dev
```

### OS X Dependencies (w/ homebrew):

Development tools:
```bash
brew install libtool automake libmicrohttpd pkgconfig
```

Dependencies:
```bash
brew install curl nettle json-c libuv
```

### Cross Compiling Dependencies

There is a make script provided for automating building of dependencies for various hosts.

To build dependencies for a host:
```
cd ./depends
make HOST="x86_64-w64-mingw32"
```

Supported hosts currently include:
- x86_64-w64-mingw32
- i686-w64-mingw32

Dependencies will then be installed with prefix at `./depends/build/x86_64-w64-mingw32/` that can be plugged into the libstorj configure script.
