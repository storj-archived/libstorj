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
make HOST="x86_64-w64-mingw32" CA_BUNDLE="/path/to/ca-certificates.crt"
```
Note: CA_BUNDLE is optional and will default to use `/etc/ssl/certs/ca-certificates.crt`

Dependencies will then be installed with prefix at `./depends/build/x86_64-w64-mingw32/` that can be plugged into the libstorj configure script.

#### Build MinGW (Windows)

Supported hosts include:
- x86_64-w64-mingw32
- i686-w64-mingw32

Dependencies:
```
apt-get install gcc-mingw-w64-x86-64 gcc-mingw-w64-i686 g++-mingw-w64-i686 g++-mingw-w64-x86-64
```

Configure command for libstorj-c:
```
PKG_CONFIG_LIBDIR="$(pwd)/depends/build/x86_64-w64-mingw32/lib/pkgconfig" CFLAGS="-DCURL_STATICLIB -I$(pwd)/depends/build/x86_64-w64-mingw32/include -L$(pwd)/depends/build/x86_64-w64-mingw32/lib -static" ./configure --host=x86_64-w64-mingw32 --enable-static --disable-shared --prefix=$(pwd)/depends/build/x86_64-w64-mingw32
```
