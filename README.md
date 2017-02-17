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

### Cross Compiling Dependencies from Debian / Ubuntu

**Windows**

Supported hosts include:
- x86_64-w64-mingw32
- i686-w64-mingw32

Dependencies:
```
apt-get install gcc-mingw-w64-x86-64 gcc-mingw-w64-i686 g++-mingw-w64-i686 g++-mingw-w64-x86-64
```

```
cd ./depends
make HOST="x86_64-w64-mingw32"
```

Configure command for libstorj-c:
```
PKG_CONFIG_LIBDIR="$(pwd)/depends/build/x86_64-w64-mingw32/lib/pkgconfig" CFLAGS="-DCURL_STATICLIB -I$(pwd)/depends/build/x86_64-w64-mingw32/include -L$(pwd)/depends/build/x86_64-w64-mingw32/lib -static" ./configure --host=x86_64-w64-mingw32 --enable-static --disable-shared --prefix=$(pwd)/depends/build/x86_64-w64-mingw32
```

**ARM GNU/Linux**

Supported hosts include:
- arm-linux-gnueabihf
- aarch64-linux-gnu

Dependencies:
```
apt-get gcc-arm-linux-gnueabihf g++-arm-linux-gnueabihf gcc-aarch64-linux-gnu g++-aarch64-linux-gnu
```

```
cd ./depends
make HOST="arm-linux-gnueabihf"
```

Configure command for libstorj-c:
```
PKG_CONFIG_LIBDIR="$(pwd)/depends/build/arm-linux-gnueabihf/lib/pkgconfig" CFLAGS="-I$(pwd)/depends/build/arm-linux-gnueabihf/include -L$(pwd)/depends/build/arm-linux-gnueabihf/lib -static" ./configure --host=arm-linux-gnueabihf --enable-static --disable-shared --prefix=$(pwd)/depends/build/arm-linux-gnueabihf
```

**GNU/Linux**

Supported hosts include:
- x86_64-pc-linux-gnu
- i686-pc-linux-gnu

```
cd ./depends
make HOST="x86_64-pc-linux-gnu"
```

Configure command for libstorj-c:
```
PKG_CONFIG_LIBDIR="$(pwd)/depends/build/x86_64-pc-linux-gnu/lib/pkgconfig" CFLAGS="-I$(pwd)/depends/build/x86_64-pc-linux-gnu/include -L$(pwd)/depends/build/x86_64-pc-linux-gnu/lib -static" ./configure --host=x86_64-pc-linux-gnu --enable-static --disable-shared --prefix=$(pwd)/depends/build/x86_64-pc-linux-gnu
```

### Compiling Dependencies from OS X

```
cd ./depends
make HOST="x86_64-apple-darwin11"
```

Configure command for libstorj-c:
```
CC=clang CXX=clang++ CFLAGS="-target x86_64-apple-darwin11 -isysroot /Library/Developer/CommandLineTools/SDKs/MacOSX10.12.sdk" PKG_CONFIG_LIBDIR="$(pwd)/depends/build/x86_64-apple-darwin11/lib/pkgconfig" CFLAGS="-I$(pwd)/depends/build/x86_64-apple-darwin11/include -L$(pwd)/depends/build/x86_64-apple-darwin11/lib" ./configure --host=x86_64-apple-darwin11 --enable-static --disable-shared --prefix=$(pwd)/depends/build/x86_64-apple-darwin11
```
