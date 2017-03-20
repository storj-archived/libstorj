libstorj
=======

[![Build Status](https://travis-ci.org/Storj/libstorj.svg?branch=master)](https://travis-ci.org/Storj/libstorj)

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

### Cross Compiling Dependencies from Ubuntu 16.04

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

Many ARM based distributions are based on Debian Jessie that includes libc6@2.19. It may be necessary to cross compile using Ubuntu 14.04. This can be accomplished using chroot (see the documentation at https://help.ubuntu.com/community/BasicChroot).

Once chroot is setup, you'll likely need to install a few additional tools (in addition to the main dependencies listed above):
```
apt-get install git bsdmainutils
```

And then install ARM toolchain dependencies:
```
apt-get install gcc-arm-linux-gnueabihf g++-arm-linux-gnueabihf gcc-aarch64-linux-gnu g++-aarch64-linux-gnu
```

```
cd ./depends
make HOST="arm-linux-gnueabihf"
```

Configure command for libstorj-c:
```
PKG_CONFIG_LIBDIR="$(pwd)/depends/build/arm-linux-gnueabihf/lib/pkgconfig" CFLAGS="-I$(pwd)/depends/build/arm-linux-gnueabihf/include -L$(pwd)/depends/build/arm-linux-gnueabihf/lib -static -std=gnu99" ./configure --host=arm-linux-gnueabihf --enable-static --disable-shared --prefix=$(pwd)/depends/build/arm-linux-gnueabihf
```

**64-bit GNU/Linux**

Supported hosts include:
- x86_64-pc-linux-gnu

```
cd ./depends
make HOST="x86_64-pc-linux-gnu"
```

Configure command for libstorj-c:
```
PKG_CONFIG_LIBDIR="$(pwd)/depends/build/x86_64-pc-linux-gnu/lib/pkgconfig" CFLAGS="-I$(pwd)/depends/build/x86_64-pc-linux-gnu/include -L$(pwd)/depends/build/x86_64-pc-linux-gnu/lib -static" ./configure --host=x86_64-pc-linux-gnu --enable-static --disable-shared --prefix=$(pwd)/depends/build/x86_64-pc-linux-gnu
```

**32-bit GNU/linux**

Supported hosts include:
- i686-pc-linux-gnu

Dependencies:
```
apt-get install gcc-multilib g++-multilib
```

```
cd ./depends
make HOST="i686-pc-linux-gnu"
```

Configure command for libstorj-c:
```
PKG_CONFIG_LIBDIR="$(pwd)/depends/build/i686-pc-linux-gnu/lib/pkgconfig" CFLAGS="-I$(pwd)/depends/build/i686-pc-linux-gnu/include -L$(pwd)/depends/build/i686-pc-linux-gnu/lib -static -m32" LDFLAGS="-m32" ./configure --host=i686-pc-linux-gnu --enable-static --disable-shared --prefix=$(pwd)/depends/build/i686-pc-linux-gnu
```

**Mac OSX**

The Apple SDK `MacOSX10.11.sdk` is needed and is available in [Xcode_7.3.1.dmg](https://developer.apple.com/devcenter/download.action?path=/Developer_Tools/Xcode_7.3.1/Xcode_7.3.1.dmg) *(requires a developer account)*. You can extract the sdk using `./depends/extract-osx-sdk.sh`:

```
apt-get install p7zip-full sleuthkit
./depends/extract-osx-sdk.sh
rm -rf 5.hfs MacOSX10.11.sdk
```

You may also need to symlink `/System/Library/Frameworks/Security.framework` to `/path/to/MacOSX10.11.sdk/System/Library/Frameworks/Security.framework` to have `darwinssl` be enabled during the build.

```
cd ./depends
make HOST="x86_64-apple-darwin11" DARWIN_SDK_PATH="/path/to/MacOSX10.11.sdk"
```

Configure command for libstorj-c:
```
export PATH="$(pwd)/depends/toolchain/build/bin:${PATH}" && PKG_CONFIG_LIBDIR="$(pwd)/depends/build/x86_64-apple-darwin11/lib/pkgconfig" CC=clang CXX=clang++ CFLAGS="-target x86_64-apple-darwin11 -isysroot $(pwd)/depends/MacOSX10.11.sdk -mmacosx-version-min=10.8 -mlinker-version=253.9 -pipe -I$(pwd)/depends/build/x86_64-apple-darwin11/include" LDFLAGS="-L$(pwd)/depends/toolchain/build/lib -L$(pwd)/depends/MacOSX10.11.sdk/usr/lib -L$(pwd)/depends/build/x86_64-apple-darwin11/lib -Wl,-syslibroot $(pwd)/depends/MacOSX10.11.sdk" ./configure --host="x86_64-apple-darwin11" --enable-static --disable-shared --prefix=$(pwd)/depends/build/x86_64-apple-darwin11
```
