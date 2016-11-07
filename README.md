Storj C
=======

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

### Debian / Ubuntu (16.04) Dependencies:

```bash
apt-get install build-essential libtool autotools-dev automake
apt-get install libneon27-gnutls-dev nettle-dev libwebsockets-dev libjson-c-dev
```

### OS X Dependencies (w/ homebrew):

```bash
brew install libtool automake
brew install neon nettle libwebsockets json-c
```
