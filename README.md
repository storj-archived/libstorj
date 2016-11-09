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

Development tools:
```bash
apt-get install build-essential libtool autotools-dev automake libmicrohttpd-dev
```

Dependencies:
```bash
apt-get install libneon27-gnutls-dev nettle-dev libwebsockets-dev libjson-c-dev
```

### OS X Dependencies (w/ homebrew):

Development tools:
```bash
brew install libtool automake libmicrohttpd
```

Dependencies:
```bash
brew install neon nettle libwebsockets json-c
```
