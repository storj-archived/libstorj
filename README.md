Storj C
=======

## Build

Build requirements:

```bash
apt-get install build-essential libtool autotools-dev automake
```

Library requirements:

```bash
apt-get install libneon27-gnutls-dev nettle-dev libwebsockets-dev libjson-c-dev
```

```bash
./autogen.sh
./configure
make
```

To run tests:
```bash
./test/tests
```
