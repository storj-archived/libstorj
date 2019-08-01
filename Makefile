CC=gcc
CFLAGS=-ggdb -Isrc -Istorj -luv -lnettle -lm -ljson-c

COMMON_SRC=src/crypto.c src/utils.c src/storj.c src/uploader.c src/downloader.c storj/uplink.so
COMMON_DEPS=src/storj.h storj/uplink.h storj/uplink.so

# cli builds the libstorj cli binary as ./cli (see: ./cli --help)
CLI_DEPS=src/cli_callback.h $(COMMON_DEPS)
CLI_SRC=src/cli.c $(COMMON_SRC)
storj-cli: libuplink $(CLI_SRC)
	$(CC) -o $@ $(CLI_SRC) $(CFLAGS)

# tests builds a test binary for libstorj
CLI_DEPS=src/cli_callback.h $(COMMON_DEPS)
TEST_DEPS=src/storjtests.h $(COMMON_DEPS)
TEST_SRC=test/tests.c $(COMMON_SRC)
tests: libuplink $(TEST_SRC)
	$(CC) -o $@ $(TEST_SRC) $(CFLAGS)

# libuplink builds the libuplink shared object
# and headers from the storj submodule
.PHONY: libuplink
libuplink:
	$(MAKE) -C storj libuplink
