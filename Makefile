SHELL=/bin/bash

CC=gcc
CFLAGS=-ggdb -Isrc -Istorj -luv -lnettle -lm -ljson-c

COMMON_SRC=src/crypto.c src/utils.c src/storj.c src/uploader.c src/downloader.c storj/uplink.so
COMMON_DEPS=src/storj.h storj/uplink.h storj/uplink.so

CLI_DEPS=src/cli_callback.h $(COMMON_DEPS)
CLI_SRC=src/cli.c $(COMMON_SRC)
cli: libuplink $(CLI_SRC)
	$(CC) -o $@ $(CLI_SRC) $(CFLAGS)

TEST_DEPS=src/storjtests.h $(COMMON_DEPS)
TEST_SRC=test/tests.c $(COMMON_SRC)
tests: libuplink $(TEST_SRC)
	$(CC) -o $@ $(TEST_SRC) $(CFLAGS)
	./$@ && rm ./$@

.PHONY: libuplink
libuplink:
	$(MAKE) -C storj libuplink
