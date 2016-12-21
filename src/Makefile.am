lib_LTLIBRARIES = libstorj.la
libstorj_la_SOURCES = storj.c utils.c shard.c http.c uploader.c downloader.c bip39.c crypto_utils.c
libstorj_la_LIBADD = -lneon -lnettle -ljson-c -luv -lm
libstorj_la_LDFLAGS = -Wall -g
include_HEADERS = storj.h bip39.h bip39_english.h

bin_PROGRAMS = storj
storj_SOURCES = cli.c $(top_builddir)/src/storj.h
storj_LDADD = $(top_builddir)/src/libstorj.la
storj_LDFLAGS = -Wall -g -static
