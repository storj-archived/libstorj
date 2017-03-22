lib_LTLIBRARIES = libstorj.la
libstorj_la_SOURCES = storj.c utils.c utils.h http.c http.h uploader.c uploader.h downloader.c downloader.h bip39.c bip39.h bip39_english.h crypto.c crypto.h
libstorj_la_LIBADD = -lcurl -lnettle -ljson-c -luv -lm
libstorj_la_LDFLAGS = -Wall
include_HEADERS = storj.h

bin_PROGRAMS = storj
storj_SOURCES = cli.c storj.h
storj_LDADD = libstorj.la
storj_LDFLAGS = -Wall -static
