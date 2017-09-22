lib_LTLIBRARIES = libstorj.la
libstorj_la_SOURCES = storj.c utils.c utils.h http.c http.h uploader.c uploader.h downloader.c downloader.h bip39.c bip39.h bip39_english.h crypto.c crypto.h rs.c rs.h
libstorj_la_LIBADD = -lcurl -lnettle -ljson-c -luv -lm
libstorj_la_LDFLAGS = -Wall
if BUILD_STORJ_DLL
libstorj_la_LDFLAGS += -no-undefined
endif
include_HEADERS = storj.h

bin_PROGRAMS = storj
storj_SOURCES = cli.c storj.h
storj_LDADD = libstorj.la -lcurl -lnettle -ljson-c -luv -lm
if BUILD_STORJ_DLL
storj_LDFLAGS = -Wall
else
storj_LDFLAGS = -Wall -static
endif
