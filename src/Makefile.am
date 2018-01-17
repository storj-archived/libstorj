lib_LTLIBRARIES = libstorj.la
libstorj_la_SOURCES = storj.c utils.c utils.h http.c http.h uploader.c uploader.h downloader.c downloader.h bip39.c bip39.h bip39_english.h crypto.c crypto.h rs.c rs.h
libstorj_la_LIBADD = -lcurl -lnettle -ljson-c -luv -lm
# The rules of thumb, when dealing with these values are:
# - Always increase the revision value.
# - Increase the current value whenever an interface has been added, removed or changed.
# - Increase the age value only if the changes made to the ABI are backward compatible.
# https://autotools.io/libtool/version.html
# The order for version-info is <current>:<revision>:<age>
libstorj_la_LDFLAGS = -Wall -version-info 1:1:0
if BUILD_STORJ_DLL
libstorj_la_LDFLAGS += -no-undefined
endif
include_HEADERS = storj.h

bin_PROGRAMS = storj
storj_SOURCES = cli.c storj.h storjapi_callback.c storjapi_callback.h
storj_LDADD = libstorj.la
if BUILD_STORJ_DLL
storj_LDFLAGS = -Wall
else
storj_LDFLAGS = -Wall -static
endif
