noinst_PROGRAMS = tests
tests_SOURCES = mockbridge.c mockfarmer.c tests.c storjtests.h $(top_builddir)/src/storj.h
tests_LDADD = $(top_builddir)/src/libstorj.la
tests_LDFLAGS = -Wall -g -static -lmicrohttpd
TESTS = tests
