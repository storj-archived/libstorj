noinst_PROGRAMS = tests
tests_SOURCES = mockbridge.c mockfarmer.c tests.c storjtests.h $(top_builddir)/src/storj.h mockbridge.json.h
tests_LDADD = $(top_builddir)/src/libstorj.la
tests_LDFLAGS = -Wall -g -static -lmicrohttpd
TESTS = tests

CLEANFILES = mockbridge.json.h

mockbridge.c: mockbridge.json.h

%.json.h: %.json
	@$(MKDIR_P) $(@D)
	@{ \
	 echo "static const char $(*F)_json[] = {" && \
	 $(HEXDUMP) -v -e '8/1 "0x%02x, "' -e '"\n"' $< | $(SED) -e 's/0x  ,//g' && \
	 echo "};"; \
	} > "$@.new" && mv -f "$@.new" "$@"
	@echo "Generated $@"
