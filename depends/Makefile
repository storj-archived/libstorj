.NOTPARALLEL :

build_DOWNLOAD = curl --location --fail --connect-timeout 120 --retry 3 -o

BUILD = $(shell ./config.guess)
HOST ?= $(BUILD)

DOWNLOAD_DIR = "$(CURDIR)/downloads/"
SOURCES_DIR = "$(CURDIR)/sources/$(HOST)/"
PREFIX_DIR = "$(CURDIR)/build/$(HOST)/"

build:=$(shell ./config.sub $(BUILD))

build_arch =$(firstword $(subst -, ,$(build)))
build_vendor=$(word 2,$(subst -, ,$(build)))
full_build_os:=$(subst $(build_arch)-$(build_vendor)-,,$(build))
build_os:=$(findstring linux,$(full_build_os))
build_os+=$(findstring darwin,$(full_build_os))
build_os:=$(strip $(build_os))
ifeq ($(build_os),)
build_os=$(full_build_os)
endif

# mac build
DARWIN_SDK_PATH = "/Library/Developer/CommandLineTools/SDKs/MacOSX10.12.sdk"
DARWIN_CFLAGS = "-target $(HOST) -isysroot $(DARWIN_SDK_PATH)"

build_SHA256SUM = $(if "$(build_os)" == "darwin",shasum -a 256,sha256sum -c)
build_env = $(if $(build_os) == "darwin",CC=clang CXX=clang++ CFLAGS=$(DARWIN_CFLAGS),)

packages:=gmp nettle gnutls libcurl json-c libuv libmicrohttpd

$(foreach package,$(packages),$(eval include packages/$(package).mk))

define fetch_file
	set -e && \
	mkdir -p "$(DOWNLOAD_DIR)" && \
	cd "$(DOWNLOAD_DIR)" && \
	if test -f "$($(1)_file_name)"; then \
	echo "Skipping download: $($(1)_download_path)"; \
	else \
	echo "Downloading: $($(1)_download_path)"; \
	$(build_DOWNLOAD) "$($(1)_file_name)" "$($(1)_download_path)"; \
	echo "$($(1)_sha256_hash)\t$($(1)_file_name)" > "$($(1)_file_name)".hash; \
	$(build_SHA256SUM) "$($(1)_file_name)".hash; \
	fi && \
	cd "$(CURDIR)"
endef

define extract_file
	set -e && \
	if test -d "$(SOURCES_DIR)$(1)"; then \
	echo "Skipping extract: $(DOWNLOAD_DIR)$($(1)_file_name)"; \
	else \
	echo "Extracting: $(DOWNLOAD_DIR)$($(1)_file_name)"; \
	mkdir -p "$(SOURCES_DIR)$(1)"; \
	tar xf "$(DOWNLOAD_DIR)$($(1)_file_name)" -C "$(SOURCES_DIR)$(1)" --strip-components=1; \
	fi
endef

define build_source
	echo "\n\nBuilding $(1)\n====================================" && \
	cd "$(SOURCES_DIR)$(1)" && \
	echo "curdir: $(CURDIR)" && \
	echo "config_env: $($(1)_config_env)" && \
	echo "config_opts: $($(1)_config_opts)" && \
	echo "host: $(HOST)" && \
	echo "prefix: $(PREFIX_DIR)" && \
	echo "====================================\n\n" && \
	if test -f "./autogen.sh"; then ./autogen.sh; fi && \
	$($(build_env)) $($(1)_config_env) ./configure --host="$(HOST)" $($(1)_config_opts) --enable-static --disable-shared --prefix=$(PREFIX_DIR) || exit && \
	make || exit && \
	make install || exit && \
	cd "$(CURDIR)"
endef

build-sources: extract-sources
	@$(foreach package,$(packages),$(call build_source,$(package));)

extract-sources: download-sources
	@$(foreach package,$(packages),$(call extract_file,$(package));)

download-sources:
	@$(foreach package,$(packages),$(call fetch_file,$(package));)

clean:
	$(RM) -rv $(DOWNLOAD_DIR)
	$(RM) -rv $(SOURCES_DIR)
	$(RM) -rv $(PREFIX_DIR)

.PHONY: extract-sources
