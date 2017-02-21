.NOTPARALLEL :

build_DOWNLOAD = curl --location --fail --connect-timeout 120 --retry 3 -o

BUILD = $(shell ./config.guess)
HOST ?= $(BUILD)

DOWNLOAD_DIR = "$(CURDIR)/downloads/"
SOURCES_DIR = "$(CURDIR)/sources/$(HOST)/"
PREFIX_DIR = "$(CURDIR)/build/$(HOST)/"
TOOLCHAIN_BUILD_DIR = "$(CURDIR)/toolchain/build/"
TOOLCHAIN_SOURCE_DIR = "$(CURDIR)/toolchain/source/"

canonical_host:=$(shell ./config.sub $(HOST))

host_arch=$(firstword $(subst -, ,$(canonical_host)))
host_vendor=$(word 2,$(subst -, ,$(canonical_host)))
full_host_os:=$(subst $(host_arch)-$(host_vendor)-,,$(canonical_host))
host_os:=$(findstring linux,$(full_host_os))
host_os+=$(findstring darwin,$(full_host_os))
host_os+=$(findstring mingw32,$(full_host_os))
host_os:=$(strip $(host_os))
ifeq ($(host_os),)
host_os=$(full_host_os)
endif

# mac build
DARWIN_SDK_PATH ?= "$(CURDIR)/MacOSX10.11.sdk"
DARWIN_CFLAGS = "-target $(HOST) -isysroot $(DARWIN_SDK_PATH) -mmacosx-version-min=10.8 -mlinker-version=253.9 -pipe -I$(PREFIX_DIR)include"
DARWIN_LDFLAGS="-L$(TOOLCHAIN_BUILD_DIR)lib -L$(DARWIN_SDK_PATH)/usr/lib -L$(PREFIX_DIR)lib -Wl,-syslibroot $(DARWIN_SDK_PATH)"

build_SHA256SUM = sha256sum -c

build_env=
ifeq ($(host_os), darwin)
build_env=PATH="$(TOOLCHAIN_BUILD_DIR)bin:${PATH}" CC=clang CXX=clang++ CFLAGS=$(DARWIN_CFLAGS) LDFLAGS=$(DARWIN_LDFLAGS)
endif
ifeq ($(HOST), i686-pc-linux-gnu)
build_env=CFLAGS=-m32 CXXFLAGS=-m32 LDFLAGS=-m32
endif

toolchain_packages:=clang cctools
packages:=gmp nettle gnutls libcurl json-c libuv libmicrohttpd
all_packages = $(toolchain_packages) $(packages)

$(foreach package,$(all_packages),$(eval include packages/$(package).mk))

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
	echo "build_env: $(build_env)" && \
	echo "config_env: $($(1)_config_env)" && \
	echo "config_opts: $($(1)_config_opts)" && \
	echo "host: $(HOST)" && \
	echo "prefix: $(PREFIX_DIR)" && \
	echo "====================================\n\n" && \
	export PATH="$(TOOLCHAIN_BUILD_DIR)bin:${PATH}" && \
	if test -f "./autogen.sh"; then ./autogen.sh; fi && \
	$(build_env) $($(1)_config_env) ./configure --host="$(HOST)" $($(1)_config_opts) --enable-static --disable-shared --prefix=$(PREFIX_DIR) || exit && \
	make || exit && \
	make install || exit && \
	cd "$(CURDIR)"
endef

define extract_toolchain_file
	if test -d "$(TOOLCHAIN_SOURCE_DIR)$(1)"; then \
	echo "Skipping extract: $(DOWNLOAD_DIR)$($(1)_file_name)"; \
	else \
	echo "Extracting: $(DOWNLOAD_DIR)$($(1)_file_name)"; \
	mkdir -p "$(TOOLCHAIN_SOURCE_DIR)$(1)"; \
	tar xf "$(DOWNLOAD_DIR)$($(1)_file_name)" -C "$(TOOLCHAIN_SOURCE_DIR)$(1)" --strip-components=1; \
	fi
endef

define extract_toolchain_file_build
	mkdir -p "$(TOOLCHAIN_BUILD_DIR)"; \
	tar xfv "$(DOWNLOAD_DIR)$($(1)_file_name)" -C "$(TOOLCHAIN_BUILD_DIR)" --strip-components=1; \
	rm -f $(TOOLCHAIN_BUILD_DIR)lib/libc++abi.so
endef

ifeq ($(host_os), darwin)
define build_darwin_toolchain
	echo "Building darwin toolchain" && \
	$(foreach package,$(toolchain_packages),$(call fetch_file,$(package));)
	$(foreach package,clang,$(call extract_toolchain_file_build,$(package));)
	$(foreach package,cctools,$(call extract_toolchain_file,$(package));)
	cd "$(TOOLCHAIN_SOURCE_DIR)cctools/cctools" && \
	if test -f "./autogen.sh"; then ./autogen.sh; fi && \
	PATH="$(TOOLCHAIN_BUILD_DIR)bin:${PATH}" CC=clang CXX=clang++ ./configure --prefix="$(TOOLCHAIN_BUILD_DIR)" --target="x86_64-apple-darwin11" || exit && \
	make || exit && \
	make install || exit && \
	cd "$(CURDIR)"
endef
else
define build_darwin_toolchain
	echo "Skipping building darwin toolchain"
endef
endif

build-sources: extract-sources
	@$(foreach package,$(packages),$(call build_source,$(package));)

extract-sources: download-sources
	@$(foreach package,$(packages),$(call extract_file,$(package));)

download-sources: build-toolchain
	@$(foreach package,$(packages),$(call fetch_file,$(package));)

build-toolchain:
	@$(call build_darwin_toolchain,)

clean:
	$(RM) -rv $(DOWNLOAD_DIR)
	$(RM) -rv $(SOURCES_DIR)
	$(RM) -rv $(PREFIX_DIR)

.PHONY: extract-sources
