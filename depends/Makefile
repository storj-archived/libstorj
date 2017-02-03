.NOTPARALLEL :

build_SHA256SUM = sha256sum
build_DOWNLOAD = curl --location --fail --connect-timeout 120 --retry 3 -o

BUILD = $(shell ./config.guess)
HOST ?= $(BUILD)

DOWNLOAD_DIR = "$(CURDIR)/downloads/"
SOURCES_DIR = "$(CURDIR)/sources/$(HOST)/"
PREFIX_DIR = "$(CURDIR)/build/$(HOST)/"

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
	$(build_SHA256SUM) -c "$($(1)_file_name)".hash; \
	fi && \
	cd "$(CURDIR)"
endef

define extract_file
	set -e && \
	echo "Extracting: $(DOWNLOAD_DIR)$($(1)_file_name)" && \
	mkdir -p "$(SOURCES_DIR)$(1)" && \
	tar xf "$(DOWNLOAD_DIR)$($(1)_file_name)" -C "$(SOURCES_DIR)$(1)" --strip-components=1
endef

extract-sources: download-sources
	@$(foreach package,$(packages),$(call extract_file,$(package));)

download-sources:
	@$(foreach package,$(packages),$(call fetch_file,$(package));)

.PHONY: extract-sources
