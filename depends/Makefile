.NOTPARALLEL :

build_SHA256SUM = sha256sum
build_DOWNLOAD = curl --location --fail --connect-timeout 120 --retry 3 -o

BUILD = $(shell ./config.guess)
HOST ?= $(BUILD)
CA_BUNDLE ?= "/etc/ssl/certs/ca-certificates.crt"

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
	if test -d "$(SOURCES_DIR)$(1)"; then \
	echo "Skipping extract: $(DOWNLOAD_DIR)$($(1)_file_name)"; \
	else \
	echo "Extracting: $(DOWNLOAD_DIR)$($(1)_file_name)"; \
	mkdir -p "$(SOURCES_DIR)$(1)"; \
	tar xf "$(DOWNLOAD_DIR)$($(1)_file_name)" -C "$(SOURCES_DIR)$(1)" --strip-components=1; \
	fi
endef

define build_source
	echo "Building $(1)" && \
	cd "$(SOURCES_DIR)$(1)" && \
	if test -f "./autogen.sh"; then ./autogen.sh; fi && \
	$($(1)_config_env) ./configure --host="$(HOST)" $($(1)_config_opts) --enable-static --disable-shared --prefix=$(PREFIX_DIR) || exit&& \
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
