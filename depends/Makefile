.NOTPARALLEL :

build_SHA256SUM = sha256sum
build_DOWNLOAD = curl --location --fail --connect-timeout 120 --retry 3 -o

packages:=gmp nettle gnutls libcurl json-c libuv libmicrohttpd

$(foreach package,$(packages),$(eval include packages/$(package).mk))

define fetch_file
	set -e && \
	$(build_DOWNLOAD) "$($(1)_file_name)" "$($(1)_download_path)" && \
	echo "$($(1)_sha256_hash)\t$($(1)_file_name)" > "$($(1)_file_name)".hash && \
	$(build_SHA256SUM) -c "$($(1)_file_name)".hash
endef

download-sources:
	@$(foreach package,$(packages),$(call fetch_file,$(package));)

.PHONY: download-sources
