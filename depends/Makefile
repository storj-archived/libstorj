.NOTPARALLEL :

build_SHA256SUM = sha256sum
build_DOWNLOAD = curl --location --fail --connect-timeout 120 --retry 3 -o

packages:=gmp nettle gnutls libcurl json-c libuv libmicrohttpd

$(foreach package,$(packages),$(eval include packages/$(package).mk))

define fetch_file
	$(build_DOWNLOAD) "$($(1)_file_name)" "$($(1)_download_path)"
endef

download-sources:
	@$(foreach package,$(packages),$(call fetch_file,$(package));)

.PHONY: download-sources
