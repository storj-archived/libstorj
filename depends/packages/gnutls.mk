package=gnutls
$(package)_version=3.5.8
$(package)_download_path=ftp://ftp.gnutls.org/gcrypt/gnutls/v3.5/gnutls-$($(package)_version).tar.xz
$(package)_file_name=$(package)-$($(package)_version).tar.xz
$(package)_sha256_hash=0e97f243ae72b70307d684b84c7fe679385aa7a7a0e37e5be810193dcc17d4ff
$(package)_config_env=NETTLE_CFLAGS="-static" GMP_CFLAGS="-static" PKG_CONFIG_LIBDIR="$(PREFIX_DIR)/lib/pkgconfig" CFLAGS="-I$(PREFIX_DIR)include -L$(PREFIX_DIR)lib -static"
$(package)_config_opts=--with-included-libtasn1 --with-included-unistring --enable-local-libopts --disable-non-suiteb-curves --disable-doc --without-p11-kit
