package=curl
$(package)_version=7.52.1
$(package)_download_path=https://curl.haxx.se/download/curl-$($(package)_version).tar.gz
$(package)_file_name=$(package)-$($(package)_version).tar.gz
$(package)_sha256_hash=a8984e8b20880b621f61a62d95ff3c0763a3152093a9f9ce4287cfd614add6ae
$(package)_config_env=LIBS="-lcrypt32 -lnettle -lhogweed -lgmp" LD_LIBRARY_PATH="$(PREFIX_DIR)lib" PKG_CONFIG_LIBDIR="$(PREFIX_DIR)lib/pkgconfig" CPPFLAGS="-I$(PREFIX_DIR)include -DCURL_STATIC_LIB -static" LDFLAGS="-L$(PREFIX_DIR)lib"
$(package)_config_opts=--disable-ftp --disable-file --disable-ldap --disable-ldaps --disable-rtsp --disable-dict --disable-telnet --disable-tftp --disable-pop3 --disable-imap --disable-smb --disable-smtp --disable-gopher --enable-proxy --without-ssl --with-gnutls="$(PREFIX_DIR)" --with-ca-bundle="$(CA_BUNDLE)" --disable-telnet
