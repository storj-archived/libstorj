AC_INIT([libstorj],[1.0.0])
AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_MACRO_DIR([build-aux/m4])
AM_INIT_AUTOMAKE([foreign])
LT_INIT

AC_PATH_PROG(HEXDUMP,hexdump)

if test x$HEXDUMP = x; then
AC_MSG_ERROR(hexdump is required for tests)
fi

PKG_PROG_PKG_CONFIG
if test -z "$PKG_CONFIG"; then
   AC_MSG_ERROR([pkg-config not found. pkg-config is required to check for some dependencies.])
fi

PKG_CHECK_MODULES([LIBCURL], [libcurl >= 7.35.0],, [AC_MSG_ERROR([libcurl 7.35.0 or greater was not found.])])
AC_CHECK_HEADERS([curl/curl.h], [libcurl_found_headers=yes; break;])
AS_IF([test "x$libcurl_found_headers" != "xyes"],
            [AC_MSG_ERROR([Unable to find libcurl headers.])])


PKG_CHECK_MODULES([NETTLE], [nettle >= 3.1],, [AC_MSG_ERROR([nettle 3.1 or greater was not found.
                            You can get it from https://www.lysator.liu.se/~nisse/nettle/])])

AC_CHECK_HEADERS([nettle/aes.h], [nettle_found_headers=yes; break;])
AS_IF([test "x$nettle_found_headers" != "xyes"],
        [AC_MSG_ERROR([Unable to find nettle headers.])])

PKG_CHECK_MODULES([JSON], [json-c >= 0.11],, [AC_MSG_ERROR([libjson-c 0.11 or greater was not found.])])
AC_CHECK_HEADERS([json-c/json.h], [json_found_headers=yes; break;])
AS_IF([test "x$json_found_headers" != "xyes"],
        [AC_MSG_ERROR([Unable to find json-c headers.])])

PKG_CHECK_MODULES([UV], [libuv >= 1.8.0],, [AC_MSG_ERROR([libuv1 1.8.0 or greater was not found.])])
AC_CHECK_HEADERS([uv.h], [uv_found_headers=yes; break;])
AS_IF([test "x$uv_found_headers" != "xyes"],
        [AC_MSG_ERROR([Unable to find libuv headers.])])

PKG_CHECK_MODULES([MICROHTTPD], [libmicrohttpd >= 0.9],, [AC_MSG_ERROR([libmicrohttpd 0.9 or greater was not found.])])
AC_CHECK_HEADERS([microhttpd.h], [microhttpd_found_headers=yes; break;])
AS_IF([test "x$microhttpd_found_headers" != "xyes"],
        [AC_MSG_ERROR([Unable to find libmicrohttpd headers.])])

AC_CONFIG_FILES([Makefile src/Makefile test/Makefile])
AC_CONFIG_FILES([libstorj.pc:libstorj.pc.in])

AC_CHECK_FUNCS([aligned_alloc posix_memalign posix_fallocate])

AC_ARG_ENABLE([debug],
        [AS_HELP_STRING([--enable-debug],
        [use debug compiler flags and macros (default is no)])],
        [enable_debug=$enableval],
        [enable_debug=no])

if test "x$enable_debug" = xyes; then
   CFLAGS="$CFLAGS -DDEBUG -g3 -O0"
else
   CFLAGS="$CFLAGS -O3"
fi

AC_OUTPUT
