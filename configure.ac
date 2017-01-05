AC_INIT([libstorj],[0.1])
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

PKG_CHECK_MODULES([NEON], [neon >= 0.30.0],, [AC_MSG_ERROR([libneon 0.30.0 or greater was not found.])])
AC_CHECK_HEADERS([neon/ne_request.h], [neon_found_headers=yes; break;])
AS_IF([test "x$neon_found_headers" != "xyes"],
            [AC_MSG_ERROR([Unable to find neon headers.])])


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

AC_CONFIG_FILES([Makefile src/Makefile test/Makefile])
AC_CONFIG_FILES([libstorj.pc:libstorj.pc.in])

AC_OUTPUT
