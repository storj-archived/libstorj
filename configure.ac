AC_INIT([libstorj],[0.1])
AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_MACRO_DIR([build-aux/m4])
AM_INIT_AUTOMAKE([foreign])
LT_INIT
AC_CHECK_HEADERS([neon/ne_request.h], [neon_found_headers=yes; break;])
AS_IF([test "x$neon_found_headers" != "xyes"],
        [AC_MSG_ERROR([Unable to find neon headers.])])
AC_CHECK_HEADERS([nettle/aes.h], [nettle_found_headers=yes; break;])
AS_IF([test "x$nettle_found_headers" != "xyes"],
        [AC_MSG_ERROR([Unable to find nettle headers.])])
AC_CHECK_HEADERS([libwebsockets.h], [websockets_found_headers=yes; break;])
AS_IF([test "x$websockets_found_headers" != "xyes"],
        [AC_MSG_ERROR([Unable to find libwebsocket headers.])])
AC_CHECK_HEADERS([json-c/json.h], [json_found_headers=yes; break;])
AS_IF([test "x$json_found_headers" != "xyes"],
        [AC_MSG_ERROR([Unable to find json-c headers.])])
AC_CONFIG_FILES([Makefile src/Makefile test/Makefile])
AC_OUTPUT
