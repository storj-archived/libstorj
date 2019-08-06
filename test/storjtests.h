#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <signal.h>

#include "storj.h"
#include "../storj/lib/uplinkc/testdata/require.h"

#define require_no_last_error() \
if (strcmp("", *STORJ_LAST_ERROR) != 0) { \
    printf("STORJ_LAST_ERROR: %s\n", *STORJ_LAST_ERROR); \
} \
require_noerror(*STORJ_LAST_ERROR);\

#define require_no_last_error_if(status) \
if (status > 0) { \
    printf("ERROR: %s\n", storj_strerror(status)); \
    require_no_last_error(); \
    require(status == 0);\
} \

#define require_not_empty(str) \
require(str != NULL); \
require(strcmp("", str) != 0) \

#define require_equal(str1, str2) \
require(str1 != NULL); \
require(str2 != NULL); \
require(strcmp(str1, str2) == 0) \


#define KRED  "\x1B[31m"
#define KGRN  "\x1B[32m"
#define RESET "\x1B[0m"

void handle_abort(int signum)
{
    exit(1);
}
