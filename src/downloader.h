#include "storj.h"
#include "http.h"
#include "utils.h"
#include "crypto.h"

#define STORJ_DOWNLOAD_CONCURRENCY 4
#define STORJ_DEFAULT_MIRRORS 5
#define STORJ_MAX_REPORT_TRIES 2
#define STORJ_MAX_TOKEN_TRIES 3
#define STORJ_MAX_POINTER_TRIES 2

static void queue_next_work(storj_download_state_t *state);
