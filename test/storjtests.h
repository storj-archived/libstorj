#include <microhttpd.h>
#include <assert.h>
#include "../src/storj.h"

#define USER "testuser@storj.io"
#define PASS "dce18e67025a8fd68cab186e196a9f8bcca6c9e4a7ad0be8a6f5e48f3abd1b04"
#define INFO "{\"info\": {\"title\":\"Storj Bridge\",\"version\":\"2.0.0\"}}"
#define BUCKETS "{\"buckets\":\"{}\"}"

int mock_bridge_server(void *cls,
                       struct MHD_Connection *connection,
                       const char *url,
                       const char *method,
                       const char *version,
                       const char *upload_data,
                       size_t *upload_data_size,
                       void **ptr);
