#include <microhttpd.h>
#include <assert.h>

#include "../src/storj.h"
#include "../src/bip39.h"
#include "../src/utils.h"
#include "../src/crypto.h"

#include "mockbridge.json.h"

#define KRED  "\x1B[31m"
#define KGRN  "\x1B[32m"
#define RESET "\x1B[0m"

#define USER "testuser@storj.io"
#define PASS "dce18e67025a8fd68cab186e196a9f8bcca6c9e4a7ad0be8a6f5e48f3abd1b04"
#define PASSHASH "83c2db176985cb39d2885b15dc3d2afc020bd886ffee10e954a5848429c03c6d"

int mock_bridge_server(void *cls,
                       struct MHD_Connection *connection,
                       const char *url,
                       const char *method,
                       const char *version,
                       const char *upload_data,
                       size_t *upload_data_size,
                       void **ptr);

int mock_farmer_shard_server(void *cls,
                             struct MHD_Connection *connection,
                             const char *url,
                             const char *method,
                             const char *version,
                             const char *upload_data,
                             size_t *upload_data_size,
                             void **ptr);

int create_test_file(char *file);
