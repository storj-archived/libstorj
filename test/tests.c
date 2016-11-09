#include <microhttpd.h>
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <string.h>

#include "../src/storj.h"

#define INFO "{ \"info\": { \"title\": \"Storj Bridge\", \"version\": \"2.0.0\" } }"
#define BUCKETS "{ \"buckets\": \"{}\"}"

static int test_server(void *cls,
                       struct MHD_Connection *connection,
                       const char *url,
                       const char *method,
                       const char *version,
                       const char *upload_data,
                       size_t *upload_data_size,
                       void **ptr) {

    static int dummy;
    struct MHD_Response *response;


    char *page = "Not Found";
    int status_code = MHD_HTTP_NOT_FOUND;

    int ret;

    char *pass;
    char *user = MHD_basic_auth_get_username_password(connection, &pass);

    if (0 != strcmp(method, "GET")) {
        return MHD_NO;
    }

    if (0 == strcmp(url, "/")) {
        page = INFO;
        status_code = MHD_HTTP_OK;
    }

    if (0 == strcmp(url, "/buckets")) {
        if (user &&
            0 == strcmp(user, "testuser@storj.io") &&
            0 == strcmp(pass, "dce18e67025a8fd68cab186e196a9f8bcca6c9e4a7ad0be8a6f5e48f3abd1b04")) {
            page = BUCKETS;
            status_code = MHD_HTTP_OK;
        } else {
            status_code = MHD_HTTP_UNAUTHORIZED;
            page = "Unauthorized";
        }
    }

    response = MHD_create_response_from_buffer(strlen(page),
                                               (void*) page,
                                               MHD_RESPMEM_PERSISTENT);

    *ptr = NULL;

    ret = MHD_queue_response(connection, status_code, response);

    MHD_destroy_response(response);

    return ret;
}

int main(void)
{

    // spin up test server
    struct MHD_Daemon *d;
    d = MHD_start_daemon(MHD_USE_THREAD_PER_CONNECTION,
                         8091,
                         NULL,
                         NULL,
                         &test_server,
                         NULL,
                         MHD_OPTION_END);
    if (d == NULL)
        return 1;

    struct storj_bridge_options options = {
        "http",
        "localhost",
        8091,
        "testuser@storj.io",
        "dce18e67025a8fd68cab186e196a9f8bcca6c9e4a7ad0be8a6f5e48f3abd1b04"
    };

    json_object *obj = storj_bridge_get_info(&options);

    printf("%s\n", json_object_to_json_string(obj));

    json_object *obj_buckets = storj_bridge_get_buckets(&options);

    printf("%s\n", json_object_to_json_string(obj_buckets));

    // shutdown test server
    MHD_stop_daemon(d);

    return 0;

}
