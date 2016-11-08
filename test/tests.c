#include <microhttpd.h>
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <string.h>

#include "../src/storj.h"

#define INFO "{ \"info\": { \"title\": \"Storj Bridge\", \"version\": \"2.0.0\" } }"

static int test_server(void * cls,
                       struct MHD_Connection * connection,
                       const char * url,
                       const char * method,
                       const char * version,
                       const char * upload_data,
                       size_t * upload_data_size,
                       void ** ptr) {
    static int dummy;
    const char * page = cls;
    struct MHD_Response * response;
    int ret;

    if (0 != strcmp(method, "GET")) {
        return MHD_NO;
    }

    *ptr = NULL;

    response = MHD_create_response_from_buffer(strlen(page),
                                               (void*) page,
                                               MHD_RESPMEM_PERSISTENT);
    ret = MHD_queue_response(connection,
                             MHD_HTTP_OK,
                             response);

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
                         INFO,
                         MHD_OPTION_END);
    if (d == NULL)
        return 1;

    struct storj_bridge_options options = {
        "https",
        "api.storj.io",
        443,
        "testuser@storj.io",
        "sha256hashofpassphrase"
    };

    json_object *obj = storj_bridge_get_info(&options);

    printf("%s\n", json_object_to_json_string(obj));

    json_object *obj_buckets = storj_bridge_get_buckets(&options);

    printf("%s\n", json_object_to_json_string(obj_buckets));

    // shutdown test server
    MHD_stop_daemon(d);

    return 0;

}
