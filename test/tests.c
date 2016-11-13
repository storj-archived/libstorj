#include "storjtests.h"

int main(void)
{
    // spin up test server
    struct MHD_Daemon *d;
    d = MHD_start_daemon(MHD_USE_THREAD_PER_CONNECTION,
                         8091,
                         NULL,
                         NULL,
                         &mock_bridge_server,
                         NULL,
                         MHD_OPTION_END);
    if (d == NULL) {
        return 1;
    }

    storj_bridge_options options = {
        .proto = "http",
        .host  = "localhost",
        .port  = 8091,
        .user  = "testuser@storj.io",
        .pass  = "dce18e67025a8fd68cab186e196a9f8bcca6c9e4a7ad0be8a6f5e48f3abd1b04"
    };

    json_object *obj = storj_bridge_get_info(&options);

    printf("%s\n", json_object_to_json_string(obj));

    json_object *obj_buckets = storj_bridge_get_buckets(&options);

    printf("%s\n", json_object_to_json_string(obj_buckets));

    // shutdown test server
    MHD_stop_daemon(d);

    return 0;

}
