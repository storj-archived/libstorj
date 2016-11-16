#include <assert.h>
#include "storjtests.h"

void callback(uv_work_t *work_req, int status)
{
    json_request_t *req = work_req->data;
    printf("%s\n\n\n", json_object_to_json_string(req->response));
}

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

    // setup bridge options to point to mock server
    storj_bridge_options_t options = {
        .proto = "http",
        .host  = "localhost",
        .port  = 8091,
        .user  = "testuser@storj.io",
        .pass  = "dce18e67025a8fd68cab186e196a9f8bcca6c9e4a7ad0be8a6f5e48f3abd1b04"
    };

    // initialize event loop and environment
    storj_env_t *env = storj_init_env(&options);
    assert(env != NULL);

    // queue a few api requests
    int status;
    status = storj_bridge_get_info(env, callback);
    assert(status == 0);

    status = storj_bridge_get_buckets(env, callback);
    assert(status == 0);

    status = storj_bridge_create_bucket(env, "backups", callback);
    assert(status == 0);

    // run all queued events
    if (uv_run(env->loop, UV_RUN_DEFAULT)) {
        return -1;
    }

    // shutdown test server
    MHD_stop_daemon(d);

    return 0;

}
