#include <assert.h>
#include "storjtests.h"

void req_callback(uv_work_t *work_req, int status)
{
    json_request_t *req = work_req->data;
    printf("%s\n\n\n", json_object_to_json_string(req->response));
}

int main(void)
{
    char const *folder = getenv("TMPDIR");

    if (folder == 0) {
        printf("You need to set $TMPDIR before running.");
        exit(0);
    }
    char *file = strcat(folder, "samplefile.txt");
    create_test_file(file);

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

    // setup bridge options to point to mock server
    storj_upload_opts_t upload_opts = {
        .file_concurrency = 1,
        .shard_concurrency  = 3,
        .redundancy  = 1,
        .bucket_id  = "368be0816766b28fd5f43af5ba0fc54ab1be516e",
        .file_path  = file,
        .key_pass = "password"
    };

    // initialize event loop and environment
    storj_env_t *env = storj_init_env(&options);
    assert(env != NULL);


    int status;

    // get general api info
    status = storj_bridge_get_info(env, req_callback);
    assert(status == 0);

    // get buckets
    status = storj_bridge_get_buckets(env, req_callback);
    assert(status == 0);

    // create a new bucket with a name
    status = storj_bridge_create_bucket(env, "backups", req_callback);
    assert(status == 0);

    char *bucket_id = "368be0816766b28fd5f43af5ba0fc54ab1be516e";

    // delete a bucket
    // TODO check for successful status code, response has object
    status = storj_bridge_delete_bucket(env, bucket_id, req_callback);
    assert(status == 0);

    // list files in a bucket
    status = storj_bridge_list_files(env, bucket_id, req_callback);
    assert(status == 0);

    // create bucket tokens
    status = storj_bridge_create_bucket_token(env,
                                              bucket_id,
                                              BUCKET_PUSH,
                                              req_callback);
    assert(status == 0);

    char *file_id = "998960317b6725a3f8080c2b26875b0d8fe5731c";

    // delete a file in a bucket
    status = storj_bridge_delete_file(env,
                                      bucket_id,
                                      file_id,
                                      req_callback);
    assert(status == 0);

    // create a file frame
    status = storj_bridge_create_frame(env, req_callback);
    assert(status == 0);

    // get frames
    status = storj_bridge_get_frames(env, req_callback);
    assert(status == 0);

    char *frame_id = "d4af71ab00e15b0c1a7b6ab2";

    // get frame
    status = storj_bridge_get_frame(env, frame_id, req_callback);
    assert(status == 0);

    // delete frame
    status = storj_bridge_delete_frame(env, frame_id, req_callback);
    assert(status == 0);

    // TODO add shard to frame

    // get file information
    status = storj_bridge_get_file_info(env, bucket_id, file_id, req_callback);
    assert(status == 0);

    // upload file
    status = storj_bridge_store_file(env, &upload_opts);
    assert(status == 0);

    int stren = 128;
    char *mnemonic = calloc(250, sizeof(char));
    status = mnemonic_generate(stren, &mnemonic);
    printf("\nmnemonic: %s\n", mnemonic);
    free(mnemonic);

    // run all queued events
    if (uv_run(env->loop, UV_RUN_DEFAULT)) {
        return -1;
    }

    // shutdown
    status = uv_loop_close(env->loop);
    if (status == UV_EBUSY) {
        return -1;
    }

    MHD_stop_daemon(d);

    return 0;
}

int create_test_file(char *file) {
    FILE *fp;
    fp = fopen(file, "w+");
    fprintf(fp, "Sample file...\n");
    fclose(fp);

    return 0;
}
