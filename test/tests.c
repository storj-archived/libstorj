#include "storjtests.h"

char *folder;
int tests_ran = 0;
int test_status = 0;
const char *test_bucket_name = "test-bucket";
const char *test_file_name = "test-file";

storj_bridge_options_t bridge_options;

storj_encrypt_options_t encrypt_options = {
    .key = { 0x31, 0x32, 0x33, 0x61, 0x33, 0x32, 0x31 }
};

// TODO: repair logger
storj_log_options_t log_options = {
    .level = 0
};

void fail(char *msg)
{
    printf("\t" KRED "FAIL" RESET " %s\n", msg);
    tests_ran += 1;
}

void pass(char *msg)
{
    printf("\t" KGRN "PASS" RESET " %s\n", msg);
    test_status += 1;
    tests_ran += 1;
}


void check_get_buckets(uv_work_t *work_req, int status)
{
    // TODO: assert req->error_code & req->status_code
    // (status_code is an http status)

    assert(status == 0);
    get_buckets_request_t *req = work_req->data;

    // TODO: add assertions
    assert(req->total_buckets == 1);
    assert(req->buckets != NULL);

    pass("storj_bridge_get_buckets");

    storj_free_get_buckets_request(req);
    free(work_req);
}

void check_get_bucket(uv_work_t *work_req, int status)
{
    // TODO: assert req->error_code & req->status_code
    // (status_code is an http status)

    assert(status == 0);
    get_bucket_request_t *req = work_req->data;
    assert(req->handle == NULL);
    assert(req->bucket != NULL);
    assert(strcmp(req->bucket->name, test_bucket_name) == 0);
    assert(strcmp(req->bucket->id, test_bucket_name) == 0);
    assert(req->bucket->decrypted);

    pass("storj_bridge_get_bucket");

    storj_free_get_bucket_request(req);
    free(work_req);
}

void check_get_bucket_id(uv_work_t *work_req, int status)
{
    assert(status == 0);
    get_bucket_id_request_t *req = work_req->data;
    assert(req->handle == NULL);
    assert(strcmp(req->bucket_id, test_bucket_name) == 0);

    pass("storj_bridge_get_bucket_id");

    json_object_put(req->response);
    free((char *)req->bucket_name);
    free((char *)req->bucket_id);
    free(req);
    free(work_req);
}

void check_create_bucket(uv_work_t *work_req, int status)
{
    // TODO: assert req->error_code & req->status_code
    // (status_code is an http status)

    assert(status == 0);
    create_bucket_request_t *req = work_req->data;

    assert(req->bucket != NULL);
    assert(strcmp(req->bucket_name, test_bucket_name) == 0);
    assert(strcmp(req->bucket->name, test_bucket_name) == 0);
    assert(strcmp(req->bucket->id, test_bucket_name) == 0);
    assert(req->bucket->created != NULL);
    pass("storj_bridge_create_bucket");

    storj_free_create_bucket_request(req);
    free(work_req);
}

void check_delete_bucket(uv_work_t *work_req, int status)
{
    assert(status == 0);
    delete_bucket_request_t *req = work_req->data;
    assert(req->handle == NULL);
    assert(req->response == NULL);
    assert(req->status_code == 204);

    // TODO: check that the bucket was actuallly deleted!

    pass("storj_bridge_delete_bucket");

    free((char *)req->bucket_name);
    free(req);
    free(work_req);
}

//void check_list_files(uv_work_t *work_req, int status)
//{
//    assert(status == 0);
//    list_files_request_t *req = work_req->data;
//    assert(req->handle == NULL);
//    assert(req->response != NULL);
//
//    struct json_object *file = json_object_array_get_idx(req->response, 0);
//    struct json_object *value;
//    int success = json_object_object_get_ex(file, "id", &value);
//    assert(success == 1);
//    assert(json_object_is_type(value, json_type_string) == 1);
//
//    const char* id = json_object_get_string(value);
//    assert(strcmp(id, "f18b5ca437b1ca3daa14969f") == 0);
//
//    pass("storj_bridge_list_files");
//
//    storj_free_list_files_request(req);
//    free(work_req);
//}
//
//void check_get_file_id(uv_work_t *work_req, int status)
//{
//    assert(status == 0);
//    get_file_id_request_t *req = work_req->data;
//    assert(req->handle == NULL);
//    assert(strcmp(req->file_id, "998960317b6725a3f8080c2b") == 0);
//
//    pass("storj_bridge_get_file_id");
//
//    json_object_put(req->response);
//    free(req);
//    free(work_req);
//}
//
//void check_resolve_file_progress(double progress,
//                                 uint64_t downloaded_bytes,
//                                 uint64_t total_bytes,
//                                 void *handle)
//{
//    assert(handle == NULL);
//    if (progress == (double)1) {
//        pass("storj_bridge_resolve_file (progress finished)");
//    }
//
//    // TODO check error case
//}
//
//void check_resolve_file(int status, FILE *fd, void *handle)
//{
//    fclose(fd);
//    assert(handle == NULL);
//    if (status) {
//        fail("storj_bridge_resolve_file");
//        printf("Download failed: %s\n", storj_strerror(status));
//    } else {
//        pass("storj_bridge_resolve_file");
//    }
//}
//
//void check_resolve_file_cancel(int status, FILE *fd, void *handle)
//{
//    fclose(fd);
//    assert(handle == NULL);
//    if (status == STORJ_TRANSFER_CANCELED) {
//        pass("storj_bridge_resolve_file_cancel");
//    } else {
//        fail("storj_bridge_resolve_file_cancel");
//    }
//}

void check_store_file_progress(double progress,
                               uint64_t uploaded_bytes,
                               uint64_t total_bytes,
                               void *handle)
{
    /* TODO: probably fix this; should be called more than once
       (assert that  subsequent calls only increase progress and
       uploaded_bytes, and that total_bytes doesn't change) */
    assert(handle == NULL);
    if (progress == (double)1) {
        pass("storj_bridge_store_file (progress finished)");
    }
}

void check_store_file(int error_code, storj_file_meta_t *file, void *handle)
{
    assert(handle == NULL);
    if (error_code == 0) {
        if (file && strcmp(file->id, test_file_name) == 0 ) {
            pass("storj_bridge_store_file");
        } else {
            fail("storj_bridge_store_file(0)");
        }
    } else {
        fail("storj_bridge_store_file(1)");
        printf("\t\tERROR:   %s\n", storj_strerror(error_code));
    }

    storj_free_uploaded_file_info(file);
}

//void check_store_file_cancel(int error_code, storj_file_meta_t *file, void *handle)
//{
//    assert(handle == NULL);
//    if (error_code == STORJ_TRANSFER_CANCELED) {
//        pass("storj_bridge_store_file_cancel");
//    } else {
//        fail("storj_bridge_store_file_cancel");
//        printf("\t\tERROR:   %s\n", storj_strerror(error_code));
//    }
//
//    storj_free_uploaded_file_info(file);
//}
//
//void check_delete_file(uv_work_t *work_req, int status)
//{
//    assert(status == 0);
//    json_request_t *req = work_req->data;
//    assert(req->handle == NULL);
//    assert(req->response == NULL);
//    assert(req->status_code == 200);
//
//    pass("storj_bridge_delete_file");
//
//    free(req->path);
//    free(req);
//    free(work_req);
//}

void check_file_info(uv_work_t *work_req, int status)
{
    assert(status == 0);
    get_file_info_request_t *req = work_req->data;
    assert(req->handle == NULL);
    assert(req->file);
    assert(strcmp(req->file->filename, "storj-test-download.data") == 0);
    assert(strcmp(req->file->mimetype, "video/ogg") == 0);

    pass("storj_bridge_get_file_info");

    storj_free_get_file_info_request(req);
    free(work_req);
}

int create_test_upload_file(char *filepath)
{
    FILE *fp;
    fp = fopen(filepath, "w+");

    if (fp == NULL) {
        printf(KRED "Could not create upload file: %s\n" RESET, filepath);
        exit(0);
    }

    int shard_size = 16777216;
    char *bytes = "abcdefghijklmn";
    for (int i = 0; i < strlen(bytes); i++) {
        char *page = calloc(shard_size + 1, sizeof(char));
        memset(page, bytes[i], shard_size);
        fputs(page, fp);
        free(page);
    }

    fclose(fp);
    return 0;
}

int test_upload()
{

    // initialize event loop and environment
    storj_env_t *env = storj_init_env(&bridge_options,
                                      &encrypt_options,
                                      NULL,
                                      &log_options);
    assert(env != NULL);

    char *file_name = "storj-test-upload.data";
    int len = strlen(folder) + strlen(file_name);
    char *file = calloc(len + 1, sizeof(char));
    strcpy(file, folder);
    strcat(file, file_name);
    file[len] = '\0';

    create_test_upload_file(file);
    char *encryption_access = new_encryption_access(STORJ_LAST_ERROR);

    // upload file
    storj_upload_opts_t upload_opts = {
        .bucket_id = test_bucket_name,
        .file_name = file_name,
        .fd = fopen(file, "r"),
        .encryption_access = encryption_access
    };

    storj_upload_state_t *state = storj_bridge_store_file(env,
                                                          &upload_opts,
                                                          NULL,
                                                          check_store_file_progress,
                                                          check_store_file);
    if (!state || state->error_status != 0) {
        return 1;
    }

    // run all queued events
    if (uv_run(env->loop, UV_RUN_DEFAULT)) {
        return 1;
    }

    free(file);
    storj_destroy_env(env);

    return 0;
}

//int test_upload_cancel()
//{
//
//    // initialize event loop and environment
//    storj_env_t *env = storj_init_env(&bridge_options,
//                                      &encrypt_options,
//                                      &http_options,
//                                      &log_options);
//    assert(env != NULL);
//
//    char *file_name = "storj-test-upload.data";
//    int len = strlen(folder) + strlen(file_name);
//    char *file = calloc(len + 1, sizeof(char));
//    strcpy(file, folder);
//    strcat(file, file_name);
//    file[len] = '\0';
//
//    create_test_upload_file(file);
//
//    // upload file
//    storj_upload_opts_t upload_opts = {
//        .index = "d2891da46d9c3bf42ad619ceddc1b6621f83e6cb74e6b6b6bc96bdbfaefb8692",
//        .bucket_id = "368be0816766b28fd5f43af5",
//        .file_name = file_name,
//        .fd = fopen(file, "r")
//    };
//
//    storj_upload_state_t *state = storj_bridge_store_file(env,
//                                                          &upload_opts,
//                                                          NULL,
//                                                          check_store_file_progress,
//                                                          check_store_file_cancel);
//    if (!state || state->error_status != 0) {
//        return 1;
//    }
//
//    // process the loop one at a time so that we can do other things while
//    // the loop is processing, such as cancel the download
//    int count = 0;
//    bool more;
//    int status = 0;
//    do {
//        more = uv_run(env->loop, UV_RUN_ONCE);
//        if (more == false) {
//            more = uv_loop_alive(env->loop);
//            if (uv_run(env->loop, UV_RUN_NOWAIT) != 0) {
//                more = true;
//            }
//        }
//
//        count++;
//
//        if (count == 100) {
//            status = storj_bridge_store_file_cancel(state);
//            assert(status == 0);
//        }
//
//    } while (more == true);
//
//    free(file);
//    storj_destroy_env(env);
//
//    return 0;
//}
//
//int _test_download(storj_encrypt_options_t *encrypt_options, void *cb_finished)
//{
//
//    // initialize event loop and environment
//    storj_env_t *env = storj_init_env(&bridge_options,
//                                      encrypt_options,
//                                      &http_options,
//                                      &log_options);
//    assert(env != NULL);
//
//    // resolve file
//    char *download_file = calloc(strlen(folder) + 24 + 1, sizeof(char));
//    strcpy(download_file, folder);
//    strcat(download_file, "storj-test-download.data");
//    FILE *download_fp = fopen(download_file, "w+");
//
//    char *bucket_id = "368be0816766b28fd5f43af5";
//    char *file_id = "998960317b6725a3f8080c2b";
//
//    storj_download_state_t *state = storj_bridge_resolve_file(env,
//                                                              bucket_id,
//                                                              file_id,
//                                                              download_fp,
//                                                              NULL,
//                                                              check_resolve_file_progress,
//                                                              cb_finished);
//
//    if (!state || state->error_status != 0) {
//        return 1;
//    }
//
//    free(download_file);
//
//    if (uv_run(env->loop, UV_RUN_DEFAULT)) {
//        return 1;
//    }
//
//    storj_destroy_env(env);
//
//    return 0;
//}
//
//int test_download()
//{
//    return _test_download(&encrypt_options, check_resolve_file);
//}
//
//int test_download_cancel()
//{
//
//    // initialize event loop and environment
//    storj_env_t *env = storj_init_env(&bridge_options,
//                                      &encrypt_options,
//                                      &http_options,
//                                      &log_options);
//    assert(env != NULL);
//
//    // resolve file
//    char *download_file = calloc(strlen(folder) + 33 + 1, sizeof(char));
//    strcpy(download_file, folder);
//    strcat(download_file, "storj-test-download-canceled.data");
//    FILE *download_fp = fopen(download_file, "w+");
//
//    char *bucket_id = "368be0816766b28fd5f43af5";
//    char *file_id = "998960317b6725a3f8080c2b";
//
//    storj_download_state_t *state = storj_bridge_resolve_file(env,
//                                                              bucket_id,
//                                                              file_id,
//                                                              download_fp,
//                                                              NULL,
//                                                              check_resolve_file_progress,
//                                                              check_resolve_file_cancel);
//
//    if (!state || state->error_status != 0) {
//        return 1;
//    }
//
//    // process the loop one at a time so that we can do other things while
//    // the loop is processing, such as cancel the download
//    int count = 0;
//    bool more;
//    int status = 0;
//    do {
//        more = uv_run(env->loop, UV_RUN_ONCE);
//        if (more == false) {
//            more = uv_loop_alive(env->loop);
//            if (uv_run(env->loop, UV_RUN_NOWAIT) != 0) {
//                more = true;
//            }
//        }
//
//        count++;
//
//        if (count == 100) {
//            status = storj_bridge_resolve_file_cancel(state);
//            assert(status == 0);
//        }
//
//    } while (more == true);
//
//
//    free(download_file);
//    storj_destroy_env(env);
//
//    return 0;
//}

int test_api()
{
    // initialize environment
    storj_env_t *env = storj_init_env(&bridge_options,
                                      &encrypt_options,
                                      NULL,
                                      &log_options);
    assert(strcmp("", *STORJ_LAST_ERROR) == 0);
    assert(env != NULL);

    int status;

    // create a new bucket with a name
    status = storj_bridge_create_bucket(env, test_bucket_name, NULL,
                                        check_create_bucket);
    assert(status == 0);
    assert(uv_run(env->loop, UV_RUN_ONCE) == 0);

    // get buckets
    status = storj_bridge_get_buckets(env, NULL, check_get_buckets);
    assert(status == 0);
    assert(uv_run(env->loop, UV_RUN_ONCE) == 0);

    // get bucket
    status = storj_bridge_get_bucket(env, test_bucket_name, NULL, check_get_bucket);
    assert(status == 0);
    assert(uv_run(env->loop, UV_RUN_ONCE) == 0);

    // get bucket id
    // NB: bucket id isn't a thing anymore; replacing id with the name.
    //      Additionally, buckets are always decrypted.
    status = storj_bridge_get_bucket_id(env, test_bucket_name, NULL, check_get_bucket_id);
    assert(status == 0);
    assert(uv_run(env->loop, UV_RUN_ONCE) == 0);

    // delete a bucket
    status = storj_bridge_delete_bucket(env, test_bucket_name,
                                        NULL, check_delete_bucket);
    assert(status == 0);
    assert(uv_run(env->loop, UV_RUN_ONCE) == 0);

    // list files in a bucket
    status = storj_bridge_list_files(env, test_bucket_name,
                                     NULL, check_list_files);
    assert(status == 0);

//    // get file id
//    status = storj_bridge_get_file_id(env, bucket_id, "storj-test-download.data",
//                                      NULL, check_get_file_id);
//    assert(status == 0);
//
//    char *file_id = "998960317b6725a3f8080c2b";
//
//    // delete a file in a bucket
//    status = storj_bridge_delete_file(env,
//                                      bucket_id,
//                                      file_id,
//                                      NULL,
//                                      check_delete_file);
//    assert(status == 0);
//
//    // get file information
//    status = storj_bridge_get_file_info(env, bucket_id,
//                                        file_id, NULL, check_file_info);
//    assert(status == 0);

    storj_destroy_env(env);
    return 0;
}

int main(void)
{
    // setup bridge options to point to testplanet
    bridge_options.addr = getenv("SATELLITE_0_ADDR");
    bridge_options.apikey = getenv("GATEWAY_0_API_KEY");

    // Make sure we have a tmp folder
    folder = getenv("TMPDIR");

    if (folder == 0) {
        printf("You need to set $TMPDIR before running. (e.g. export TMPDIR=/tmp/)\n");
        exit(1);
    }

    printf("Test Suite: API\n");
    test_api();
//    printf("\n");

//    printf("Test Suite: Uploads\n");
//    test_upload();
//    test_upload_cancel();
//    printf("\n");
//
//    printf("Test Suite: Downloads\n");
//    test_download();
//    test_download_null_mnemonic();
//    test_download_cancel();

    int num_failed = tests_ran - test_status;
    printf(KGRN "\nPASSED: %i" RESET, test_status);
    if (num_failed > 0) {
        printf(KRED " FAILED: %i" RESET, num_failed);
    }
    printf(" TOTAL: %i\n", (tests_ran));

    if (num_failed > 0) {
        return 1;
    }

    return 0;
}
