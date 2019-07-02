#include "storjtests.h"

//char *folder;
int tests_ran = 0;
int test_status = 0;
char *test_bucket_name = "test-bucket";

// setup bridge options to point to mock server
//storj_bridge_options_t bridge_options = {
//    getenv("SATELLITE_0_ADDR"),
//    getenv("GATEWAY_0_API_KEY")
//};

//// setup bridge options to point to mock server (with incorrect auth)
//storj_bridge_options_t bridge_options_bad = {
//    .addr  = getenv("SATELLITE_0_ADDR"),
//    .apikey  = "bad apikey"
//};
//
//storj_encrypt_options_t encrypt_options = {
//    .key = {}
//};

//storj_encrypt_options_t encrypt_options_null_mnemonic = {
//    .key = {}
//};
//
//storj_http_options_t http_options = {
//    .user_agent = "storj-test",
//    .low_speed_limit = 0,
//    .low_speed_time = 0,
//    .timeout = 0
//};
//
//storj_log_options_t log_options = {
//    .level = 0
//};

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
    assert(req->bucket->decrypted);

    pass("storj_bridge_get_bucket");

    storj_free_get_bucket_request(req);
    free(work_req);
}

//void check_get_bucket_id(uv_work_t *work_req, int status)
//{
//    assert(status == 0);
//    get_bucket_id_request_t *req = work_req->data;
//    assert(req->handle == NULL);
//    assert(strcmp(req->bucket_id, "368be0816766b28fd5f43af5") == 0);
//
//    pass("storj_bridge_get_bucket_id");
//
//    json_object_put(req->response);
//    free(req);
//    free(work_req);
//}
//
//void check_get_buckets_badauth(uv_work_t *work_req, int status)
//{
//    assert(status == 0);
//    get_buckets_request_t *req = work_req->data;
//    assert(req->handle == NULL);
//    assert(req->buckets == NULL);
//    assert(req->status_code == 401);
//
//    pass("storj_bridge_get_buckets_badauth");
//
//    storj_free_get_buckets_request(req);
//    free(work_req);
//}

void check_create_bucket(uv_work_t *work_req, int status)
{
    // TODO: assert req->error_code & req->status_code
    // (status_code is an http status)

    assert(status == 0);
    create_bucket_request_t *req = work_req->data;

    assert(req->bucket != NULL);
    assert(strcmp(req->bucket_name, test_bucket_name) == 0);
    assert(strcmp(req->bucket->name, test_bucket_name) == 0);
    assert(req->bucket->created != NULL);
    pass("storj_bridge_create_bucket");

    free(req->bucket);
    free(req);
    free(work_req);
}

//void check_delete_bucket(uv_work_t *work_req, int status)
//{
//    assert(status == 0);
//    json_request_t *req = work_req->data;
//    assert(req->handle == NULL);
//    assert(req->response == NULL);
//    assert(req->status_code == 204);
//
//    pass("storj_bridge_delete_bucket");
//
//    json_object_put(req->response);
//    free(req->path);
//    free(req);
//    free(work_req);
//}
//
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
//void check_list_files_badauth(uv_work_t *work_req, int status)
//{
//    assert(status == 0);
//    list_files_request_t *req = work_req->data;
//    assert(req->handle == NULL);
//    assert(req->response == NULL);
//    assert(req->files == NULL);
//    assert(req->status_code == 401);
//
//    pass("storj_bridge_list_files_badauth");
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
//void check_bucket_tokens(uv_work_t *work_req, int status)
//{
//    assert(status == 0);
//    json_request_t *req = work_req->data;
//    assert(req->handle == NULL);
//
//    struct json_object *value;
//    int success = json_object_object_get_ex(req->response, "token", &value);
//    assert(success == 1);
//    assert(json_object_is_type(value, json_type_string) == 1);
//
//    const char* token = json_object_get_string(value);
//
//    char *t = "a264e12611ad93b1777e82065f86cfcf088967dba2f15559cea5e140d5339a0e";
//
//    assert(strcmp(token, t) == 0);
//
//    pass("storj_bridge_create_bucket_token");
//
//    json_object_put(req->body);
//    json_object_put(req->response);
//    free(req->path);
//    free(req);
//    free(work_req);
//}
//
//void check_file_pointers(uv_work_t *work_req, int status)
//{
//    assert(status == 0);
//    json_request_t *req = work_req->data;
//    assert(req->handle == NULL);
//    assert(req->response);
//
//    assert(json_object_is_type(req->response, json_type_array) == 1);
//
//    struct json_object *bucket = json_object_array_get_idx(req->response, 0);
//    struct json_object* value;
//    int success = json_object_object_get_ex(bucket, "farmer", &value);
//    assert(success == 1);
//
//    pass("storj_bridge_get_file_pointers");
//
//    json_object_put(req->response);
//    free(req->path);
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
//void check_resolve_file_null_mnemonic(int status, FILE *fd, void *handle)
//{
//    fclose(fd);
//    assert(handle == NULL);
//    if (status == STORJ_FILE_DECRYPTION_ERROR) {
//        pass("storj_bridge_resolve_file_null_mnemonic");
//    } else {
//        fail("storj_bridge_resolve_file_null_mnemonic");
//        printf("Status: %d\n", status);
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
//
//void check_store_file_progress(double progress,
//                               uint64_t uploaded_bytes,
//                               uint64_t total_bytes,
//                               void *handle)
//{
//    assert(handle == NULL);
//    if (progress == (double)1) {
//        pass("storj_bridge_store_file (progress finished)");
//    }
//}
//
//void check_store_file(int error_code, storj_file_meta_t *file, void *handle)
//{
//    assert(handle == NULL);
//    if (error_code == 0) {
//        if (file && strcmp(file->id, "85fb0ed00de1196dc22e0f6d") == 0 ) {
//            pass("storj_bridge_store_file");
//        } else {
//            fail("storj_bridge_store_file(0)");
//        }
//    } else {
//        fail("storj_bridge_store_file(1)");
//        printf("\t\tERROR:   %s\n", storj_strerror(error_code));
//    }
//
//    storj_free_uploaded_file_info(file);
//}
//
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
//
//void check_create_frame(uv_work_t *work_req, int status)
//{
//    assert(status == 0);
//    json_request_t *req = work_req->data;
//    assert(req->handle == NULL);
//
//    struct json_object *value;
//    int success = json_object_object_get_ex(req->response, "id", &value);
//    assert(success == 1);
//    assert(json_object_is_type(value, json_type_string) == 1);
//
//    const char* id = json_object_get_string(value);
//
//    assert(strcmp(id, "d6367831f7f1b117ffdd0015") == 0);
//    pass("storj_bridge_create_frame");
//
//    json_object_put(req->response);
//    free(req);
//    free(work_req);
//}
//
//void check_get_frames(uv_work_t *work_req, int status)
//{
//    assert(status == 0);
//    json_request_t *req = work_req->data;
//    assert(req->handle == NULL);
//
//    struct json_object *file = json_object_array_get_idx(req->response, 0);
//    struct json_object *value;
//    int success = json_object_object_get_ex(file, "id", &value);
//    assert(success == 1);
//    assert(json_object_is_type(value, json_type_string) == 1);
//
//    const char* id = json_object_get_string(value);
//    assert(strcmp(id, "52b8cc8dfd47bb057d8c8a17") == 0);
//
//    pass("storj_bridge_get_frames");
//
//    json_object_put(req->response);
//    free(req);
//    free(work_req);
//}
//
//void check_get_frame(uv_work_t *work_req, int status)
//{
//    assert(status == 0);
//    json_request_t *req = work_req->data;
//    assert(req->handle == NULL);
//
//    struct json_object *value;
//    int success = json_object_object_get_ex(req->response, "id", &value);
//    assert(success == 1);
//    assert(json_object_is_type(value, json_type_string) == 1);
//
//    const char* id = json_object_get_string(value);
//
//    assert(strcmp(id, "192f90792f42875a7533340b") == 0);
//    pass("storj_bridge_get_frame");
//
//    json_object_put(req->response);
//    free(req->path);
//    free(req);
//    free(work_req);
//}
//
//void check_delete_frame(uv_work_t *work_req, int status)
//{
//    assert(status == 0);
//    json_request_t *req = work_req->data;
//    assert(req->handle == NULL);
//    assert(req->response == NULL);
//    assert(req->status_code == 200);
//
//    pass("storj_bridge_delete_frame");
//
//    json_object_put(req->response);
//    free(req->path);
//    free(req);
//    free(work_req);
//}
//
//void check_file_info(uv_work_t *work_req, int status)
//{
//    assert(status == 0);
//    get_file_info_request_t *req = work_req->data;
//    assert(req->handle == NULL);
//    assert(req->file);
//    assert(strcmp(req->file->filename, "storj-test-download.data") == 0);
//    assert(strcmp(req->file->mimetype, "video/ogg") == 0);
//
//    pass("storj_bridge_get_file_info");
//
//    storj_free_get_file_info_request(req);
//    free(work_req);
//}
//
//void check_list_mirrors(uv_work_t *work_req, int status)
//{
//    assert(status == 0);
//    json_request_t *req = work_req->data;
//    assert(req->handle == NULL);
//
//    assert(json_object_is_type(req->response, json_type_array) == 1);
//    struct json_object *firstShard = json_object_array_get_idx(req->response,
//                                                               0);
//    struct json_object *established;
//    struct json_object *available;
//    json_object_object_get_ex(firstShard, "established", &established);
//    json_object_object_get_ex(firstShard, "available", &available);
//    assert(json_object_is_type(established, json_type_array) == 1);
//    assert(json_object_is_type(established, json_type_array) == 1);
//
//    pass("storj_bridge_list_mirrors");
//
//    json_object_put(req->response);
//    free(req->path);
//    free(req);
//    free(work_req);
//}
//
//void check_register(uv_work_t *work_req, int status)
//{
//    assert(status == 0);
//    json_request_t *req = work_req->data;
//    assert(req->handle == NULL);
//    assert(req->status_code == 201);
//
//    struct json_object *value;
//    int success = json_object_object_get_ex(req->response, "email", &value);
//    assert(success == 1);
//    assert(json_object_is_type(value, json_type_string) == 1);
//
//    const char *email = json_object_get_string(value);
//
//    assert(strcmp(email, "test@test.com") == 0);
//    pass("storj_bridge_register");
//
//    json_object_put(req->body);
//    json_object_put(req->response);
//    free(req);
//    free(work_req);
//}
//
//int create_test_upload_file(char *filepath)
//{
//    FILE *fp;
//    fp = fopen(filepath, "w+");
//
//    if (fp == NULL) {
//        printf(KRED "Could not create upload file: %s\n" RESET, filepath);
//        exit(0);
//    }
//
//    int shard_size = 16777216;
//    char *bytes = "abcdefghijklmn";
//    for (int i = 0; i < strlen(bytes); i++) {
//        char *page = calloc(shard_size + 1, sizeof(char));
//        memset(page, bytes[i], shard_size);
//        fputs(page, fp);
//        free(page);
//    }
//
//    fclose(fp);
//    return 0;
//}
//
//int test_upload()
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
//        .fd = fopen(file, "r"),
//        .rs = true
//    };
//
//    storj_upload_state_t *state = storj_bridge_store_file(env,
//                                                          &upload_opts,
//                                                          NULL,
//                                                          check_store_file_progress,
//                                                          check_store_file);
//    if (!state || state->error_status != 0) {
//        return 1;
//    }
//
//    // run all queued events
//    if (uv_run(env->loop, UV_RUN_DEFAULT)) {
//        return 1;
//    }
//
//    free(file);
//    storj_destroy_env(env);
//
//    return 0;
//}
//
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
//int test_download_null_mnemonic()
//{
//    return _test_download(&encrypt_options_null_mnemonic, check_resolve_file_null_mnemonic);
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
//
//int test_api_badauth()
//{
//    // initialize event loop and environment
//    storj_env_t *env = storj_init_env(&bridge_options_bad,
//                                      &encrypt_options,
//                                      &http_options,
//                                      &log_options);
//
//    assert(env != NULL);
//
//    int status = 0;
//
//    // get buckets
//    status = storj_bridge_get_buckets(env, NULL, check_get_buckets_badauth);
//    assert(status == 0);
//
//    char *bucket_id = "368be0816766b28fd5f43af5";
//
//    // list files in a bucket
//    status = storj_bridge_list_files(env, bucket_id, NULL,
//                                     check_list_files_badauth);
//    assert(status == 0);
//
//    // run all queued events
//    if (uv_run(env->loop, UV_RUN_DEFAULT)) {
//        return 1;
//    }
//
//    storj_destroy_env(env);
//
//    return 0;
//}

int test_api()
{
    storj_bridge_options_t bridge_options = {
        .addr = getenv("SATELLITE_0_ADDR"),
        .apikey = getenv("GATEWAY_0_API_KEY")
    };

    storj_encrypt_options_t encrypt_options = {
        .key = { 0x00 }
    };

    // initialize environment
    storj_env_t *env = storj_init_env(&bridge_options,
                                      &encrypt_options,
                                      NULL,
                                      NULL);
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

//    char *bucket_id = "368be0816766b28fd5f43af5";

    // get bucket
    status = storj_bridge_get_bucket(env, test_bucket_name, NULL, check_get_bucket);
    assert(status == 0);
    assert(uv_run(env->loop, UV_RUN_ONCE) == 0);

//    // get bucket id
//    status = storj_bridge_get_bucket_id(env, "test", NULL, check_get_bucket_id);
//    assert(status == 0);
//
//    // delete a bucket
//    // TODO check for successful status code, response has object
//    status = storj_bridge_delete_bucket(env, bucket_id, NULL,
//                                        check_delete_bucket);
//    assert(status == 0);
//
//    // list files in a bucket
//    status = storj_bridge_list_files(env, bucket_id, NULL,
//                                     check_list_files);
//    assert(status == 0);
//
//    // get file id
//    status = storj_bridge_get_file_id(env, bucket_id, "storj-test-download.data",
//                                      NULL, check_get_file_id);
//    assert(status == 0);
//
//    // create bucket tokens
//    status = storj_bridge_create_bucket_token(env,
//                                              bucket_id,
//                                              BUCKET_PUSH,
//                                              NULL,
//                                              check_bucket_tokens);
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
//    // create a file frame
//    status = storj_bridge_create_frame(env, NULL, check_create_frame);
//    assert(status == 0);
//
//    // get frames
//    status = storj_bridge_get_frames(env, NULL, check_get_frames);
//    assert(status == 0);
//
//    char *frame_id = "d4af71ab00e15b0c1a7b6ab2";
//
//    // get frame
//    status = storj_bridge_get_frame(env, frame_id, NULL, check_get_frame);
//    assert(status == 0);
//
//    // delete frame
//    status = storj_bridge_delete_frame(env, frame_id, NULL, check_delete_frame);
//    assert(status == 0);
//
//    // get file information
//    status = storj_bridge_get_file_info(env, bucket_id,
//                                        file_id, NULL, check_file_info);
//    assert(status == 0);
//
//    // get file pointers
//    status = storj_bridge_get_file_pointers(env, bucket_id,
//                                            file_id, NULL, check_file_pointers);
//    assert(status == 0);
//
//    // get mirrors
//    status = storj_bridge_list_mirrors(env, bucket_id, file_id, NULL,
//                                       check_list_mirrors);
//    assert(status == 0);
//
//    // register a user
//    status = storj_bridge_register(env, "testuser@test.com", "asdf", NULL,
//                                   check_register);
//    assert(status == 0);

    // run all queued events
//    if (uv_run(env->loop, UV_RUN_DEFAULT)) {
//        return 1;
//    }

    storj_destroy_env(env);

    return 0;
}


//int test_mnemonic_check()
//{
//    static const char *vectors_ok[] = {
//        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
//        "legal winner thank year wave sausage worth useful legal winner thank yellow",
//        "letter advice cage absurd amount doctor acoustic avoid letter advice cage above",
//        "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong",
//        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon agent",
//        "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal will",
//        "letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter always",
//        "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo when",
//        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art",
//        "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth title",
//        "letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic bless",
//        "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo vote",
//        "jelly better achieve collect unaware mountain thought cargo oxygen act hood bridge",
//        "renew stay biology evidence goat welcome casual join adapt armor shuffle fault little machine walk stumble urge swap",
//        "dignity pass list indicate nasty swamp pool script soccer toe leaf photo multiply desk host tomato cradle drill spread actor shine dismiss champion exotic",
//        "afford alter spike radar gate glance object seek swamp infant panel yellow",
//        "indicate race push merry suffer human cruise dwarf pole review arch keep canvas theme poem divorce alter left",
//        "clutch control vehicle tonight unusual clog visa ice plunge glimpse recipe series open hour vintage deposit universe tip job dress radar refuse motion taste",
//        "turtle front uncle idea crush write shrug there lottery flower risk shell",
//        "kiss carry display unusual confirm curtain upgrade antique rotate hello void custom frequent obey nut hole price segment",
//        "exile ask congress lamp submit jacket era scheme attend cousin alcohol catch course end lucky hurt sentence oven short ball bird grab wing top",
//        "board flee heavy tunnel powder denial science ski answer betray cargo cat",
//        "board blade invite damage undo sun mimic interest slam gaze truly inherit resist great inject rocket museum chief",
//        "beyond stage sleep clip because twist token leaf atom beauty genius food business side grid unable middle armed observe pair crouch tonight away coconut",
//        0,
//    };
//    static const char *vectors_fail[] = {
//        "above abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
//        "above winner thank year wave sausage worth useful legal winner thank yellow",
//        "above advice cage absurd amount doctor acoustic avoid letter advice cage above",
//        "above zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong",
//        "above abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon agent",
//        "above winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal will",
//        "above advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter always",
//        "above zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo when",
//        "above abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art",
//        "above winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth title",
//        "above advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic bless",
//        "above zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo vote",
//        "above better achieve collect unaware mountain thought cargo oxygen act hood bridge",
//        "above stay biology evidence goat welcome casual join adapt armor shuffle fault little machine walk stumble urge swap",
//        "above pass list indicate nasty swamp pool script soccer toe leaf photo multiply desk host tomato cradle drill spread actor shine dismiss champion exotic",
//        "above alter spike radar gate glance object seek swamp infant panel yellow",
//        "above race push merry suffer human cruise dwarf pole review arch keep canvas theme poem divorce alter left",
//        "above control vehicle tonight unusual clog visa ice plunge glimpse recipe series open hour vintage deposit universe tip job dress radar refuse motion taste",
//        "above front uncle idea crush write shrug there lottery flower risk shell",
//        "above carry display unusual confirm curtain upgrade antique rotate hello void custom frequent obey nut hole price segment",
//        "above ask congress lamp submit jacket era scheme attend cousin alcohol catch course end lucky hurt sentence oven short ball bird grab wing top",
//        "above flee heavy tunnel powder denial science ski answer betray cargo cat",
//        "above blade invite damage undo sun mimic interest slam gaze truly inherit resist great inject rocket museum chief",
//        "above stage sleep clip because twist token leaf atom beauty genius food business side grid unable middle armed observe pair crouch tonight away coconut",
//        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
//        "winner thank year wave sausage worth useful legal winner thank yellow",
//        "advice cage absurd amount doctor acoustic avoid letter advice cage above",
//        "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong",
//        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon agent",
//        "winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal will",
//        "advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter always",
//        "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo when",
//        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art",
//        "winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth title",
//        "advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic bless",
//        "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo vote",
//        "better achieve collect unaware mountain thought cargo oxygen act hood bridge",
//        "stay biology evidence goat welcome casual join adapt armor shuffle fault little machine walk stumble urge swap",
//        "pass list indicate nasty swamp pool script soccer toe leaf photo multiply desk host tomato cradle drill spread actor shine dismiss champion exotic",
//        "alter spike radar gate glance object seek swamp infant panel yellow",
//        "race push merry suffer human cruise dwarf pole review arch keep canvas theme poem divorce alter left",
//        "control vehicle tonight unusual clog visa ice plunge glimpse recipe series open hour vintage deposit universe tip job dress radar refuse motion taste",
//        "front uncle idea crush write shrug there lottery flower risk shell",
//        "carry display unusual confirm curtain upgrade antique rotate hello void custom frequent obey nut hole price segment",
//        "ask congress lamp submit jacket era scheme attend cousin alcohol catch course end lucky hurt sentence oven short ball bird grab wing top",
//        "flee heavy tunnel powder denial science ski answer betray cargo cat",
//        "blade invite damage undo sun mimic interest slam gaze truly inherit resist great inject rocket museum chief",
//        "stage sleep clip because twist token leaf atom beauty genius food business side grid unable middle armed observe pair crouch tonight away coconut",
//        0,
//    };
//
//    const char **m;
//    int r;
//    int r2;
//    m = vectors_ok;
//    while (*m) {
//        r = mnemonic_check(*m);
//        r2 = storj_mnemonic_check(*m);
//        assert(r == 1);
//        assert(r2 == 1);
//        m++;
//    }
//    m = vectors_fail;
//    while (*m) {
//        r = mnemonic_check(*m);
//        r2 = mnemonic_check(*m);
//        assert(r == 0);
//        assert(r2 == 0);
//        m++;
//    }
//
//    pass("mnemonic_check");
//
//    return 0;
//}
//
//int test_storj_mnemonic_generate_256()
//{
//    int status;
//    int stren = 256;
//    char *mnemonic = NULL;
//    storj_mnemonic_generate(stren, &mnemonic);
//    status = storj_mnemonic_check(mnemonic);
//
//    if (status != 1) {
//        fail("test_mnemonic_generate");
//        printf("\t\texpected mnemonic check: %i\n", 0);
//        printf("\t\tactual mnemonic check:   %i\n", status);
//        free(mnemonic);
//        return 1;
//    }
//    free(mnemonic);
//
//    pass("test_storj_mnemonic_check_256");
//
//    return 0;
//}
//
//int test_storj_mnemonic_generate()
//{
//    int status;
//    int stren = 128;
//    char *mnemonic = NULL;
//    storj_mnemonic_generate(stren, &mnemonic);
//    status = storj_mnemonic_check(mnemonic);
//
//    if (status != 1) {
//        fail("test_mnemonic_generate");
//        printf("\t\texpected mnemonic check: %i\n", 0);
//        printf("\t\tactual mnemonic check:   %i\n", status);
//        free(mnemonic);
//        return 1;
//    }
//    free(mnemonic);
//
//    pass("test_storj_mnemonic_check");
//
//    return 0;
//}
//
//int test_mnemonic_generate()
//{
//    int status;
//    int stren = 128;
//    char *mnemonic = NULL;
//    mnemonic_generate(stren, &mnemonic);
//    status = mnemonic_check(mnemonic);
//
//    if (status != 1) {
//        fail("test_mnemonic_generate");
//        printf("\t\texpected mnemonic check: %i\n", 0);
//        printf("\t\tactual mnemonic check:   %i\n", status);
//        free(mnemonic);
//        return 1;
//    }
//    free(mnemonic);
//
//    pass("test_mnemonic_check");
//
//    return 0;
//}
//
//int test_generate_seed()
//{
//    char *mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
//    char *seed = calloc(128 + 1, sizeof(char));
//    char *expected_seed = "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4";
//
//    mnemonic_to_seed(mnemonic, "", &seed);
//    seed[128] = '\0';
//
//    int check = memcmp(seed, expected_seed, 128);
//    if (check != 0) {
//        fail("test_generate_seed");
//        printf("\t\texpected seed: %s\n", expected_seed);
//        printf("\t\tactual seed:   %s\n", seed);
//
//        free(seed);
//        return 1;
//    }
//
//    free(seed);
//    pass("test_generate_seed");
//
//    return 0;
//}
//
//int test_generate_seed_256()
//{
//    char *mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";
//    char *seed = calloc(128 + 1, sizeof(char));
//    char *expected_seed = "408b285c123836004f4b8842c89324c1f01382450c0d439af345ba7fc49acf705489c6fc77dbd4e3dc1dd8cc6bc9f043db8ada1e243c4a0eafb290d399480840";
//
//    mnemonic_to_seed(mnemonic, "", &seed);
//    seed[128] = '\0';
//
//    int check = memcmp(seed, expected_seed, 128);
//    if (check != 0) {
//        fail("test_generate_seed_256");
//        printf("\t\texpected seed: %s\n", expected_seed);
//        printf("\t\tactual seed:   %s\n", seed);
//
//        free(seed);
//        return 1;
//    }
//
//    free(seed);
//    pass("test_generate_seed_256");
//
//    return 0;
//}
//
//
//int test_generate_seed_256_trezor()
//{
//    char *mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";
//    char *seed = calloc(128 + 1, sizeof(char));
//    char *expected_seed = "bda85446c68413707090a52022edd26a1c9462295029f2e60cd7c4f2bbd3097170af7a4d73245cafa9c3cca8d561a7c3de6f5d4a10be8ed2a5e608d68f92fcc8";
//
//    mnemonic_to_seed(mnemonic, "TREZOR", &seed);
//    seed[128] = '\0';
//
//    int check = memcmp(seed, expected_seed, 128);
//    if (check != 0) {
//        fail("test_generate_seed_256_trezor");
//        printf("\t\texpected seed: %s\n", expected_seed);
//        printf("\t\tactual seed:   %s\n", seed);
//
//        free(seed);
//        return 1;
//    }
//
//    free(seed);
//    pass("test_generate_seed_256_trezor");
//
//    return 0;
//}
//
//int test_generate_seed_null_mnemonic()
//{
//    char *mnemonic = NULL;
//    char *seed = calloc(128 + 1, sizeof(char));
//    char *expected_seed = "4ed8d4b17698ddeaa1f1559f152f87b5d472f725ca86d341bd0276f1b61197e21dd5a391f9f5ed7340ff4d4513aab9cce44f9497a5e7ed85fd818876b6eb402e";
//
//    mnemonic_to_seed(mnemonic, "", &seed);
//    seed[128] = '\0';
//
//    int check = memcmp(seed, expected_seed, 128);
//    if (check != 0) {
//        fail("test_generate_seed");
//        printf("\t\texpected seed: %s\n", expected_seed);
//        printf("\t\tactual seed:   %s\n", seed);
//
//        free(seed);
//        return 1;
//    }
//
//    free(seed);
//    pass("test_generate_seed_null_mnemonic");
//
//    return 0;
//}
//
//int test_generate_bucket_key()
//{
//    char *mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
//    char *bucket_id = "0123456789ab0123456789ab";
//    char *bucket_key = calloc(DETERMINISTIC_KEY_SIZE + 1, sizeof(char));
//    char *expected_bucket_key = "b2464469e364834ad21e24c64f637c39083af5067693605c84e259447644f6f6";
//
//    generate_bucket_key(mnemonic, bucket_id, &bucket_key);
//    bucket_key[DETERMINISTIC_KEY_SIZE] = '\0';
//
//    int check = memcmp(expected_bucket_key, bucket_key, DETERMINISTIC_KEY_SIZE);
//    if (check != 0) {
//        fail("test_generate_bucket_key");
//        printf("\t\texpected bucket_key: %s\n", expected_bucket_key);
//        printf("\t\tactual bucket_key:   %s\n", bucket_key);
//
//        free(bucket_key);
//        return 1;
//    }
//
//    free(bucket_key);
//    pass("test_generate_bucket_key");
//
//    return 0;
//}
//
//int test_generate_file_key()
//{
//    char *mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
//    char *bucket_id = "0123456789ab0123456789ab";
//    char *file_name = "samplefile.txt";
//    char *index = "150589c9593bbebc0e795d8c4fa97304b42c110d9f0095abfac644763beca66e";
//    char *file_key = calloc(DETERMINISTIC_KEY_SIZE + 1, sizeof(char));
//    char *expected_file_key = "bb3552fc2e16d24a147af4b2d163e3164e6dbd04bbc45fc1c3eab69f384337e9";
//
//    generate_file_key(mnemonic, bucket_id, index, &file_key);
//
//    int check = strcmp(expected_file_key, file_key);
//    if (check != 0) {
//        fail("test_generate_file_key");
//        printf("\t\texpected file_key: %s\n", expected_file_key);
//        printf("\t\tactual file_key:   %s\n", file_key);
//
//        free(file_key);
//        return 1;
//    }
//
//    free(file_key);
//    pass("test_generate_file_key");
//
//    return 0;
//}
//
//int test_str2hex()
//{
//    char *data = "632442ba2e5f28a3a4e68dcb0b45d1d8f097d5b47479d74e2259055aa25a08aa";
//
//    uint8_t *buffer = str2hex(64, data);
//
//    uint8_t expected[32] = {99,36,66,186,46,95,40,163,164,230,141,203,11,69,
//                              209,216,240,151,213,180,116,121,215,78,34,89,5,
//                              90,162,90,8,170};
//
//    int failed = 0;
//    for (int i = 0; i < 32; i++) {
//        if (expected[i] != buffer[i]) {
//            failed = 1;
//        }
//    }
//
//    if (failed) {
//        fail("test_str2hex");
//    } else {
//        pass("test_str2hex");
//    }
//
//    free(buffer);
//
//    return 0;
//}
//
//int test_hex2str()
//{
//    uint8_t data[32] = {99,36,66,186,46,95,40,163,164,230,141,203,11,69,
//                              209,216,240,151,213,180,116,121,215,78,34,89,5,
//                              90,162,90,8,170};
//
//    char *result = hex2str(32, data);
//    if (!result) {
//        fail("test_hex2str");
//        return 0;
//    }
//
//    char *expected = "632442ba2e5f28a3a4e68dcb0b45d1d8f097d5b47479d74e2259055aa25a08aa";
//
//    int failed = 0;
//    if (strcmp(expected, result) != 0) {
//        failed = 1;
//    }
//
//    if (failed) {
//        fail("test_hex2str");
//    } else {
//        pass("test_hex2str");
//    }
//
//    free(result);
//
//    return 0;
//}
//
//int test_get_time_milliseconds()
//{
//    double time = get_time_milliseconds();
//
//    // TODO check against another source
//    if (time) {
//        pass("test_get_time_milliseconds");
//    } else {
//        fail("test_get_time_milliseconds");
//    }
//
//    return 0;
//}
//
//int test_determine_shard_size()
//{
//    uint64_t file_size;
//    uint64_t shard_size;
//    uint64_t expected_shard_size;
//
//    // 1000 bytes should be 8Mb
//    file_size = 1000;
//    expected_shard_size = 2097152;
//    shard_size = determine_shard_size(file_size, 0);
//
//    if (shard_size != expected_shard_size) {
//        fail("test_determine_shard_size");
//        printf("\t\texpected shard_size: %" PRIu64 "\n", expected_shard_size);
//        printf("\t\tactual shard_size:   %" PRIu64 "\n", shard_size);
//
//        return 1;
//    }
//
//    file_size = 134217729;
//    expected_shard_size = 16777216;
//    shard_size = determine_shard_size(file_size, 0);
//
//    if (shard_size != expected_shard_size) {
//        fail("test_determine_shard_size");
//        printf("\t\texpected shard_size: %" PRIu64 "\n", expected_shard_size);
//        printf("\t\tactual shard_size:   %" PRIu64 "\n", shard_size);
//
//        return 1;
//    }
//
//    file_size = 268435457;
//    expected_shard_size = 33554432;
//    shard_size = determine_shard_size(file_size, 0);
//
//    if (shard_size != expected_shard_size) {
//        fail("test_determine_shard_size");
//        printf("\t\texpected shard_size: %" PRIu64 "\n", expected_shard_size);
//        printf("\t\tactual shard_size:   %" PRIu64 "\n", shard_size);
//
//        return 1;
//    }
//
//    // Make sure we stop at max file size
//    file_size = 1012001737418240;
//    expected_shard_size = 4294967296;
//    shard_size = determine_shard_size(file_size, 0);
//
//    if (shard_size != expected_shard_size) {
//        fail("test_determine_shard_size");
//        printf("\t\texpected shard_size: %" PRIu64 "\n", expected_shard_size);
//        printf("\t\tactual shard_size:   %" PRIu64 "\n", shard_size);
//
//        return 1;
//    }
//
//    // Test fail case
//    file_size = 0;
//    expected_shard_size = 0;
//    shard_size = determine_shard_size(file_size, 0);
//
//    if (shard_size != expected_shard_size) {
//        fail("test_determine_shard_size");
//        printf("\t\texpected shard_size: %" PRIu64 "\n", expected_shard_size);
//        printf("\t\tactual shard_size:   %" PRIu64 "\n", shard_size);
//
//        return 1;
//    }
//
//    pass("test_determine_shard_size");
//
//    return 0;
//}
//
//int test_increment_ctr_aes_iv()
//{
//    uint8_t iv[16] = {188,14,95,229,78,112,182,107,
//                        34,206,248,225,52,22,16,183};
//
//    if (!increment_ctr_aes_iv(iv, 1)) {
//        fail("increment_ctr_aes_iv(0)");
//        return 1;
//    }
//
//    if (increment_ctr_aes_iv(iv, AES_BLOCK_SIZE)) {
//        fail("increment_ctr_aes_iv(1)");
//        return 1;
//    }
//
//    if (iv[15] != 184) {
//        fail("increment_ctr_aes_iv(2)");
//        return 1;
//    }
//
//    if (increment_ctr_aes_iv(iv, AES_BLOCK_SIZE * 72)) {
//        fail("increment_ctr_aes_iv(3)");
//        return 1;
//    }
//
//    if (iv[15] != 0 || iv[14] != 17) {
//        fail("increment_ctr_aes_iv(4)");
//        return 1;
//    }
//
//    pass("increment_ctr_aes_iv");
//    return 0;
//}
//
//int test_read_write_encrypted_file()
//{
//    // it should create file passed in if it does not exist
//    char test_file[1024];
//    strcpy(test_file, folder);
//    strcat(test_file, "storj-test-user.json");
//    if (access(test_file, F_OK) != -1) {
//        unlink(test_file);
//    }
//
//    // it should successfully encrypt and decrypt a file with the provided key and salt
//    char *expected_mnemonic = "letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic bless";
//    storj_encrypt_write_auth(test_file, "testpass",
//                             "testuser@storj.io", "bridgepass", expected_mnemonic);
//
//    char *bridge_user = NULL;
//    char *bridge_pass = NULL;
//    char *mnemonic = NULL;
//    if (storj_decrypt_read_auth(test_file, "testpass",
//                                &bridge_user, &bridge_pass, &mnemonic)) {
//        fail("test_storj_write_read_auth(0)");
//        return 1;
//    }
//
//    if (strcmp(bridge_user, "testuser@storj.io") != 0) {
//        fail("test_storj_write_read_auth(1)");
//        return 1;
//    }
//
//    if (strcmp(bridge_pass, "bridgepass") != 0) {
//        fail("test_storj_write_read_auth(2)");
//        return 1;
//    }
//
//    if (strcmp(mnemonic, expected_mnemonic) != 0) {
//        fail("test_storj_write_read_auth(3)");
//        return 1;
//    }
//
//    free(bridge_user);
//    free(bridge_pass);
//    free(mnemonic);
//
//    // it should fail to decrypt if the wrong password
//    if (!storj_decrypt_read_auth(test_file, "wrongpass",
//                                 &bridge_user, &bridge_pass, &mnemonic)) {
//        fail("test_storj_write_read_auth(4)");
//        return 1;
//    }
//
//    free(bridge_user);
//    free(bridge_pass);
//
//    pass("test_storj_write_read_auth");
//
//    return 0;
//}
//
//int test_meta_encryption_name(char *filename)
//{
//
//    uint8_t encrypt_key[32] = {215,99,0,133,172,219,64,35,54,53,171,23,146,160,
//                               81,126,137,21,253,171,48,217,184,188,8,137,3,
//                               4,83,50,30,251};
//    uint8_t iv[32] = {70,219,247,135,162,7,93,193,44,123,188,234,203,115,129,
//                      82,70,219,247,135,162,7,93,193,44,123,188,234,203,115,
//                      129,82};
//
//    char *buffer = NULL;
//    encrypt_meta(filename, encrypt_key, iv, &buffer);
//
//    char *buffer2 = NULL;
//    int status = decrypt_meta(buffer, encrypt_key, &buffer2);
//    if (status != 0) {
//        return 1;
//    }
//
//    if (strcmp(filename, buffer2) != 0) {
//        return 1;
//    }
//
//    free(buffer);
//    free(buffer2);
//
//    return 0;
//}
//
//int test_meta_encryption()
//{
//    for (int i = 1; i < 24; i++) {
//        char *filename = calloc(i + 1, sizeof(char));
//        memset(filename, 'a', i);
//        if (test_meta_encryption_name(filename)) {
//            fail("test_meta_encryption");
//            printf("Failed with filename: %s\n", filename);
//            return 1;
//        }
//        free(filename);
//    }
//    pass("test_meta_encryption");
//    return 0;
//}
//
//int test_memory_mapping()
//{
//
//    char *file_name = "storj-memory-map.data";
//    int len = strlen(folder) + strlen(file_name);
//    char *file = calloc(len + 1, sizeof(char));
//    strcpy(file, folder);
//    strcat(file, file_name);
//    file[len] = '\0';
//
//    create_test_upload_file(file);
//
//    FILE *fp = fopen(file, "r+");
//    int fd = fileno(fp);
//
//    if (!fp) {
//        printf("failed open.\n");
//        return 1;
//    }
//
//    fseek(fp, 0L, SEEK_END);
//    uint64_t filesize = ftell(fp);
//    rewind(fp);
//
//    uint8_t *map = NULL;
//    int error = map_file(fd, filesize, &map, false);
//    if (error) {
//        printf("failed to map file: %i\n", error);
//        fail("test_memory_mapping(0)");
//        return 1;
//    }
//
//    if (map[40001] != 97) {
//        fail("test_memory_mapping(1)");
//    }
//
//    map[40001] = 0;
//
//    error = unmap_file(map, filesize);
//    if (error) {
//        printf("failed to unmap file: %d", error);
//        fail("test_memory_mapping(2)");
//        return 1;
//    }
//
//    fclose(fp);
//
//    FILE *fp2 = fopen(file, "r+");
//    int fd2 = fileno(fp2);
//
//    if (!fp2) {
//        printf("failed open.\n");
//        return 1;
//    }
//
//    uint8_t *map2 = NULL;
//    error = map_file(fd2, filesize, &map2, false);
//    if (error) {
//        printf("failed to map file: %i\n", error);
//        fail("test_memory_mapping(3)");
//        return 1;
//    }
//
//    if (map2[40001] != 0) {
//        fail("test_memory_mapping(4)");
//    }
//
//    error = unmap_file(map2, filesize);
//    if (error) {
//        printf("failed to unmap file: %d", error);
//        fail("test_memory_mapping(5)");
//        return error;
//    }
//
//    fclose(fp2);
//    free(file);
//
//    pass("test_memory_mapping");
//
//    return 0;
//}
//
//int test_str_replace()
//{
//    char *subject = "g9qacwq2AE1+5nzL/HYyYdY9WoIr+1ueOuVEx6/IzzZKK9sULoKDDdYvhOpavHH2P3xQNw==";
//
//    char *result = str_replace("/", "%2F", subject);
//    if (!result) {
//        fail("test_str_replace");
//        return 0;
//    }
//
//    char *expected = "g9qacwq2AE1+5nzL%2FHYyYdY9WoIr+1ueOuVEx6%2FIzzZKK9sULoKDDdYvhOpavHH2P3xQNw==";
//
//    int failed = 0;
//    if (strcmp(expected, result) != 0) {
//        failed = 1;
//    }
//
//    if (failed) {
//        fail("test_str_replace");
//    } else {
//        pass("test_str_replace");
//    }
//
//    free(result);
//
//    return 0;
//}
//
//// Test Bridge Server
//struct MHD_Daemon *start_test_server()
//{
//    // spin up test bridge server
//    return MHD_start_daemon(MHD_USE_THREAD_PER_CONNECTION,
//                            8091,
//                            NULL,
//                            NULL,
//                            &mock_bridge_server,
//                            NULL,
//                            MHD_OPTION_END);
//}
//
int main(void)
{
//    // Make sure we have a tmp folder
//    folder = getenv("TMPDIR");
//
//    if (folder == 0) {
//        printf("You need to set $TMPDIR before running. (e.g. export TMPDIR=/tmp/)\n");
//        exit(1);
//    }
//
//    // spin up test bridge server
//    struct MHD_Daemon *d = start_test_server();
//    if (d == NULL) {
//        printf("Could not start test server.\n");
//        return 0;
//    };
//
//    // spin up test farmer server
//    struct MHD_Daemon *f = start_farmer_server();

    printf("Test Suite: API\n");
    test_api();
//    test_api_badauth();
    printf("\n");

//    printf("Test Suite: Uploads\n");
//    test_upload();
//    test_upload_cancel();
//    printf("\n");
//
//    printf("Test Suite: Downloads\n");
//    test_download();
//    test_download_null_mnemonic();
//    test_download_cancel();
//    printf("\n");
//
//    printf("Test Suite: BIP39\n");
//    test_mnemonic_check();
//    test_mnemonic_generate();
//    test_storj_mnemonic_generate();
//    test_storj_mnemonic_generate_256();
//    test_generate_seed();
//    test_generate_seed_256();
//    test_generate_seed_256_trezor();
//    test_generate_seed_null_mnemonic();
//    printf("\n");
//
//    printf("Test Suite: Crypto\n");
//    test_generate_bucket_key();
//    test_generate_file_key();
//    test_increment_ctr_aes_iv();
//    test_read_write_encrypted_file();
//    test_meta_encryption();
//    printf("\n");
//
//    printf("Test Suite: Utils\n");
//    test_str2hex();
//    test_hex2str();
//    test_get_time_milliseconds();
//    test_determine_shard_size();
//    test_memory_mapping();
//    test_str_replace();

    int num_failed = tests_ran - test_status;
    printf(KGRN "\nPASSED: %i" RESET, test_status);
    if (num_failed > 0) {
        printf(KRED " FAILED: %i" RESET, num_failed);
    }
    printf(" TOTAL: %i\n", (tests_ran));

//    // Shutdown test servers
//    MHD_stop_daemon(d);
//    MHD_stop_daemon(f);
//    free_farmer_data();

    if (num_failed > 0) {
        return 1;
    }

    return 0;
}
