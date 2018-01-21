#include "storjapi_callback.h"

static inline void noop() {};

static void get_input(char *line)
{
    if (fgets(line, BUFSIZ, stdin) == NULL) {
        line[0] = '\0';
    } else {
        int len = strlen(line);
        if (len > 0) {
            char *last = strrchr(line, '\n');
            if (last) {
                last[0] = '\0';
            }
            last = strrchr(line, '\r');
            if (last) {
                last[0] = '\0';
            }
        }
    }
}

static const char *get_filename_separator(const char *file_path)
{
    const char *file_name = NULL;
#ifdef _WIN32
    file_name = strrchr(file_path, '\\');
    if (!file_name) {
        file_name = strrchr(file_path, '/');
    }
    if (!file_name && file_path) {
        file_name = file_path;
    }
    if (!file_name) {
        return NULL;
    }
    if (file_name[0] == '\\' || file_name[0] == '/') {
        file_name++;
    }
#else
    file_name = strrchr(file_path, '/');
    if (!file_name && file_path) {
        file_name = file_path;
    }
    if (!file_name) {
        return NULL;
    }
    if (file_name[0] == '/') {
        file_name++;
    }
#endif
    return file_name;
}

static void close_signal(uv_handle_t *handle)
{
    ((void)0);
}

static void file_progress(double progress,
                          uint64_t downloaded_bytes,
                          uint64_t total_bytes,
                          void *handle)
{
    int bar_width = 70;

    if (progress == 0 && downloaded_bytes == 0) 
    {
        printf("Preparing File...");
        fflush(stdout);
        return;
    }

    printf("\r[");
    int pos = bar_width * progress;
    for (int i = 0; i < bar_width; ++i) 
    {
        if (i < pos) 
        {
            printf("=");
        } 
        else if (i == pos) 
        {
            printf(">");
        } 
        else 
        {
            printf(" ");
        }
    }
    printf("] %.*f%%", 2, progress * 100);

    fflush(stdout);
}

static void upload_file_complete(int status, char *file_id, void *handle)
{
    storj_api_t *storj_api = handle;
    storj_api->rcvd_cmd_resp = "upload-file-resp";

    printf("\n");
    if (status != 0) 
    {
        printf("Upload failure: %s\n", storj_strerror(status));
        exit(status);
    }

    printf("Upload Success! File ID: %s\n", file_id);

    queue_next_cmd_req(storj_api);
}

static void upload_signal_handler(uv_signal_t *req, int signum)
{
    storj_upload_state_t *state = req->data;
    storj_bridge_store_file_cancel(state);
    if (uv_signal_stop(req)) 
    {
        printf("Unable to stop signal\n");
    }
    uv_close((uv_handle_t *)req, close_signal);
}

static int upload_file(storj_env_t *env, char *bucket_id, const char *file_path, void *handle)
{
    FILE *fd = fopen(file_path, "r");

    if (!fd) 
    {
        printf("Invalid file path: %s\n", file_path);
    }

    const char *file_name = get_filename_separator(file_path);

    if (!file_name) 
    {
        file_name = file_path;
    }

    // Upload opts env variables:
    char *prepare_frame_limit = getenv("STORJ_PREPARE_FRAME_LIMIT");
    char *push_frame_limit = getenv("STORJ_PUSH_FRAME_LIMIT");
    char *push_shard_limit = getenv("STORJ_PUSH_SHARD_LIMIT");
    char *rs = getenv("STORJ_REED_SOLOMON");

    storj_upload_opts_t upload_opts = 
    {
        .prepare_frame_limit = (prepare_frame_limit) ? atoi(prepare_frame_limit) : 1,
        .push_frame_limit = (push_frame_limit) ? atoi(push_frame_limit) : 64,
        .push_shard_limit = (push_shard_limit) ? atoi(push_shard_limit) : 64,
        .rs = (!rs) ? true : (strcmp(rs, "false") == 0) ? false : true,
        .bucket_id = bucket_id,
        .file_name = file_name,
        .fd = fd
    };

    uv_signal_t *sig = malloc(sizeof(uv_signal_t));
    if (!sig) 
    {
        return 1;
    }
    uv_signal_init(env->loop, sig);
    uv_signal_start(sig, upload_signal_handler, SIGINT);



    storj_progress_cb progress_cb = (storj_progress_cb)noop;
    if (env->log_options->level == 0) 
    {
        progress_cb = file_progress;
    }

    storj_upload_state_t *state = storj_bridge_store_file(env,
                                                          &upload_opts,
                                                          handle,
                                                          progress_cb,
                                                          upload_file_complete);

    if (!state) {
        return 1;
    }

    sig->data = state;

    return state->error_status;
}

static void download_file_complete(int status, FILE *fd, void *handle)
{
    storj_api_t *storj_api = handle;
    storj_api->rcvd_cmd_resp = "download-file-resp";

    printf("\n");
    fclose(fd);
    if (status) {
        // TODO send to stderr
        switch(status) {
            case STORJ_FILE_DECRYPTION_ERROR:
                printf("Unable to properly decrypt file, please check " \
                       "that the correct encryption key was " \
                       "imported correctly.\n\n");
                break;
            default:
                printf("Download failure: %s\n", storj_strerror(status));
        }

        exit(status);
    }
    printf("Download Success!\n");

    queue_next_cmd_req(storj_api);
}

static void download_signal_handler(uv_signal_t *req, int signum)
{
    storj_download_state_t *state = req->data;
    storj_bridge_resolve_file_cancel(state);
    if (uv_signal_stop(req)) {
        printf("Unable to stop signal\n");
    }
    uv_close((uv_handle_t *)req, close_signal);
}

static int download_file(storj_env_t *env, char *bucket_id,
                         char *file_id, char *path, void *handle)
{
    FILE *fd = NULL;

    if (path) {
        char user_input[BUFSIZ];
        memset(user_input, '\0', BUFSIZ);

        if(access(path, F_OK) != -1 ) {
            printf("Warning: File already exists at path [%s].\n", path);
            while (strcmp(user_input, "y") != 0 && strcmp(user_input, "n") != 0)
            {
                memset(user_input, '\0', BUFSIZ);
                printf("Would you like to overwrite [%s]: [y/n] ", path);
                get_input(user_input);
            }

            if (strcmp(user_input, "n") == 0) {
                printf("\nCanceled overwriting of [%s].\n", path);
                return 1;
            }

            unlink(path);
        }

        fd = fopen(path, "w+");
    } else {
        fd = stdout;
    }

    if (fd == NULL) {
        // TODO send to stderr
        printf("Unable to open %s: %s\n", path, strerror(errno));
        return 1;
    }

    uv_signal_t *sig = malloc(sizeof(uv_signal_t));
    uv_signal_init(env->loop, sig);
    uv_signal_start(sig, download_signal_handler, SIGINT);

    storj_progress_cb progress_cb = (storj_progress_cb)noop;
    if (path && env->log_options->level == 0) {
        progress_cb = file_progress;
    }

    storj_download_state_t *state = storj_bridge_resolve_file(env, bucket_id,
                                                              file_id, fd, handle,
                                                              progress_cb,
                                                              download_file_complete);
    if (!state) {
        return 1;
    }
    sig->data = state;

    return state->error_status;
}

static void list_mirrors_callback(uv_work_t *work_req, int status)
{
    assert(status == 0);
    json_request_t *req = work_req->data;

    storj_api_t *storj_api = req->handle;
    storj_api->last_cmd_req = storj_api->curr_cmd_req;
    storj_api->rcvd_cmd_resp = "list-mirrors-resp";

    if (req->status_code != 200) {
        printf("Request failed with status code: %i\n",
               req->status_code);
        goto cleanup;
    }

    if (req->response == NULL) {
        free(req);
        free(work_req);
        printf("Failed to list mirrors.\n");
        goto cleanup;
    }

    int num_mirrors = json_object_array_length(req->response);

    struct json_object *shard;
    struct json_object *established;
    struct json_object *available;
    struct json_object *item;
    struct json_object *hash;
    struct json_object *contract;
    struct json_object *address;
    struct json_object *port;
    struct json_object *node_id;

    for (int i = 0; i < num_mirrors; i++) {
        shard = json_object_array_get_idx(req->response, i);
        json_object_object_get_ex(shard, "established",
                                 &established);
        int num_established =
            json_object_array_length(established);
        for (int j = 0; j < num_established; j++) {
            item = json_object_array_get_idx(established, j);
            if (j == 0) {
                json_object_object_get_ex(item, "shardHash",
                                          &hash);
                printf("Shard %i: %s\n", i, json_object_get_string(hash));
            }
            json_object_object_get_ex(item, "contract", &contract);
            json_object_object_get_ex(contract, "farmer_id", &node_id);

            const char *node_id_str = json_object_get_string(node_id);
            printf("\tnodeID: %s\n", node_id_str);
        }
        printf("\n\n");
    }

    json_object_put(req->response);

    queue_next_cmd_req(storj_api);
cleanup:
    free(req->path);
    free(req);
    free(work_req);
}

static void delete_file_callback(uv_work_t *work_req, int status)
{
    assert(status == 0);
    json_request_t *req = work_req->data;

    storj_api_t *storj_api = req->handle;
    storj_api->last_cmd_req = storj_api->curr_cmd_req;
    storj_api->rcvd_cmd_resp = "remove-file-resp";

    if (req->status_code == 200 || req->status_code == 204) {
        printf("File was successfully removed from bucket.\n");
    } else if (req->status_code == 401) {
        printf("Invalid user credentials.\n");
        goto cleanup;
    } else {
        printf("Failed to remove file from bucket. (%i)\n", req->status_code);
        goto cleanup;
    }

    json_object_put(req->response);

    queue_next_cmd_req(storj_api);
cleanup:
    free(req->path);
    free(req);
    free(work_req);
}

static void delete_bucket_callback(uv_work_t *work_req, int status)
{
    assert(status == 0);
    json_request_t *req = work_req->data;

    storj_api_t *storj_api = req->handle;
    storj_api->last_cmd_req = storj_api->curr_cmd_req;
    storj_api->rcvd_cmd_resp = "remove-bucket-resp";

    if (req->status_code == 200 || req->status_code == 204)
    {
        printf("Bucket was successfully removed.\n");
    } 
    else if (req->status_code == 401)
    {
        printf("Invalid user credentials.\n");
        goto cleanup;
    } 
    else
    {
        printf("Failed to destroy bucket. (%i)\n", req->status_code);
        goto cleanup;
    }

    json_object_put(req->response);

    queue_next_cmd_req(storj_api);
cleanup:
    free(req->path);
    free(req);
    free(work_req);
}

void get_bucket_id_callback(uv_work_t *work_req, int status)
{
    int ret_status = 0x00;
    assert(status == 0);
    get_buckets_request_t *req = work_req->data;
    storj_api_t *storj_api = req->handle;

    storj_api->last_cmd_req = storj_api->curr_cmd_req;
    storj_api->rcvd_cmd_resp = "get-bucket-id-resp";

    if (req->status_code == 401)
    {
        printf("Invalid user credentials.\n");
        goto cleanup;
    } 
    else if (req->status_code != 200 && req->status_code != 304)
    {
        printf("Request failed with status code: %i\n", req->status_code);
        goto cleanup;
    } 
    else if (req->total_buckets == 0)
    {
        printf("No buckets.\n");
        goto cleanup;
    }

    for (int i = 0; i < req->total_buckets; i++)
    {
        storj_bucket_meta_t *bucket = &req->buckets[i];

        if (strcmp(storj_api->bucket_name, bucket->name) == 0x00)
        {
            printf("ID: %s \tDecrypted: %s \tCreated: %s \tName: %s\n",
                   bucket->id, bucket->decrypted ? "true" : "false",
                   bucket->created, bucket->name);

            /* store the bucket id */
            storj_api->bucket_id = (char *)bucket->id;

            break;
        } 
        else
        {
            if (i >= (req->total_buckets - 1))
            {
                printf("Invalid bucket name. \n");
                goto cleanup;
            }
        }
    }

    queue_next_cmd_req(storj_api);

cleanup:
    storj_free_get_buckets_request(req);
    free(work_req);
}


void list_files_callback(uv_work_t *work_req, int status)
{
    int ret_status = 0;
    assert(status == 0);
    list_files_request_t *req = work_req->data;

    storj_api_t *storj_api = req->handle;
    storj_api->last_cmd_req = storj_api->curr_cmd_req;
    storj_api->rcvd_cmd_resp = "list-files-resp";

    if (req->status_code == 404)
    {
        printf("Bucket id [%s] does not exist\n", req->bucket_id);
        goto cleanup;
    } 
    else if (req->status_code == 400)
    {
        printf("Bucket id [%s] is invalid\n", req->bucket_id);
        goto cleanup;
    } 
    else if (req->status_code == 401)
    {
        printf("Invalid user credentials.\n");
        goto cleanup;
    } 
    else if (req->status_code != 200)
    {
        printf("Request failed with status code: %i\n", req->status_code);
    }

    if (req->total_files == 0)
    {
        printf("No files for bucket.\n");
        goto cleanup;
    }

    storj_api->file_id = NULL;
    for (int i = 0; i < req->total_files; i++)
    {
        storj_file_meta_t *file = &req->files[i];

        if ((storj_api->file_name != NULL) &&
            (strcmp(storj_api->file_name, file->filename)) == 0x00)
        {
            /* store the file id */
            storj_api->file_id = (char *)file->id;
        }

        printf("ID: %s \tSize: %" PRIu64 " bytes \tDecrypted: %s \tType: %s \tCreated: %s \tName: %s\n",
               file->id,
               file->size,
               file->decrypted ? "true" : "false",
               file->mimetype,
               file->created,
               file->filename);
    }

    queue_next_cmd_req(storj_api);

  cleanup:

    storj_free_list_files_request(req);
    free(work_req);
}

void queue_next_cmd_req(storj_api_t *storj_api)
{
    void *handle = storj_api->handle;

    if (strcmp(storj_api->excp_cmd_resp, storj_api->rcvd_cmd_resp) == 0x00)
    {
        printf("[%s][%d]expt resp = %s; rcvd resp = %s \n",
               __FUNCTION__, __LINE__,
                storj_api->excp_cmd_resp, storj_api->rcvd_cmd_resp );
        printf("[%s][%d]last cmd = %s; cur cmd = %s; next cmd = %s\n",
               __FUNCTION__, __LINE__, storj_api->last_cmd_req, 
               storj_api->curr_cmd_req, storj_api->next_cmd_req);

        if ((storj_api->next_cmd_req != NULL) && 
            (strcmp(storj_api->next_cmd_req, "list-files-req") == 0x00))
        {
            storj_api->curr_cmd_req  = storj_api->next_cmd_req;
            storj_api->next_cmd_req  = storj_api->final_cmd_req;
            storj_api->final_cmd_req = NULL;
            storj_api->excp_cmd_resp = "list-files-resp";

            storj_bridge_list_files(storj_api->env, storj_api->bucket_id, 
                                    storj_api, list_files_callback);
        }
        else if ((storj_api->next_cmd_req != NULL) && 
                 (strcmp(storj_api->next_cmd_req, "remove-bucket-req") == 0x00))
        {
            storj_api->curr_cmd_req  = storj_api->next_cmd_req;
            storj_api->next_cmd_req  = storj_api->final_cmd_req;
            storj_api->final_cmd_req = NULL;
            storj_api->excp_cmd_resp = "remove-bucket-resp";

            storj_bridge_delete_bucket(storj_api->env, storj_api->bucket_id, 
                                       storj_api, delete_bucket_callback);
        }
        else if ((storj_api->next_cmd_req != NULL) && 
                 (strcmp(storj_api->next_cmd_req, "remove-file-req") == 0x00))
        {
            if (storj_api->file_id != NULL)
            {
                printf("[%s][%d]file-name = %s; file-id = %s; bucket-name = %s \n",
                       __FUNCTION__, __LINE__, storj_api->file_name, storj_api->file_id,
                       storj_api->bucket_name);

                storj_api->curr_cmd_req  = storj_api->next_cmd_req;
                storj_api->next_cmd_req  = storj_api->final_cmd_req;
                storj_api->final_cmd_req = NULL;
                storj_api->excp_cmd_resp = "remove-file-resp";

                storj_bridge_delete_file(storj_api->env, storj_api->bucket_id, storj_api->file_id,
                                         storj_api, delete_file_callback);
            }
            else
            {
                printf("\'%s\' file doesn't exists in \'%s\' bucket\n", 
                       storj_api->file_name, storj_api->bucket_name);
            }
        }
        else if ((storj_api->next_cmd_req != NULL) && 
                 (strcmp(storj_api->next_cmd_req, "list-mirrors-req") == 0x00))
        {
            if (storj_api->file_id != NULL)
            {   
                printf("[%s][%d]file-name = %s; file-id = %s; bucket-name = %s \n",
                       __FUNCTION__, __LINE__, storj_api->file_name, storj_api->file_id,
                       storj_api->bucket_name);

                storj_api->curr_cmd_req  = storj_api->next_cmd_req;
                storj_api->next_cmd_req  = storj_api->final_cmd_req;
                storj_api->final_cmd_req = NULL;
                storj_api->excp_cmd_resp = "list-mirrors-resp";

                storj_bridge_list_mirrors(storj_api->env, storj_api->bucket_id, storj_api->file_id,
                                          storj_api, list_mirrors_callback);
            }
            else
            {
                printf("\'%s\' file doesn't exists in \'%s\' bucket\n", 
                       storj_api->file_name, storj_api->bucket_name);
            }
        }
        else if ((storj_api->next_cmd_req != NULL) && 
                 (strcmp(storj_api->next_cmd_req, "upload-file-req") == 0x00))
        {
            storj_api->curr_cmd_req  = storj_api->next_cmd_req;
            storj_api->next_cmd_req  = storj_api->final_cmd_req;
            storj_api->final_cmd_req = NULL;
            storj_api->excp_cmd_resp = "upload-file-resp";

            upload_file(storj_api->env, storj_api->bucket_id, storj_api->file_name, storj_api);
        }
        else if ((storj_api->next_cmd_req != NULL) && 
                 (strcmp(storj_api->next_cmd_req, "download-file-req") == 0x00))
        {
            storj_api->curr_cmd_req  = storj_api->next_cmd_req;
            storj_api->next_cmd_req  = storj_api->final_cmd_req;
            storj_api->final_cmd_req = NULL;
            storj_api->excp_cmd_resp = "download-file-resp";
            printf("\n\nAM here ....\n\n");

            printf("dst_file= %s\n", storj_api->dst_file);
            download_file(storj_api->env, storj_api->bucket_id, storj_api->file_id, 
                          storj_api->dst_file, storj_api);
        }
        else
        {
            printf("[%s][%d] **** ALL CLEAN & DONE  *****\n", 
                   __FUNCTION__, __LINE__);
            exit(0);
        }
    }
    else
    {
        printf("[%s][%d]Oops !!!! expt resp = %s; rcvd resp = %s \n",
               __FUNCTION__, __LINE__,
                storj_api->excp_cmd_resp, storj_api->rcvd_cmd_resp );
        printf("[%s][%d]last cmd = %s; cur cmd = %s; next cmd = %s\n",
               __FUNCTION__, __LINE__, storj_api->last_cmd_req, 
               storj_api->curr_cmd_req, storj_api->next_cmd_req);
    }
}
