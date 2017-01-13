#include "downloader.h"

// TODO memory cleanup

static void request_token(uv_work_t *work)
{
    token_request_download_t *req = work->data;

    char *path = ne_concat("/buckets/", req->bucket_id, "/tokens", NULL);

    struct json_object *body = json_object_new_object();
    json_object *op_string = json_object_new_string(req->bucket_op);
    json_object_object_add(body, "operation", op_string);

    int status_code = 0;
    struct json_object *response = fetch_json(req->http_options,
                                              req->options,
                                              "POST",
                                              path,
                                              body,
                                              true,
                                              NULL,
                                              &status_code);

    if (status_code == 201) {
        struct json_object *token_value;
        if (!json_object_object_get_ex(response, "token", &token_value)) {
            req->error_status = STORJ_BRIDGE_JSON_ERROR;
        }

        if (!json_object_is_type(token_value, json_type_string) == 1) {
            req->error_status = STORJ_BRIDGE_JSON_ERROR;
        }

        req->token = (char *)json_object_get_string(token_value);

        free(token_value);

    } else if (status_code == 403 || status_code == 401) {
        req->error_status = STORJ_BRIDGE_AUTH_ERROR;
    } else if (status_code == 404) {
        req->error_status = STORJ_BRIDGE_BUCKET_NOTFOUND_ERROR;
    } else if (status_code == 500) {
        req->error_status = STORJ_BRIDGE_INTERNAL_ERROR;
    } else {
        req->error_status = STORJ_BRIDGE_REQUEST_ERROR;
    }

    req->status_code = status_code;

    free(response);
    free(body);
}

static void after_request_token(uv_work_t *work, int status)
{
    token_request_download_t *req = work->data;

    req->state->pending_work_count--;
    req->state->requesting_token = false;

    if (status != 0) {
        req->state->error_status = STORJ_BRIDGE_TOKEN_ERROR;
    } else if (req->status_code == 201) {
        req->state->token = req->token;
    } else if (req->error_status){
        switch (req->error_status) {
            case STORJ_BRIDGE_REQUEST_ERROR:
            case STORJ_BRIDGE_INTERNAL_ERROR:
                req->state->token_fail_count += 1;
                break;
            default:
                req->state->error_status = req->error_status;
                break;
        }
        if (req->state->token_fail_count >= STORJ_MAX_TOKEN_TRIES) {
            req->state->token_fail_count = 0;
            req->state->error_status = req->error_status;
        }

    } else {
        req->state->error_status = STORJ_BRIDGE_TOKEN_ERROR;
    }

    queue_next_work(req->state);

    free(req);
    free(work);
}

static int queue_request_bucket_token(storj_download_state_t *state)
{
    if (state->requesting_token) {
        return 0;
    }

    uv_work_t *work = malloc(sizeof(uv_work_t));
    assert(work != NULL);

    token_request_download_t *req = malloc(sizeof(token_request_download_t));
    assert(req != NULL);

    req->http_options = state->env->http_options;
    req->options = state->env->bridge_options;
    req->bucket_id = state->bucket_id;
    req->bucket_op = (char *)BUCKET_OP[BUCKET_PULL];
    req->state = state;
    work->data = req;

    state->pending_work_count++;
    int status = uv_queue_work(state->env->loop, (uv_work_t*) work,
                               request_token, after_request_token);

    // TODO check status
    state->requesting_token = true;

    return status;

}

static void request_pointers(uv_work_t *work)
{
    json_request_download_t *req = work->data;

    int status_code = 0;
    req->response = fetch_json(req->http_options, req->options, req->method,
                               req->path, req->body, req->auth, req->token,
                               &status_code);

    req->status_code = status_code;

    if (!req->response) {
        req->status_code = -1;
    }
}

static void request_replace_pointer(uv_work_t *work)
{
    json_request_replace_pointer_t *req = work->data;

    int status_code = 0;

    char query_args[32 + strlen(req->excluded_farmer_ids)];
    ne_snprintf(query_args, 25 + strlen(req->excluded_farmer_ids),
                "?limit=1&skip=%i&exclude=%s",
                req->pointer_index,
                req->excluded_farmer_ids);

    char *path = ne_concat("/buckets/", req->bucket_id, "/files/",
                           req->file_id, query_args, NULL);

    req->response = fetch_json(req->http_options, req->options, "GET",
                               path, NULL, NULL, req->token, &status_code);

    req->status_code = status_code;

    if (!req->response) {
        req->status_code = -1;
    }
}

static void set_pointer_from_json(storj_download_state_t *state,
                                  storj_pointer_t *p,
                                  struct json_object *json,
                                  bool is_replaced)
{
    // TODO free existing values if is replaced?

    if (!json_object_is_type(json, json_type_object)) {
        state->error_status = STORJ_BRIDGE_JSON_ERROR;
        return;
    }

    struct json_object *token_value;
    if (!json_object_object_get_ex(json, "token", &token_value)) {
        state->error_status = STORJ_BRIDGE_JSON_ERROR;
        return;
    }
    char *token = (char *)json_object_get_string(token_value);

    struct json_object *hash_value;
    if (!json_object_object_get_ex(json, "hash", &hash_value)) {
        state->error_status = STORJ_BRIDGE_JSON_ERROR;
        return;
    }
    char *hash = (char *)json_object_get_string(hash_value);

    struct json_object *size_value;
    if (!json_object_object_get_ex(json, "size", &size_value)) {
        state->error_status = STORJ_BRIDGE_JSON_ERROR;
        return;
    }
    uint64_t size = json_object_get_int64(size_value);


    struct json_object *index_value;
    if (!json_object_object_get_ex(json, "index", &index_value)) {
        state->error_status = STORJ_BRIDGE_JSON_ERROR;
        return;
    }
    uint32_t index = json_object_get_int(index_value);

    struct json_object *farmer_value;
    if (!json_object_object_get_ex(json, "farmer", &farmer_value)) {
        state->error_status = STORJ_BRIDGE_JSON_ERROR;
        return;
    }
    if (!json_object_is_type(farmer_value, json_type_object)) {
        state->error_status = STORJ_BRIDGE_JSON_ERROR;
        return;
    }

    struct json_object *address_value;
    if (!json_object_object_get_ex(farmer_value, "address",
                                   &address_value)) {
        state->error_status = STORJ_BRIDGE_JSON_ERROR;
        return;
    }
    char *address = (char *)json_object_get_string(address_value);

    struct json_object *port_value;
    if (!json_object_object_get_ex(farmer_value, "port", &port_value)) {
        state->error_status = STORJ_BRIDGE_JSON_ERROR;
        return;
    }
    uint32_t port = json_object_get_int(port_value);

    struct json_object *farmer_id_value;
    if (!json_object_object_get_ex(farmer_value, "nodeID",
                                   &farmer_id_value)) {
        state->error_status = STORJ_BRIDGE_JSON_ERROR;
        return;
    }
    char *farmer_id = (char *)json_object_get_string(farmer_id_value);

    free(token_value);
    free(hash_value);
    free(size_value);
    free(index_value);
    free(address_value);
    free(port_value);
    free(farmer_id_value);

    if (is_replaced) {
        p->replace_count += 1;
    } else {
        p->replace_count = 0;
    }

    // reset the status
    p->status = POINTER_CREATED;

    p->token = token;
    p->shard_hash = hash;
    p->size = size;
    p->downloaded_size = 0;
    p->index = index;
    p->farmer_address = address;
    p->farmer_port = port;
    p->farmer_id = farmer_id;

    // setup exchange report values
    p->report = malloc(
        sizeof(storj_exchange_report_t));

    char *client_id = state->env->bridge_options->user;
    p->report->reporter_id = client_id;
    p->report->client_id = client_id;
    p->report->data_hash = hash;
    p->report->farmer_id = farmer_id;
    p->report->send_status = 0; // not sent
    p->report->send_count = 0;

    // these values will be changed in after_request_shard
    p->report->start = 0;
    p->report->end = 0;
    p->report->code = STORJ_REPORT_FAILURE;
    p->report->message = STORJ_REPORT_DOWNLOAD_ERROR;

    p->work = NULL;

    if (!state->shard_size) {
        // TODO make sure all except last shard is the same size
        state->shard_size = size;
    };
}

static void append_pointers_to_state(storj_download_state_t *state,
                                     struct json_object *res)
{
    int length = json_object_array_length(res);

    if (length == 0) {
        state->pointers_completed = true;
    } else if (length > 0) {

        int prev_total_pointers = state->total_pointers;
        int total_pointers = state->total_pointers + length;

        if (state->total_pointers > 0) {
            state->pointers = realloc(state->pointers,
                                      total_pointers * sizeof(storj_pointer_t));
        } else {
            state->pointers = malloc(length * sizeof(storj_pointer_t) * 100);
        }

        state->total_pointers = total_pointers;
        state->total_shards = total_pointers;

        for (int i = 0; i < length; i++) {

            // get the relative index
            int j = i + prev_total_pointers;

            struct json_object *json = json_object_array_get_idx(res, i);

            set_pointer_from_json(state, &state->pointers[j], json, false);

            free(json);

        }
    }

}

static void after_request_pointers(uv_work_t *work, int status)
{
    json_request_download_t *req = work->data;

    req->state->pending_work_count--;
    req->state->requesting_pointers = false;

    // expired token
    req->state->token = NULL;

    if (status != 0)  {
        req->state->error_status = STORJ_BRIDGE_POINTER_ERROR;
    } else if (req->status_code != 200) {
        if (req->status_code > 0 && req->status_code < 500) {
            req->state->error_status = STORJ_BRIDGE_POINTER_ERROR;
        } else {
            req->state->pointer_fail_count += 1;
        }

        if (req->state->pointer_fail_count >= STORJ_MAX_POINTER_TRIES) {
            req->state->pointer_fail_count = 0;
            req->state->error_status = STORJ_BRIDGE_POINTER_ERROR;
        }

    } else if (!json_object_is_type(req->response, json_type_array)) {
        req->state->error_status = STORJ_BRIDGE_JSON_ERROR;
    } else {
        append_pointers_to_state(req->state, req->response);
    }

    queue_next_work(req->state);

    free(work->data);
    free(work);
}

static void after_request_replace_pointer(uv_work_t *work, int status)
{
    // TODO check status

    json_request_replace_pointer_t *req = work->data;

    req->state->pending_work_count--;
    req->state->requesting_pointers = false;

    // expired token
    req->state->token = NULL;

    if (status != 0) {
        req->state->error_status = STORJ_BRIDGE_REPOINTER_ERROR;
    } else if (req->status_code != 200) {
        req->state->error_status = STORJ_BRIDGE_REPOINTER_ERROR;

        if (req->status_code > 0 && req->status_code < 500) {
            req->state->error_status = STORJ_BRIDGE_POINTER_ERROR;
        } else {
            req->state->pointer_fail_count += 1;
        }

        if (req->state->pointer_fail_count >= STORJ_MAX_POINTER_TRIES) {
            req->state->pointer_fail_count = 0;
            req->state->error_status = STORJ_BRIDGE_POINTER_ERROR;
        }

    } else if (!json_object_is_type(req->response, json_type_array)) {
        req->state->error_status = STORJ_BRIDGE_JSON_ERROR;
    } else {
        struct json_object *json = json_object_array_get_idx(req->response, 0);
        // TODO check json

        // TODO check that the index of pointer matches what is expected
        // TODO check that the shard hash is the same

        set_pointer_from_json(req->state,
                              &req->state->pointers[req->pointer_index],
                              json,
                              true);
    }

    queue_next_work(req->state);

    free(work->data);
    free(work);

}

static void queue_request_pointers(storj_download_state_t *state)
{
    if (state->requesting_pointers) {
        return;
    }

    uv_work_t *work = malloc(sizeof(uv_work_t));
    assert(work != NULL);

    // queue request to replace pointer if any pointers have failure
    for (int i = 0; i < state->total_pointers; i++) {

        storj_pointer_t *pointer = &state->pointers[i];

        if (pointer->replace_count >= STORJ_DEFAULT_MIRRORS) {
            state->error_status = STORJ_FARMER_EXHAUSTED_ERROR;
            return;
        }

        if (pointer->status == POINTER_ERROR_REPORTED) {

            // exclude this farmer id from future requests
            if (!state->excluded_farmer_ids) {
                state->excluded_farmer_ids = calloc(41, sizeof(char));
                strcat(state->excluded_farmer_ids, pointer->report->farmer_id);
            } else {
                state->excluded_farmer_ids =
                    realloc(state->excluded_farmer_ids,
                            strlen(state->excluded_farmer_ids) + 41);

                strcat(state->excluded_farmer_ids, ",");
                strcat(state->excluded_farmer_ids, pointer->report->farmer_id);
            }

            json_request_replace_pointer_t *req =
                malloc(sizeof(json_request_replace_pointer_t));
            assert(req != NULL);

            req->pointer_index = i;

            req->http_options = state->env->http_options;
            req->options = state->env->bridge_options;
            req->token = state->token;
            req->bucket_id = state->bucket_id;
            req->file_id = state->file_id;
            req->state = state;
            req->excluded_farmer_ids = state->excluded_farmer_ids;

            work->data = req;

            state->pending_work_count++;
            int status = uv_queue_work(state->env->loop,
                                       (uv_work_t*) work,
                                       request_replace_pointer,
                                       after_request_replace_pointer);
            // TODO check status

            pointer->status = POINTER_BEING_REPLACED;

            // we're done until the next pass
            state->requesting_pointers = true;
            return;
        }

    }

    // only request the next set of pointers if we're not finished
    if (state->pointers_completed) {
        return;
    }

    json_request_download_t *req = malloc(sizeof(json_request_download_t));
    assert(req != NULL);

    char query_args[32];
    ne_snprintf(query_args, 20, "?limit=6&skip=%i", state->total_pointers);
    char *path = ne_concat("/buckets/", state->bucket_id, "/files/",
                           state->file_id, query_args, NULL);

    req->http_options = state->env->http_options;
    req->options = state->env->bridge_options;
    req->method = "GET";
    req->path = path;
    req->body = NULL;
    req->auth = true;
    req->token = state->token;

    req->state = state;

    work->data = req;

    state->pending_work_count++;
    int status = uv_queue_work(state->env->loop, (uv_work_t*) work,
                               request_pointers, after_request_pointers);

    // TODO check status
    state->requesting_pointers = true;
}

static void request_shard(uv_work_t *work)
{
    shard_request_download_t *req = work->data;

    int status_code;

    req->start = get_time_milliseconds();

    int error_status = fetch_shard(req->http_options, req->farmer_id,
                                   req->farmer_proto, req->farmer_host,
                                   req->farmer_port, req->shard_hash,
                                   req->shard_total_bytes, req->shard_data,
                                   req->token, &status_code,
                                   &req->progress_handle,
                                   req->cancelled);

    req->end = get_time_milliseconds();

    if (error_status) {
        req->error_status = error_status;
    } else if (status_code != 200) {
        switch(status_code) {
            case 401:
            case 403:
                req->error_status = STORJ_FARMER_AUTH_ERROR;
                break;
            case 504:
                req->error_status = STORJ_FARMER_TIMEOUT_ERROR;
                break;
            default:
                req->error_status = STORJ_FARMER_REQUEST_ERROR;
        }
    } else {
        // Decrypt the shard
        if (req->decrypt_key && req->decrypt_ctr) {
            struct aes256_ctx *ctx = malloc(sizeof(struct aes256_ctx));
            aes256_set_encrypt_key(ctx, req->decrypt_key);
            ctr_crypt(ctx, (nettle_cipher_func *)aes256_encrypt,
                      AES_BLOCK_SIZE, req->decrypt_ctr,
                      req->shard_total_bytes, req->shard_data, req->shard_data);
        }

        req->error_status = 0;
    }
}

static void free_request_shard_work(uv_handle_t *progress_handle)
{
    uv_work_t *work = progress_handle->data;

    free(work->data);
    free(work);
}

static void after_request_shard(uv_work_t *work, int status)
{
    // TODO check status
    shard_request_download_t *req = work->data;

    req->state->logger("Finished downloading shard: %s\n", req->shard_hash);

    req->state->pending_work_count--;
    req->state->resolving_shards -= 1;

    uv_handle_t *progress_handle = (uv_handle_t *) &req->progress_handle;

    // free the download progress
    free(progress_handle->data);

    // assign work so that we can free after progress_handle is closed
    progress_handle->data = work;

    // update the pointer status
    storj_pointer_t *pointer = &req->state->pointers[req->pointer_index];

    pointer->report->start = req->start;
    pointer->report->end = req->end;

    if (req->error_status) {
        pointer->status = POINTER_ERROR;

        switch(req->error_status) {
            case STORJ_FARMER_INTEGRITY_ERROR:
                pointer->report->code = STORJ_REPORT_FAILURE;
                pointer->report->message = STORJ_REPORT_FAILED_INTEGRITY;
            default:
                pointer->report->code = STORJ_REPORT_FAILURE;
                pointer->report->message = STORJ_REPORT_DOWNLOAD_ERROR;
        }
    } else {
        pointer->report->code = STORJ_REPORT_SUCCESS;
        pointer->report->message = STORJ_REPORT_SHARD_DOWNLOADED;
        pointer->status = POINTER_DOWNLOADED;
        pointer->shard_data = req->shard_data;
    }

    queue_next_work(req->state);

    // close the async progress handle
    uv_close(progress_handle, free_request_shard_work);
}

static void progress_request_shard(uv_async_t* async)
{

    shard_download_progress_t *progress = async->data;

    storj_download_state_t *state = progress->state;

    state->pointers[progress->pointer_index].downloaded_size = progress->bytes;

    uint64_t downloaded_bytes = 0;
    uint64_t total_bytes = 0;

    for (int i = 0; i < state->total_pointers; i++) {

        storj_pointer_t *pointer = &state->pointers[i];

        downloaded_bytes += pointer->downloaded_size;
        total_bytes += pointer->size;
    }

    double total_progress = (double)downloaded_bytes / (double)total_bytes;

    state->progress_cb(total_progress, downloaded_bytes, total_bytes);
}

static int queue_request_shards(storj_download_state_t *state)
{
    int i = 0;

    while (state->resolving_shards < STORJ_DOWNLOAD_CONCURRENCY &&
           i < state->total_pointers) {

        storj_pointer_t *pointer = &state->pointers[i];

        if (pointer->status == POINTER_CREATED) {
            shard_request_download_t *req = malloc(sizeof(shard_request_download_t));
            assert(req != NULL);

            req->http_options = state->env->http_options;
            req->farmer_id = pointer->farmer_id;
            req->farmer_proto = "http";
            req->farmer_host = pointer->farmer_address;
            req->farmer_port = pointer->farmer_port;
            req->shard_hash = pointer->shard_hash;
            req->shard_total_bytes = pointer->size;
            req->byte_position = state->shard_size * i;
            req->token = pointer->token;

            // TODO assert max bytes for shard
            req->shard_data = calloc(pointer->size, sizeof(char));

            if (state->decrypt_key && state->decrypt_ctr) {
                req->decrypt_key = calloc(SHA256_DIGEST_SIZE, sizeof(uint8_t));
                req->decrypt_ctr = calloc(AES_BLOCK_SIZE, sizeof(uint8_t));
                memcpy(req->decrypt_key, state->decrypt_key, SHA256_DIGEST_SIZE);
                memcpy(req->decrypt_ctr, state->decrypt_ctr, AES_BLOCK_SIZE);

                increment_ctr_aes_iv(req->decrypt_ctr, req->byte_position);
            } else {
                req->decrypt_key = NULL;
                req->decrypt_ctr = NULL;
            }

            req->pointer_index = pointer->index;

            req->state = state;
            req->cancelled = &state->cancelled;

            uv_work_t *work = malloc(sizeof(uv_work_t));
            assert(work != NULL);

            work->data = req;

            state->resolving_shards += 1;
            pointer->status = POINTER_BEING_DOWNLOADED;
            pointer->work = work;

            // setup download progress reporting
            shard_download_progress_t *progress =
                malloc(sizeof(shard_download_progress_t));

            progress->pointer_index = pointer->index;
            progress->bytes = 0;
            progress->state = state;

            req->progress_handle.data = progress;

            uv_async_init(state->env->loop, &req->progress_handle,
                          progress_request_shard);

            // queue download
            state->pending_work_count++;
            uv_queue_work(state->env->loop, (uv_work_t*) work,
                          request_shard, after_request_shard);
        }

        i++;
    }
}

static void write_shard(uv_work_t *work)
{
    shard_request_write_t *req = work->data;
    req->error_status = 0;

    if (req->shard_total_bytes != fwrite(req->shard_data,
                                         sizeof(char),
                                         req->shard_total_bytes,
                                         req->destination)) {

        req->error_status = ferror(req->destination);
    }
}

static void after_write_shard(uv_work_t *work, int status)
{
    shard_request_write_t *req = work->data;

    req->state->pending_work_count--;
    req->state->writing = false;

    if (status != 0) {
        req->state->error_status = STORJ_FILE_WRITE_ERROR;
    } else if (req->error_status) {
        req->state->error_status = STORJ_FILE_WRITE_ERROR;
    } else {
        // write success
        req->state->pointers[req->pointer_index].status = POINTER_WRITTEN;

        req->state->completed_shards += 1;

        storj_pointer_t *pointer = &req->state->pointers[req->pointer_index];

        free(pointer->shard_data);
    }

    queue_next_work(req->state);

    free(work->data);
    free(work);
}

static void queue_write_next_shard(storj_download_state_t *state)
{
    int i = 0;

    while (!state->writing && i < state->total_pointers) {
        storj_pointer_t *pointer = &state->pointers[i];

        if (pointer->status < POINTER_DOWNLOADED) {
            break;
        }

        if (pointer->status == POINTER_DOWNLOADED) {
            uv_work_t *work = malloc(sizeof(uv_work_t));
            assert(work != NULL);

            shard_request_write_t *req = malloc(sizeof(shard_request_write_t));

            req->shard_data = pointer->shard_data;
            req->shard_total_bytes = pointer->size;
            req->destination = state->destination;
            req->pointer_index = pointer->index;
            req->state = state;

            work->data = req;

            state->writing = true;
            pointer->status = POINTER_BEING_WRITTEN;

            state->pending_work_count++;
            uv_queue_work(state->env->loop, (uv_work_t*) work,
                          write_shard, after_write_shard);
            break;
        }

        i++;

    }
}

static void send_exchange_report(uv_work_t *work)
{
    shard_send_report_t *req = work->data;

    struct json_object *body = json_object_new_object();

    json_object_object_add(body, "dataHash",
                           json_object_new_string(req->report->data_hash));

    json_object_object_add(body, "reporterId",
                           json_object_new_string(req->report->reporter_id));

    json_object_object_add(body, "farmerId",
                           json_object_new_string(req->report->farmer_id));

    json_object_object_add(body, "clientId",
                           json_object_new_string(req->report->client_id));

    json_object_object_add(body, "exchangeStart",
                           json_object_new_int64(req->report->start));

    json_object_object_add(body, "exchangeEnd",
                           json_object_new_int64(req->report->end));

    json_object_object_add(body, "exchangeResultCode",
                           json_object_new_int(req->report->code));

    json_object_object_add(body, "exchangeResultMessage",
                           json_object_new_string(req->report->message));

    int status_code = 0;

    // there should be an empty object in response
    struct json_object *response = fetch_json(req->http_options,
                                              req->options, "POST",
                                              "/reports/exchanges", body,
                                              NULL, NULL, &status_code);
    req->status_code = status_code;

    free(body);
}

static void after_send_exchange_report(uv_work_t *work, int status)
{
    shard_send_report_t *req = work->data;

    req->state->pending_work_count--;

    // set status so that this pointer can be replaced
    if (req->report->send_count >= STORJ_MAX_REPORT_TRIES ||
        req->status_code == 201) {

        storj_pointer_t *pointer = &req->state->pointers[req->pointer_index];

        if (pointer->status == POINTER_ERROR) {
            pointer->status = POINTER_ERROR_REPORTED;
        }
    }

    if (req->status_code == 201) {
        // set the status so that this pointer can be replaced
        req->report->send_status = 2; // report has been sent
    } else {
        req->report->send_status = 0; // reset report back to unsent
    }

    queue_next_work(req->state);

    free(work->data);
    free(work);

}

static void queue_send_exchange_reports(storj_download_state_t *state)
{

    for (int i = 0; i < state->total_pointers; i++) {

        storj_pointer_t *pointer = &state->pointers[i];

        if (pointer->report->send_status < 1 &&
            pointer->report->send_count < STORJ_MAX_REPORT_TRIES &&
            pointer->report->start > 0 &&
            pointer->report->end > 0) {

            uv_work_t *work = malloc(sizeof(uv_work_t));
            assert(work != NULL);

            shard_send_report_t *req = malloc(sizeof(shard_send_report_t));

            req->http_options = state->env->http_options;
            req->options = state->env->bridge_options;
            req->status_code = 0;
            req->report = pointer->report;
            req->report->send_status = 1; // being reported
            req->report->send_count += 1;
            req->state = state;
            req->pointer_index = i;

            work->data = req;

            state->pending_work_count++;
            uv_queue_work(state->env->loop, (uv_work_t*) work,
                          send_exchange_report, after_send_exchange_report);
        }
    }
}

static void queue_next_work(storj_download_state_t *state)
{
    // report any errors
    if (state->error_status != 0) {
        if (!state->finished && state->pending_work_count == 0) {

            state->finished = true;
            state->finished_cb(state->error_status, state->destination);

            free(state->pointers);
            free(state);
        }

        return;
    }

    queue_write_next_shard(state);

    // report download complete
    if (state->pointers_completed &&
        state->completed_shards == state->total_shards) {

        if (!state->finished && state->pending_work_count == 0) {
            state->finished = true;
            state->finished_cb(0, state->destination);

            free(state->pointers);
            free(state);
        }

        return;
    }

    if (!state->token) {
        queue_request_bucket_token(state);
    }

    if (state->token) {
        queue_request_pointers(state);
    }

    queue_request_shards(state);

    // send back download status reports to the bridge
    queue_send_exchange_reports(state);
}

int storj_bridge_resolve_file_cancel(storj_download_state_t *state)
{
    state->cancelled = true;
    state->error_status = STORJ_TRANSFER_CANCELLED;

    // loop over all pointers, and cancel any that are queued to be downloaded
    // any downloads that are in-progress will monitor the state->cancelled
    // status and exit when set to true
    for (int i = 0; i < state->total_pointers; i++) {
        storj_pointer_t *pointer = &state->pointers[i];
        if (pointer->status == POINTER_BEING_DOWNLOADED) {
            uv_cancel((uv_req_t *)pointer->work);
        }
    }

    return 0;
}

int storj_bridge_resolve_file(storj_env_t *env,
                              storj_download_state_t *state,
                              char *bucket_id,
                              char *file_id,
                              FILE *destination,
                              storj_progress_cb progress_cb,
                              storj_finished_download_cb finished_cb)
{

    // setup download state
    state->total_bytes = 0;
    state->env = env;
    state->file_id = file_id;
    state->bucket_id = bucket_id;
    state->destination = destination;
    state->progress_cb = progress_cb;
    state->finished_cb = finished_cb;
    state->finished = false;
    state->total_shards = 0;
    state->completed_shards = 0;
    state->resolving_shards = 0;
    state->total_pointers = 0;
    state->pointers = NULL;
    state->pointers_completed = false;
    state->pointer_fail_count = 0;
    state->requesting_pointers = false;
    state->error_status = STORJ_TRANSFER_OK;
    state->writing = false;
    state->token = NULL;
    state->requesting_token = false;
    state->token_fail_count = 0;
    state->shard_size = 0;
    state->excluded_farmer_ids = NULL;
    state->pending_work_count = 0;
    state->cancelled = false;
    state->logger = env->log_options->logger;

    // determine the decryption key
    if (!env->encrypt_options || !env->encrypt_options->mnemonic) {
        state->decrypt_key = NULL;
        state->decrypt_ctr = NULL;
    } else {
        char *file_key = calloc(DETERMINISTIC_KEY_SIZE + 1, sizeof(char));

        generate_file_key(env->encrypt_options->mnemonic, bucket_id,
                          file_id, &file_key);
        file_key[DETERMINISTIC_KEY_SIZE] = '\0';

        uint8_t *decrypt_key = calloc(SHA256_DIGEST_SIZE + 1, sizeof(uint8_t));
        sha256_of_str(file_key, DETERMINISTIC_KEY_SIZE, decrypt_key);
        decrypt_key[SHA256_DIGEST_SIZE] = '\0';

        state->decrypt_key = decrypt_key;

        uint8_t *file_id_hash = calloc(RIPEMD160_DIGEST_SIZE + 1, sizeof(uint8_t));
        ripemd160_of_str(file_id, FILE_ID_SIZE, file_id_hash);
        file_id_hash[RIPEMD160_DIGEST_SIZE] = '\0';

        uint8_t *decrypt_ctr = calloc(AES_BLOCK_SIZE, sizeof(uint8_t));
        memcpy(decrypt_ctr, file_id_hash, AES_BLOCK_SIZE);

        state->decrypt_ctr = decrypt_ctr;
    };

    // start download
    queue_next_work(state);

    return 0;
}
