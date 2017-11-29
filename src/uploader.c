#include "uploader.h"

static void print_shard_info(storj_upload_state_t *state, int index) {
    shard_tracker_t *shard = &state->shard[index];
    shard_meta_t *shard_meta = state->shard[index].meta;
    farmer_pointer_t *p = state->shard[index].pointer;

    printf("\n================\n");

    printf("Shard index [%d]\n", index);

    printf("=== Shard Tracker ===\n");
    printf("progress: %d\n", shard->progress);
    printf("push_frame_request_count: %d\n", shard->push_frame_request_count);
    printf("push_shard_request_count: %d\n", shard->push_shard_request_count);
    printf("index: %d\n", shard->index);
    printf("uploaded_size: %"PRIu64"\n", shard->uploaded_size);

    printf("\n=== Shard Pointer ===\n");
    printf("token: %s\n", p->token);
    printf("farmer_user_agent: %s\n", p->farmer_user_agent);
    printf("farmer_protocol: %s\n", p->farmer_protocol);
    printf("farmer_address: %s\n", p->farmer_address);
    printf("farmer_port: %s\n", p->farmer_port);
    printf("farmer_node_id: %s\n", p->farmer_node_id);

    printf("\n=== Shard Meta ===\n");
    printf("hash: %s\n", shard_meta->hash);
    printf("index: %d\n", shard_meta->index);
    printf("size:  %"PRIu64"\n", shard_meta->size);
    printf("is_parity: %d\n", shard_meta->is_parity);
    for (int i = 0; i < STORJ_SHARD_CHALLENGES; i++ ) {
        printf("Challenge [%d]: %s\n", i, (char *)shard_meta->challenges_as_str[i]);
    }
    for (int i = 0; i < STORJ_SHARD_CHALLENGES; i++ ) {
        printf("Leaf [%d]: %s\n", i, (char *)shard_meta->tree[i]);
    }

    printf("================\n");

    return;

}

static uv_work_t *uv_work_new()
{
    uv_work_t *work = malloc(sizeof(uv_work_t));
    return work;
}

static uv_work_t *frame_work_new(int *index, storj_upload_state_t *state)
{
    uv_work_t *work = uv_work_new();
    if (!work) {
        return NULL;
    }

    frame_request_t *req = malloc(sizeof(frame_request_t));
    if (!req) {
        return NULL;
    }

    req->http_options = state->env->http_options;
    req->options = state->env->bridge_options;
    req->upload_state = state;
    req->error_status = 0;
    req->status_code = 0;
    req->log = state->log;

    if (index != NULL) {
        req->shard_meta_index = *index;
        req->farmer_pointer = farmer_pointer_new();
    }

    work->data = req;

    return work;
}

static uv_work_t *shard_meta_work_new(int index, storj_upload_state_t *state)
{
    uv_work_t *work = uv_work_new();
    if (!work) {
        return NULL;
    }
    frame_builder_t *req = malloc(sizeof(frame_builder_t));
    if (!req) {
        return NULL;
    }
    req->shard_meta = malloc(sizeof(shard_meta_t));
    if (!req->shard_meta) {
        return NULL;
    }
    req->upload_state = state;
    req->log = state->log;

    // make sure we switch between parity and data shards files.
    // When using Reed solomon must also read from encrypted file
    // rather than the original file for the data
    if (index + 1 > state->total_data_shards) {
        req->shard_file = state->parity_file;
    } else if (state->rs) {
        req->shard_file = state->encrypted_file;
    } else {
        req->shard_file = state->original_file;
    }
    // Reset shard index when using parity shards
    req->shard_meta->index = (index + 1 > state->total_data_shards) ? index - state->total_data_shards: index;

    // Position on shard_meta array
    req->shard_meta_index = index;

    req->error_status = 0;
    req->status_code = 0;

    work->data = req;

    return work;
}

static storj_exchange_report_t *storj_exchange_report_new()
{
    storj_exchange_report_t *report = malloc(sizeof(storj_exchange_report_t));
    if (!report) {
        return NULL;
    }
    report->data_hash = NULL;
    report->reporter_id = NULL;
    report->farmer_id = NULL;
    report->client_id = NULL;
    report->message = NULL;

    report->send_status = STORJ_REPORT_NOT_PREPARED; // not sent
    report->start = 0;
    report->end = 0;
    report->code = 0;
    report->send_count = 0;

    return report;
}

static farmer_pointer_t *farmer_pointer_new()
{
    farmer_pointer_t *pointer = calloc(sizeof(farmer_pointer_t), sizeof(char));
    if (!pointer) {
        return NULL;
    }
    pointer->token = NULL;
    pointer->farmer_user_agent = NULL;
    pointer->farmer_protocol = NULL;
    pointer->farmer_address = NULL;
    pointer->farmer_port = NULL;
    pointer->farmer_node_id = NULL;

    return pointer;
}

static shard_meta_t *shard_meta_new()
{
    shard_meta_t *meta = calloc(sizeof(shard_meta_t), sizeof(char));
    if (!meta) {
        return NULL;
    }
    meta->hash = NULL;

    return meta;
}

static storj_encryption_ctx_t *prepare_encryption_ctx(uint8_t *ctr, uint8_t *pass)
{
    storj_encryption_ctx_t *ctx = calloc(sizeof(storj_encryption_ctx_t), sizeof(char));
    if (!ctx) {
        return NULL;
    }

    ctx->ctx = calloc(sizeof(struct aes256_ctx), sizeof(char));
    if (!ctx->ctx) {
        return NULL;
    }

    ctx->encryption_ctr = calloc(AES_BLOCK_SIZE, sizeof(char));
    if (!ctx->encryption_ctr) {
        return NULL;
    }

    memcpy(ctx->encryption_ctr, ctr, AES_BLOCK_SIZE);

    aes256_set_encrypt_key(ctx->ctx, pass);

    return ctx;
}

static void shard_meta_cleanup(shard_meta_t *shard_meta)
{
    if (shard_meta->hash != NULL) {
        free(shard_meta->hash);
    }

    free(shard_meta);
}

static void pointer_cleanup(farmer_pointer_t *farmer_pointer)
{
    if (farmer_pointer->token != NULL) {
        free(farmer_pointer->token);
    }

    if (farmer_pointer->farmer_user_agent != NULL) {
        free(farmer_pointer->farmer_user_agent);
    }

    if (farmer_pointer->farmer_protocol != NULL) {
        free(farmer_pointer->farmer_protocol);
    }

    if (farmer_pointer->farmer_address != NULL) {
        free(farmer_pointer->farmer_address);
    }

    if (farmer_pointer->farmer_port != NULL) {
        free(farmer_pointer->farmer_port);
    }

    if (farmer_pointer->farmer_node_id != NULL) {
        free(farmer_pointer->farmer_node_id);
    }

    free(farmer_pointer);
}

static void cleanup_state(storj_upload_state_t *state)
{
    if (state->final_callback_called) {
        return;
    }

    if (state->pending_work_count > 0) {
        return;
    }

    if (state->original_file) {
        fclose(state->original_file);
    }

    state->final_callback_called = true;

    if (state->frame_id) {
        free(state->frame_id);
    }

    if (state->hmac_id) {
        free(state->hmac_id);
    }

    if (state->encrypted_file_name) {
        free((char *)state->encrypted_file_name);
    }

    if (state->exclude) {
        free(state->exclude);
    }

    if (state->encryption_ctr) {
        free(state->encryption_ctr);
    }

    if (state->encryption_key) {
        free(state->encryption_key);
    }

    if (state->parity_file) {
        fclose(state->parity_file);
    }

    if (state->parity_file_path) {
        unlink(state->parity_file_path);
        free(state->parity_file_path);
    }

    if (state->encrypted_file) {
        fclose(state->encrypted_file);
    }

    if (state->encrypted_file_path) {
        unlink(state->encrypted_file_path);
        free(state->encrypted_file_path);
    }

    if (state->index) {
        free((char *)state->index);
    }

    if (state->shard) {
        for (int i = 0; i < state->total_shards; i++ ) {

            state->log->debug(state->env->log_options, state->handle,
                              "fn[cleanup_state] - Cleaning up shard %d", i);

            shard_meta_cleanup(state->shard[i].meta);

            state->log->debug(state->env->log_options, state->handle,
                              "fn[cleanup_state] - Cleaning up pointers %d", i);

            pointer_cleanup(state->shard[i].pointer);
            if (state->shard[i].report) {
                free(state->shard[i].report);
            }
        }
        free(state->shard);
    }

    state->finished_cb(state->error_status, state->file_id, state->handle);

    free(state);
}

static void free_encryption_ctx(storj_encryption_ctx_t *ctx)
{
    if (ctx->encryption_ctr) {
        free(ctx->encryption_ctr);
    }

    if (ctx->encryption_key) {
        free(ctx->encryption_key);
    }

    if (ctx->ctx) {
        free(ctx->ctx);
    }

    free(ctx);
}

static void after_create_bucket_entry(uv_work_t *work, int status)
{
    post_to_bucket_request_t *req = work->data;
    storj_upload_state_t *state = req->upload_state;

    state->pending_work_count -= 1;

    if (status == UV_ECANCELED) {
        state->add_bucket_entry_count = 0;
        state->creating_bucket_entry = false;
        goto clean_variables;
    }

    state->add_bucket_entry_count += 1;
    state->creating_bucket_entry = false;

    if (req->error_status) {
        state->error_status = req->error_status;
        goto clean_variables;
    }

    // Check if we got a 200 status and token
    if (req->status_code == 200 || req->status_code == 201) {

        req->log->info(state->env->log_options, state->handle,
                       "Successfully Added bucket entry");

        state->add_bucket_entry_count = 0;
        state->completed_upload = true;

        struct json_object *file_id_value = NULL;
        char *file_id = NULL;
        if (json_object_object_get_ex(req->response, "id", &file_id_value)) {
            file_id = (char *)json_object_get_string(file_id_value);
        }

        if (file_id) {
            state->file_id = strdup(file_id);
        }

    } else if (state->add_bucket_entry_count == 6) {
        state->error_status = STORJ_BRIDGE_REQUEST_ERROR;
    }

clean_variables:
    queue_next_work(state);
    if (req->response) {
        json_object_put(req->response);
    }
    free(req);
    free(work);
}

static void create_bucket_entry(uv_work_t *work)
{
    post_to_bucket_request_t *req = work->data;
    storj_upload_state_t *state = req->upload_state;

    req->log->info(state->env->log_options, state->handle,
                   "[%s] Creating bucket entry... (retry: %d)",
                   state->file_name,
                   state->add_bucket_entry_count);

    struct json_object *body = json_object_new_object();
    json_object *frame = json_object_new_string(state->frame_id);
    json_object_object_add(body, "frame", frame);

    json_object *file_name = json_object_new_string(state->encrypted_file_name);
    json_object_object_add(body, "filename", file_name);

    json_object *index = json_object_new_string(state->index);
    json_object_object_add(body, "index", index);

    struct json_object *hmac = json_object_new_object();

    json_object *type = json_object_new_string("sha512");
    json_object_object_add(hmac, "type", type);

    json_object *value = json_object_new_string(state->hmac_id);
    json_object_object_add(hmac, "value", value);

    json_object_object_add(body, "hmac", hmac);

    if (state->rs) {
        struct json_object *erasure = json_object_new_object();
        json_object *erasure_type = json_object_new_string("reedsolomon");
        json_object_object_add(erasure, "type", erasure_type);
        json_object_object_add(body, "erasure", erasure);
    }

    int path_len = strlen(state->bucket_id) + 16;
    char *path = calloc(path_len + 1, sizeof(char));
    if (!path) {
        req->error_status = STORJ_MEMORY_ERROR;
        return;
    }
    sprintf(path, "%s%s%s%c", "/buckets/", state->bucket_id, "/files", '\0');

    req->log->debug(state->env->log_options, state->handle,
                    "fn[create_bucket_entry] - JSON body: %s", json_object_to_json_string(body));

    int status_code;
    int request_status = fetch_json(req->http_options,
                                    req->options,
                                    "POST",
                                    path,
                                    body,
                                    true,
                                    &req->response,
                                    &status_code);

    req->log->debug(state->env->log_options,
                    state->handle,
                    "fn[create_bucket_entry] - JSON Response: %s",
                    json_object_to_json_string(req->response));


    if (request_status) {
        req->log->warn(state->env->log_options, state->handle,
                       "Create bucket entry error: %i", request_status);
    }


    req->status_code = status_code;

    json_object_put(body);
    free(path);
}

static int prepare_bucket_entry_hmac(storj_upload_state_t *state)
{
    struct hmac_sha512_ctx hmac_ctx;
    hmac_sha512_set_key(&hmac_ctx, SHA256_DIGEST_SIZE, state->encryption_key);

    for (int i = 0; i < state->total_shards; i++) {

        shard_tracker_t *shard = &state->shard[i];

        if (!shard->meta ||
            !shard->meta->hash ||
            strlen(shard->meta->hash) != RIPEMD160_DIGEST_SIZE * 2) {
            return 1;
        }

        struct base16_decode_ctx base16_ctx;
        base16_decode_init(&base16_ctx);

        size_t decode_len = 0;
        uint8_t hash[RIPEMD160_DIGEST_SIZE];
        if (!base16_decode_update(&base16_ctx, &decode_len, hash,
                                  RIPEMD160_DIGEST_SIZE * 2,
                                  (uint8_t *)shard->meta->hash)) {
            return 1;

        }
        if (!base16_decode_final(&base16_ctx) ||
            decode_len != RIPEMD160_DIGEST_SIZE) {
            return 1;
        }
        hmac_sha512_update(&hmac_ctx, RIPEMD160_DIGEST_SIZE, hash);
    }

    uint8_t digest_raw[SHA512_DIGEST_SIZE];
    hmac_sha512_digest(&hmac_ctx, SHA512_DIGEST_SIZE, digest_raw);

    size_t digest_len = BASE16_ENCODE_LENGTH(SHA512_DIGEST_SIZE);
    state->hmac_id = calloc(digest_len + 1, sizeof(char));
    if (!state->hmac_id) {
        return 1;
    }

    base16_encode_update((uint8_t *)state->hmac_id, SHA512_DIGEST_SIZE, digest_raw);

    return 0;
}

static void queue_create_bucket_entry(storj_upload_state_t *state)
{
    uv_work_t *work = uv_work_new();
    if (!work) {
        state->error_status = STORJ_MEMORY_ERROR;
        return;
    }

    post_to_bucket_request_t *req = malloc(sizeof(post_to_bucket_request_t));
    if (!req) {
        state->error_status = STORJ_MEMORY_ERROR;
        return;
    }

    if (prepare_bucket_entry_hmac(state)) {
        state->error_status = STORJ_FILE_GENERATE_HMAC_ERROR;
        return;
    }

    req->http_options = state->env->http_options;
    req->options = state->env->bridge_options;
    req->upload_state = state;
    req->response = NULL;
    req->error_status = 0;
    req->status_code = 0;
    req->log = state->log;
    work->data = req;

    state->pending_work_count += 1;
    int status = uv_queue_work(state->env->loop, (uv_work_t*) work,
                               create_bucket_entry, after_create_bucket_entry);

    if (status) {
        state->error_status = STORJ_QUEUE_ERROR;
        return;
    }

    state->creating_bucket_entry = true;
}

static void free_push_shard_work(uv_handle_t *progress_handle)
{
    uv_work_t *work = progress_handle->data;
    push_shard_request_t *req = work->data;

    if (req) {
        free(req);
    }

    if (work) {
        free(work);
    }
}

static void after_push_shard(uv_work_t *work, int status)
{
    push_shard_request_t *req = work->data;
    storj_upload_state_t *state = req->upload_state;
    uv_handle_t *progress_handle = (uv_handle_t *) &req->progress_handle;
    shard_tracker_t *shard = &state->shard[req->shard_meta_index];

    // free the upload progress
    free(progress_handle->data);

    // assign work so that we can free after progress_handle is closed
    progress_handle->data = work;

    state->pending_work_count -= 1;

    if (status == UV_ECANCELED) {
        shard->push_shard_request_count = 0;
        shard->progress = AWAITING_PUSH_FRAME;
        shard->report->send_status = STORJ_REPORT_NOT_PREPARED;
        goto clean_variables;
    }

    // Update times on exchange report
    shard->report->start = req->start;
    shard->report->end = req->end;

    // Check if we got a 200 status and token
    if (!req->error_status &&
        (req->status_code == 200 ||
         req->status_code == 201 ||
         req->status_code == 304)) {

        req->log->info(state->env->log_options, state->handle,
                       "Successfully transferred shard index %d",
                       req->shard_meta_index);

        shard->progress = COMPLETED_PUSH_SHARD;
        state->completed_shards += 1;
        shard->push_shard_request_count = 0;

        // Update the uploaded size outside of the progress async handle
        shard->uploaded_size = shard->meta->size;

        // Update the exchange report with success
        shard->report->code = STORJ_REPORT_SUCCESS;
        shard->report->message = STORJ_REPORT_SHARD_UPLOADED;
        shard->report->send_status = STORJ_REPORT_AWAITING_SEND;

    } else if (!state->canceled){

        // Update the exchange report with failure
        shard->report->code = STORJ_REPORT_FAILURE;
        shard->report->message = STORJ_REPORT_UPLOAD_ERROR;
        shard->report->send_status = STORJ_REPORT_AWAITING_SEND;

        if (shard->push_shard_request_count == 6) {

            req->log->error(state->env->log_options, state->handle,
                            "Failed to push shard %d\n", req->shard_meta_index);

            state->error_status = STORJ_FARMER_REQUEST_ERROR;
        } else {
            req->log->warn(state->env->log_options, state->handle,
                           "Failed to push shard %d... Retrying...",
                           req->shard_meta_index);

            // We go back to getting a new pointer instead of retrying push with same pointer
            shard->progress = AWAITING_PUSH_FRAME;
            shard->push_shard_request_count += 1;

            // Add pointer to exclude for future calls
            if (state->exclude == NULL) {
                state->exclude = calloc(strlen(shard->pointer->farmer_node_id) + 1, sizeof(char));
                if (!state->exclude) {
                    state->error_status = STORJ_MEMORY_ERROR;
                    return;
                }
                strcpy(state->exclude, shard->pointer->farmer_node_id);
            } else {
                int new_len = strlen(state->exclude) + strlen(shard->pointer->farmer_node_id) + 1;
                state->exclude = realloc(state->exclude, new_len + 1);
                strcat(state->exclude, ",");
                strcat(state->exclude, shard->pointer->farmer_node_id);
                state->exclude[new_len] = '\0';
            }
        }
    }

clean_variables:
    queue_next_work(state);
    // close the async progress handle
    uv_close(progress_handle, free_push_shard_work);
}

static void push_shard(uv_work_t *work)
{
    push_shard_request_t *req = work->data;
    storj_upload_state_t *state = req->upload_state;
    shard_tracker_t *shard = &state->shard[req->shard_meta_index];

    req->log->info(state->env->log_options, state->handle,
                   "Transfering Shard index %d... (retry: %d)",
                   req->shard_meta_index,
                   state->shard[req->shard_meta_index].push_shard_request_count);

    int status_code = 0;
    int read_code = 0;

    req->start = get_time_milliseconds();

    uint64_t file_position = req->shard_index * state->shard_size;

    storj_encryption_ctx_t *encryption_ctx = NULL;
    if (!state->rs) {
        // Initialize the encryption context
        encryption_ctx = prepare_encryption_ctx(state->encryption_ctr,
                                                                        state->encryption_key);
        if (!encryption_ctx) {
            state->error_status = STORJ_MEMORY_ERROR;
            goto clean_variables;
        }
        // Increment the iv to proper placement because we may be reading from the middle of the file
        increment_ctr_aes_iv(encryption_ctx->encryption_ctr, req->shard_meta_index * state->shard_size);
    }

    int req_status = put_shard(req->http_options,
                               shard->pointer->farmer_node_id,
                               "http",
                               shard->pointer->farmer_address,
                               atoi(shard->pointer->farmer_port),
                               shard->meta->hash,
                               shard->meta->size,
                               req->shard_file,
                               file_position,
                               encryption_ctx,
                               shard->pointer->token,
                               &status_code,
                               &read_code,
                               &req->progress_handle,
                               req->canceled);

    if (read_code != 0) {
        req->log->error(state->env->log_options, state->handle,
                        "Put shard read error: %i", read_code);
    }

    if (req_status) {
        req->error_status = req_status;
        req->log->error(state->env->log_options, state->handle,
                        "Put shard request error code: %i", req_status);
    }

    req->end = get_time_milliseconds();

    req->status_code = status_code;

clean_variables:
    if (encryption_ctx) {
        free_encryption_ctx(encryption_ctx);
    }
}

static void progress_put_shard(uv_async_t* async)
{

    shard_upload_progress_t *progress = async->data;

    storj_upload_state_t *state = progress->state;

    state->shard[progress->pointer_index].uploaded_size = progress->bytes;

    uint64_t uploaded_bytes = 0;
    uint64_t total_bytes = 0;

    for (int i = 0; i < state->total_shards; i++) {

        shard_tracker_t *shard = &state->shard[i];

        uploaded_bytes += shard->uploaded_size;
        total_bytes += shard->meta->size;
    }

    double total_progress = (double)uploaded_bytes / (double)total_bytes;

    if (state->progress_finished) {
        return;
    }

    if (uploaded_bytes == total_bytes) {
        state->progress_finished = true;
    }

    state->progress_cb(total_progress,
                       uploaded_bytes,
                       total_bytes,
                       state->handle);


}

static void queue_push_shard(storj_upload_state_t *state, int index)
{
    uv_work_t *work = uv_work_new();
    if (!work) {
        state->error_status = STORJ_MEMORY_ERROR;
        return;
    }

    push_shard_request_t *req = malloc(sizeof(push_shard_request_t));
    if (!req) {
        state->error_status = STORJ_MEMORY_ERROR;
        return;
    }

    req->http_options = state->env->http_options;
    req->options = state->env->bridge_options;
    req->upload_state = state;
    req->error_status = 0;
    req->log = state->log;

    // Reset shard index when using parity shards
    req->shard_index = (index + 1 > state->total_data_shards) ? index - state->total_data_shards: index;

    // make sure we switch between parity and data shards files.
    // When using Reed solomon must also read from encrypted file
    // rather than the original file for the data
    if (index + 1 > state->total_data_shards) {
        req->shard_file = state->parity_file;
    } else if (state->rs) {
        req->shard_file = state->encrypted_file;
    } else {
        req->shard_file = state->original_file;
    }

    // Position on shard_meta array
    req->shard_meta_index = index;

    req->status_code = 0;

    req->canceled = &state->canceled;

    // setup upload progress reporting
    shard_upload_progress_t *progress =
        malloc(sizeof(shard_upload_progress_t));

    if (!progress) {
        state->error_status = STORJ_MEMORY_ERROR;
        return;
    }

    progress->pointer_index = index;
    progress->bytes = 0;
    progress->state = state;

    req->progress_handle.data = progress;

    uv_async_init(state->env->loop, &req->progress_handle,
                  progress_put_shard);

    work->data = req;

    state->pending_work_count += 1;
    int status = uv_queue_work(state->env->loop, (uv_work_t*) work,
                               push_shard, after_push_shard);

    if (status) {
        state->error_status = STORJ_QUEUE_ERROR;
        return;
    }

    state->shard[index].progress = PUSHING_SHARD;

    if (state->shard[index].report->farmer_id != NULL) {
        free(state->shard[index].report);
        state->shard[index].report = storj_exchange_report_new();
    }

    if (!state->shard[index].report) {
        state->error_status = STORJ_MEMORY_ERROR;
        return;
    }

    // setup the exchange report
    storj_exchange_report_t *report = state->shard[index].report;
    report->data_hash = state->shard[index].meta->hash;
    report->reporter_id = (char *)state->env->bridge_options->user;
    report->farmer_id = state->shard[index].pointer->farmer_node_id;
    report->client_id = (char *)state->env->bridge_options->user;
    report->pointer_index = index;
    report->start = 0;
    report->end = 0;
    report->code = 0;
    report->message = NULL;
    report->send_status = 0; // not sent
    report->send_count = 0;

    state->shard[index].work = work;
}

static void after_push_frame(uv_work_t *work, int status)
{
    frame_request_t *req = work->data;
    storj_upload_state_t *state = req->upload_state;
    farmer_pointer_t *pointer = req->farmer_pointer;

    state->pending_work_count -= 1;

    if (status == UV_ECANCELED) {
        state->shard[req->shard_meta_index].push_frame_request_count = 0;
        state->shard[req->shard_meta_index].progress = AWAITING_PUSH_FRAME;
        goto clean_variables;
    }

    // Increment request count every request for retry counts
    state->shard[req->shard_meta_index].push_frame_request_count += 1;

    if (req->status_code == 429 || req->status_code == 420) {

        state->error_status = STORJ_BRIDGE_RATE_ERROR;

    } else if ((req->status_code == 200 || req->status_code == 201) &&
        pointer->token != NULL) {
        // Check if we got a 200 status and token

        // Reset for if we need to get a new pointer later
        state->shard[req->shard_meta_index].push_frame_request_count = 0;
        state->shard[req->shard_meta_index].progress = AWAITING_PUSH_SHARD;

        farmer_pointer_t *p = state->shard[req->shard_meta_index].pointer;

        // Add token to shard[].pointer
        p->token = calloc(strlen(pointer->token) + 1, sizeof(char));
        if (!p->token) {
            state->error_status = STORJ_MEMORY_ERROR;
            goto clean_variables;
        }
        memcpy(p->token, pointer->token, strlen(pointer->token));

        // Add farmer_user_agent to shard[].pointer
        p->farmer_user_agent = calloc(strlen(pointer->farmer_user_agent) + 1,
                                      sizeof(char));
        if (!p->farmer_user_agent) {
            state->error_status = STORJ_MEMORY_ERROR;
            goto clean_variables;
        }
        memcpy(p->farmer_user_agent, pointer->farmer_user_agent,
               strlen(pointer->farmer_user_agent));

        // Add farmer_address to shard[].pointer
        p->farmer_address = calloc(strlen(pointer->farmer_address) + 1,
                                   sizeof(char));
        if (!p->farmer_address) {
            state->error_status = STORJ_MEMORY_ERROR;
            goto clean_variables;
        }
        memcpy(p->farmer_address, pointer->farmer_address,
               strlen(pointer->farmer_address));

        // Add farmer_port to shard[].pointer
        p->farmer_port = calloc(strlen(pointer->farmer_port) + 1, sizeof(char));
        if (!p->farmer_port) {
            state->error_status = STORJ_MEMORY_ERROR;
            goto clean_variables;
        }
        memcpy(p->farmer_port, pointer->farmer_port,
               strlen(pointer->farmer_port));

        // Add farmer_protocol to shard[].pointer
        p->farmer_protocol = calloc(strlen(pointer->farmer_protocol) + 1,
                                    sizeof(char));
        if (!p->farmer_protocol) {
            state->error_status = STORJ_MEMORY_ERROR;
            goto clean_variables;
        }
        memcpy(p->farmer_protocol, pointer->farmer_protocol,
               strlen(pointer->farmer_protocol));

        // Add farmer_node_id to shard[].pointer
        p->farmer_node_id = calloc(strlen(pointer->farmer_node_id) + 1,
                                   sizeof(char));
        if (!p->farmer_node_id) {
            state->error_status = STORJ_MEMORY_ERROR;
            goto clean_variables;
        }
        memcpy(p->farmer_node_id, pointer->farmer_node_id,
               strlen(pointer->farmer_node_id));

        state->log->info(
            state->env->log_options,
            state->handle,
            "Contract negotiated with: "
            "{ "
            "\"userAgent: \"%s\", "
            "\"protocol:\" \"%s\", "
            "\"port\": \"%s\", "
            "\"nodeID\": \"%s\""
            "}",
            p->farmer_user_agent,
            p->farmer_protocol,
            p->farmer_port,
            p->farmer_node_id
        );

    } else if (state->shard[req->shard_meta_index].push_frame_request_count ==
               STORJ_MAX_PUSH_FRAME_COUNT) {
        state->error_status = STORJ_BRIDGE_OFFER_ERROR;
    } else {
        state->shard[req->shard_meta_index].progress = AWAITING_PUSH_FRAME;
    }

clean_variables:
    queue_next_work(state);
    if (pointer) {
        pointer_cleanup(pointer);
    }

    free(req);
    free(work);
}

static void push_frame(uv_work_t *work)
{
    frame_request_t *req = work->data;
    storj_upload_state_t *state = req->upload_state;
    shard_meta_t *shard_meta = state->shard[req->shard_meta_index].meta;

    req->log->info(state->env->log_options, state->handle,
                   "Pushing frame for shard index %d... (retry: %d)",
                   req->shard_meta_index,
                   state->shard[req->shard_meta_index].push_frame_request_count);

    char resource[strlen(state->frame_id) + 9];
    memset(resource, '\0', strlen(state->frame_id) + 9);
    strcpy(resource, "/frames/");
    strcat(resource, state->frame_id);

    // Prepare the body
    struct json_object *body = json_object_new_object();

    // Add shard hash
    json_object *shard_hash = json_object_new_string(shard_meta->hash);
    json_object_object_add(body, "hash", shard_hash);

    // Add shard size
    json_object *shard_size = json_object_new_int64(shard_meta->size);
    json_object_object_add(body, "size", shard_size);

    // Add shard index
    json_object *shard_index = json_object_new_int(req->shard_meta_index);
    json_object_object_add(body, "index", shard_index);

    json_object *parity_shard = NULL;
    if (req->shard_meta_index + 1 > state->total_data_shards) {
        parity_shard = json_object_new_boolean(true);
    } else {
        parity_shard = json_object_new_boolean(false);
    }
    json_object_object_add(body, "parity", parity_shard);

    // Add challenges
    json_object *challenges = json_object_new_array();
    for (int i = 0; i < STORJ_SHARD_CHALLENGES; i++ ) {
        json_object_array_add(challenges,
                              json_object_new_string(
                                  (char *)shard_meta->challenges_as_str[i]));
    }
    json_object_object_add(body, "challenges", challenges);

    // Add Tree
    json_object *tree = json_object_new_array();
    for (int i = 0; i < STORJ_SHARD_CHALLENGES; i++ ) {
        json_object_array_add(tree,
                              json_object_new_string(
                                  (char *)shard_meta->tree[i]));
    }
    json_object_object_add(body, "tree", tree);

    // Add exclude (Don't try to upload to farmers that have failed before)
    json_object *exclude = json_object_new_array();
    if (state->exclude) {
        char *exclude_list = calloc(strlen(state->exclude) + 1, sizeof(char));
        if (!exclude_list) {
            req->error_status = STORJ_MEMORY_ERROR;
            goto clean_variables;
        }
        strcpy(exclude_list, state->exclude);

        char *node_id = strtok(exclude_list, ",");
        while (node_id != NULL) {
            json_object_array_add(exclude, json_object_new_string(node_id));
            node_id = strtok (NULL, ",");
        }
        free(exclude_list);
    }

    json_object_object_add(body, "exclude", exclude);

    req->log->debug(state->env->log_options, state->handle,
                    "fn[push_frame] - JSON body: %s", json_object_to_json_string(body));

    int status_code;
    struct json_object *response = NULL;
    int request_status = fetch_json(req->http_options,
                                    req->options,
                                    "PUT",
                                    resource,
                                    body,
                                    true,
                                    &response,
                                    &status_code);

    req->log->debug(state->env->log_options, state->handle,
                    "fn[push_frame] - JSON Response: %s",
                    json_object_to_json_string(response));

    if (request_status) {
        req->log->warn(state->env->log_options, state->handle,
                       "Push frame error: %i", request_status);
        req->error_status = STORJ_BRIDGE_REQUEST_ERROR;
        goto clean_variables;
    }

    struct json_object *obj_token;
    if (!json_object_object_get_ex(response, "token", &obj_token)) {
        req->error_status = STORJ_BRIDGE_JSON_ERROR;
        goto clean_variables;
    }

    struct json_object *obj_farmer;
    if (!json_object_object_get_ex(response, "farmer", &obj_farmer)) {
        req->error_status = STORJ_BRIDGE_JSON_ERROR;
        goto clean_variables;
    }

    struct json_object *obj_farmer_address;
    if (!json_object_object_get_ex(obj_farmer, "address",
                                   &obj_farmer_address)) {

        req->error_status = STORJ_BRIDGE_JSON_ERROR;
        goto clean_variables;
    }

    struct json_object *obj_farmer_port;
    if (!json_object_object_get_ex(obj_farmer, "port", &obj_farmer_port)) {
        req->error_status = STORJ_BRIDGE_JSON_ERROR;
        goto clean_variables;
    }

    struct json_object *obj_farmer_user_agent;
    if (!json_object_object_get_ex(obj_farmer, "userAgent",
                                   &obj_farmer_user_agent)) {

        req->error_status = STORJ_BRIDGE_JSON_ERROR;
        goto clean_variables;
    }

    struct json_object *obj_farmer_protocol;
    if (!json_object_object_get_ex(obj_farmer, "protocol",
                                   &obj_farmer_protocol)) {

        req->error_status = STORJ_BRIDGE_JSON_ERROR;
        goto clean_variables;
    }

    struct json_object *obj_farmer_node_id;
    if (!json_object_object_get_ex(obj_farmer, "nodeID",
                                   &obj_farmer_node_id)) {

        req->error_status = STORJ_BRIDGE_JSON_ERROR;
        goto clean_variables;
    }

    if (!json_object_is_type(obj_token, json_type_string)) {

        req->error_status = STORJ_BRIDGE_JSON_ERROR;
        goto clean_variables;
    }

    // Token
    char *token = (char *)json_object_get_string(obj_token);
    req->farmer_pointer->token = calloc(strlen(token) + 1, sizeof(char));
    if (!req->farmer_pointer->token) {
        req->error_status = STORJ_MEMORY_ERROR;
        goto clean_variables;
    }
    memcpy(req->farmer_pointer->token, token, strlen(token));

    // Farmer user agent
    char *farmer_user_agent =
        (char *)json_object_get_string(obj_farmer_user_agent);
    req->farmer_pointer->farmer_user_agent =
        calloc(strlen(farmer_user_agent) + 1, sizeof(char));
    if (!req->farmer_pointer->farmer_user_agent) {
        req->error_status = STORJ_MEMORY_ERROR;
        goto clean_variables;
    }
    memcpy(req->farmer_pointer->farmer_user_agent,
           farmer_user_agent,
           strlen(farmer_user_agent));

    // Farmer protocol
    char *farmer_protocol = (char *)json_object_get_string(obj_farmer_protocol);
    req->farmer_pointer->farmer_protocol =
        calloc(strlen(farmer_protocol) + 1, sizeof(char));
    if (!req->farmer_pointer->farmer_protocol) {
        req->error_status = STORJ_MEMORY_ERROR;
        goto clean_variables;
    }
    memcpy(req->farmer_pointer->farmer_protocol,
           farmer_protocol,
           strlen(farmer_protocol));

    // Farmer address
    char *farmer_address = (char *)json_object_get_string(obj_farmer_address);
    req->farmer_pointer->farmer_address =
        calloc(strlen(farmer_address) + 1, sizeof(char));
    if (!req->farmer_pointer->farmer_address) {
        req->error_status = STORJ_MEMORY_ERROR;
        goto clean_variables;
    }
    memcpy(req->farmer_pointer->farmer_address,
           farmer_address,
           strlen(farmer_address));

    // Farmer port
    char *farmer_port = (char *)json_object_get_string(obj_farmer_port);
    req->farmer_pointer->farmer_port = calloc(strlen(farmer_port) + 1, sizeof(char));
    if (!req->farmer_pointer->farmer_port) {
        req->error_status = STORJ_MEMORY_ERROR;
        goto clean_variables;
    }
    memcpy(req->farmer_pointer->farmer_port, farmer_port, strlen(farmer_port));

    // Farmer node id
    char *farmer_node_id = (char *)json_object_get_string(obj_farmer_node_id);
    req->farmer_pointer->farmer_node_id =
        calloc(strlen(farmer_node_id) + 1, sizeof(char));
    if (!req->farmer_pointer->farmer_node_id) {
        req->error_status = STORJ_MEMORY_ERROR;
        goto clean_variables;
    }
    memcpy(req->farmer_pointer->farmer_node_id,
           farmer_node_id,
           strlen(farmer_node_id));

    // Status code
    req->status_code = status_code;

clean_variables:
    if (response) {
        json_object_put(response);
    }
    if (body) {
        json_object_put(body);
    }
}

static void queue_push_frame(storj_upload_state_t *state, int index)
{
    if (state->shard[index].pointer->token != NULL) {
        pointer_cleanup(state->shard[index].pointer);
        state->shard[index].pointer = farmer_pointer_new();
        if (!state->shard[index].pointer) {
            state->error_status = STORJ_MEMORY_ERROR;
            return;
        }
    }

    uv_work_t *shard_work = frame_work_new(&index, state);
    if (!shard_work) {
        state->error_status = STORJ_MEMORY_ERROR;
        return;
    }

    state->pending_work_count += 1;
    int status = uv_queue_work(state->env->loop, (uv_work_t*) shard_work,
                               push_frame, after_push_frame);
    if (status) {
        state->error_status = STORJ_QUEUE_ERROR;
        return;
    }

    state->shard[index].progress = PUSHING_FRAME;
}

static void after_prepare_frame(uv_work_t *work, int status)
{
    frame_builder_t *req = work->data;
    shard_meta_t *shard_meta = req->shard_meta;
    storj_upload_state_t *state = req->upload_state;

    state->pending_work_count -= 1;

    if (status == UV_ECANCELED) {
        state->shard[shard_meta->index].progress = AWAITING_PREPARE_FRAME;
        goto clean_variables;
    }

    if (req->error_status) {
        state->error_status = req->error_status;
        goto clean_variables;
    }

    /* set the shard_meta to a struct array in the state for later use. */

    // Add Hash
    state->shard[req->shard_meta_index].meta->hash =
        calloc(RIPEMD160_DIGEST_SIZE * 2 + 1, sizeof(char));

    if (!state->shard[req->shard_meta_index].meta->hash) {
        state->error_status = STORJ_MEMORY_ERROR;
        goto clean_variables;
    }

    memcpy(state->shard[req->shard_meta_index].meta->hash,
           shard_meta->hash,
           RIPEMD160_DIGEST_SIZE * 2);

    req->log->info(state->env->log_options, state->handle,
                  "Shard (%d) hash: %s", req->shard_meta_index,
                  state->shard[req->shard_meta_index].meta->hash);

    // Add challenges_as_str
    state->log->debug(state->env->log_options, state->handle,
                      "Challenges for shard index %d",
                      req->shard_meta_index);

    for (int i = 0; i < STORJ_SHARD_CHALLENGES; i++ ) {
        memcpy(state->shard[req->shard_meta_index].meta->challenges_as_str[i],
               shard_meta->challenges_as_str[i],
               64);

        state->log->debug(state->env->log_options, state->handle,
                          "Shard %d Challenge [%d]: %s",
                        req->shard_meta_index,
                          i,
                          state->shard[req->shard_meta_index].meta->challenges_as_str[i]);
    }

    // Add Merkle Tree leaves.
    state->log->debug(state->env->log_options, state->handle,
                      "Tree for shard index %d",
                      req->shard_meta_index);

    for (int i = 0; i < STORJ_SHARD_CHALLENGES; i++ ) {
        memcpy(state->shard[req->shard_meta_index].meta->tree[i],
               shard_meta->tree[i],
               40);

        state->log->debug(state->env->log_options, state->handle,
                          "Shard %d Leaf [%d]: %s", req->shard_meta_index, i,
                          state->shard[req->shard_meta_index].meta->tree[i]);
    }

    // Add index
    state->shard[req->shard_meta_index].meta->index = shard_meta->index;

    // Add size
    state->shard[req->shard_meta_index].meta->size = shard_meta->size;

    state->log->info(state->env->log_options, state->handle,
                     "Successfully created frame for shard index %d",
                     req->shard_meta_index);

    state->shard[req->shard_meta_index].progress = AWAITING_PUSH_FRAME;

clean_variables:
    queue_next_work(state);
    if (shard_meta) {
        shard_meta_cleanup(shard_meta);
    }

    free(req);
    free(work);
}

static void prepare_frame(uv_work_t *work)
{
    frame_builder_t *req = work->data;
    shard_meta_t *shard_meta = req->shard_meta;
    storj_upload_state_t *state = req->upload_state;

    // Set the challenges
    uint8_t buff[32];
    for (int i = 0; i < STORJ_SHARD_CHALLENGES; i++ ) {
        memset_zero(buff, 32);

        random_buffer(buff, 32);
        memcpy(shard_meta->challenges[i], buff, 32);

        // Convert the uint8_t challenges to character arrays
        char *challenge_as_str = hex2str(32, buff);
        if (!challenge_as_str) {
            req->error_status = STORJ_MEMORY_ERROR;
            goto clean_variables;
        }
        memcpy(shard_meta->challenges_as_str[i], challenge_as_str, strlen(challenge_as_str));
        free(challenge_as_str);
    }

    // Hash of the shard_data
    shard_meta->hash = calloc(RIPEMD160_DIGEST_SIZE*2 + 2, sizeof(char));
    if (!shard_meta->hash) {
        req->error_status = STORJ_MEMORY_ERROR;
        goto clean_variables;
    }

    req->log->info(state->env->log_options, state->handle,
                   "Creating frame for shard index %d",
                   req->shard_meta_index);

    // Sha256 of encrypted data for calculating shard has
    uint8_t prehash_sha256[SHA256_DIGEST_SIZE];

    // Initialize context for sha256 of encrypted data
    struct sha256_ctx shard_hash_ctx;
    sha256_init(&shard_hash_ctx);

    // Calculate the merkle tree with challenges
    struct sha256_ctx first_sha256_for_leaf[STORJ_SHARD_CHALLENGES];
    for (int i = 0; i < STORJ_SHARD_CHALLENGES; i++ ) {
        sha256_init(&first_sha256_for_leaf[i]);
        sha256_update(&first_sha256_for_leaf[i], 32, (uint8_t *)&shard_meta->challenges[i]);
    }

    storj_encryption_ctx_t *encryption_ctx = NULL;
    if (!state->rs) {
        // Initialize the encryption context
        encryption_ctx = prepare_encryption_ctx(state->encryption_ctr, state->encryption_key);
        if (!encryption_ctx) {
            state->error_status = STORJ_MEMORY_ERROR;
            goto clean_variables;
        }
        // Increment the iv to proper placement because we may be reading from the middle of the file
        increment_ctr_aes_iv(encryption_ctx->encryption_ctr, req->shard_meta_index * state->shard_size);
    }

    uint8_t cphr_txt[AES_BLOCK_SIZE * 256];
    memset_zero(cphr_txt, AES_BLOCK_SIZE * 256);
    char read_data[AES_BLOCK_SIZE * 256];
    memset_zero(read_data, AES_BLOCK_SIZE * 256);
    unsigned long int read_bytes = 0;
    uint64_t total_read = 0;

    do {
        if (state->canceled) {
            goto clean_variables;
        }

        read_bytes = pread(fileno(req->shard_file),
                           read_data, AES_BLOCK_SIZE * 256,
                           shard_meta->index*state->shard_size + total_read);

        if (read_bytes == -1) {
            req->log->warn(state->env->log_options, state->handle,
                           "Error reading file: %d",
                           errno);
            req->error_status = STORJ_FILE_READ_ERROR;
            goto clean_variables;
        }

        total_read += read_bytes;

        if (!state->rs) {
            // Encrypt data
            ctr_crypt(encryption_ctx->ctx, (nettle_cipher_func *)aes256_encrypt,
                      AES_BLOCK_SIZE, encryption_ctx->encryption_ctr, read_bytes,
                      (uint8_t *)cphr_txt, (uint8_t *)read_data);
        } else {
            // Just use the already encrypted data
            memcpy(cphr_txt, read_data, AES_BLOCK_SIZE*256);
        }

        sha256_update(&shard_hash_ctx, read_bytes, cphr_txt);

        for (int i = 0; i < STORJ_SHARD_CHALLENGES; i++ ) {
            sha256_update(&first_sha256_for_leaf[i], read_bytes, cphr_txt);
        }

        memset_zero(read_data, AES_BLOCK_SIZE * 256);
        memset_zero(cphr_txt, AES_BLOCK_SIZE * 256);

    } while(total_read < state->shard_size && read_bytes > 0);

    shard_meta->size = total_read;

    sha256_digest(&shard_hash_ctx, SHA256_DIGEST_SIZE, prehash_sha256);

    uint8_t prehash_ripemd160[RIPEMD160_DIGEST_SIZE];
    memset_zero(prehash_ripemd160, RIPEMD160_DIGEST_SIZE);
    ripemd160_of_str(prehash_sha256, SHA256_DIGEST_SIZE, prehash_ripemd160);

    // Shard Hash
    char *hash = hex2str(RIPEMD160_DIGEST_SIZE, prehash_ripemd160);
    if (!hash) {
        req->error_status = STORJ_MEMORY_ERROR;
        goto clean_variables;
    }
    memcpy(shard_meta->hash, hash, strlen(hash));
    free(hash);

    uint8_t preleaf_sha256[SHA256_DIGEST_SIZE];
    memset_zero(preleaf_sha256, SHA256_DIGEST_SIZE);
    uint8_t preleaf_ripemd160[RIPEMD160_DIGEST_SIZE];
    memset_zero(preleaf_ripemd160, RIPEMD160_DIGEST_SIZE);
    char leaf[RIPEMD160_DIGEST_SIZE*2 +1];
    memset(leaf, '\0', RIPEMD160_DIGEST_SIZE*2 +1);
    for (int i = 0; i < STORJ_SHARD_CHALLENGES; i++ ) {
        // finish first sha256 for leaf
        sha256_digest(&first_sha256_for_leaf[i], SHA256_DIGEST_SIZE, preleaf_sha256);

        // ripemd160 result of sha256
        ripemd160_of_str(preleaf_sha256, SHA256_DIGEST_SIZE, preleaf_ripemd160);

        // sha256 and ripemd160 again
        ripemd160sha256_as_string(preleaf_ripemd160, RIPEMD160_DIGEST_SIZE, leaf);

        memcpy(shard_meta->tree[i], leaf, RIPEMD160_DIGEST_SIZE*2 + 1);
    }

clean_variables:
    if (encryption_ctx) {
        free_encryption_ctx(encryption_ctx);
    }
}

static void queue_prepare_frame(storj_upload_state_t *state, int index)
{
    uv_work_t *shard_work = shard_meta_work_new(index, state);
    if (!shard_work) {
        state->error_status = STORJ_MEMORY_ERROR;
        return;
    }

    state->pending_work_count += 1;
    int status = uv_queue_work(state->env->loop, (uv_work_t*) shard_work,
                               prepare_frame, after_prepare_frame);

    if (status) {
        state->error_status = STORJ_QUEUE_ERROR;
        return;
    }

    state->shard[index].progress = PREPARING_FRAME;
}

static void after_create_encrypted_file(uv_work_t *work, int status)
{
    encrypt_file_req_t *req = work->data;
    storj_upload_state_t *state = req->upload_state;

    state->pending_work_count -= 1;
    state->create_encrypted_file_count += 1;

    uint64_t encrypted_file_size = 0;
    #ifdef _WIN32
        struct _stati64 st;
        _stati64(state->encrypted_file_path, &st);
        encrypted_file_size = st.st_size;
    #else
        struct stat st;
        stat(state->encrypted_file_path, &st);
        encrypted_file_size = st.st_size;
    #endif

    if (req->error_status != 0 || state->file_size != encrypted_file_size) {
        state->log->warn(state->env->log_options, state->handle,
                       "Failed to encrypt data.");

        if (state->create_encrypted_file_count == 6) {
            state->error_status = STORJ_FILE_ENCRYPTION_ERROR;
        }
    } else {
        state->log->info(state->env->log_options, state->handle,
                       "Successfully encrypted file");

        state->encrypted_file = fopen(state->encrypted_file_path, "r");
        if (!state->encrypted_file) {
            state->error_status = STORJ_FILE_READ_ERROR;
        }
    }

    state->creating_encrypted_file = false;

clean_variables:
    queue_next_work(state);
    free(work->data);
    free(work);
}

static void create_encrypted_file(uv_work_t *work)
{
    encrypt_file_req_t *req = work->data;
    storj_upload_state_t *state = req->upload_state;

    state->log->info(state->env->log_options, state->handle, "Encrypting file...");

    // Initialize the encryption context
    storj_encryption_ctx_t *encryption_ctx = prepare_encryption_ctx(state->encryption_ctr,
                                                                    state->encryption_key);
    if (!encryption_ctx) {
        state->error_status = STORJ_MEMORY_ERROR;
        goto clean_variables;
    }

    uint8_t cphr_txt[AES_BLOCK_SIZE * 256];
    memset_zero(cphr_txt, AES_BLOCK_SIZE * 256);
    char read_data[AES_BLOCK_SIZE * 256];
    memset_zero(read_data, AES_BLOCK_SIZE * 256);
    unsigned long int read_bytes = 0;
    unsigned long int written_bytes = 0;
    uint64_t total_read = 0;

    FILE *encrypted_file = fopen(state->encrypted_file_path, "w+");

    if (encrypted_file == NULL) {
      state->log->error(state->env->log_options, state->handle,
                     "Can't create file for encrypted data [%s]",
                     state->encrypted_file_path);
        goto clean_variables;
    }

    do {
        if (state->canceled) {
            goto clean_variables;
        }

        read_bytes = pread(fileno(state->original_file),
                           read_data, AES_BLOCK_SIZE * 256,
                           total_read);

        if (read_bytes == -1) {
            state->log->warn(state->env->log_options, state->handle,
                           "Error reading file: %d",
                           errno);
            req->error_status = STORJ_FILE_READ_ERROR;
            goto clean_variables;
        }

        // Encrypt data
        ctr_crypt(encryption_ctx->ctx, (nettle_cipher_func *)aes256_encrypt,
                  AES_BLOCK_SIZE, encryption_ctx->encryption_ctr, read_bytes,
                  (uint8_t *)cphr_txt, (uint8_t *)read_data);

        written_bytes = pwrite(fileno(encrypted_file), cphr_txt, read_bytes, total_read);

        memset_zero(read_data, AES_BLOCK_SIZE * 256);
        memset_zero(cphr_txt, AES_BLOCK_SIZE * 256);

        total_read += read_bytes;

        if (written_bytes != read_bytes) {
            goto clean_variables;
        }

    } while(total_read < state->file_size && read_bytes > 0);

clean_variables:
    if (encrypted_file) {
        fclose(encrypted_file);
    }
    if (encryption_ctx) {
        free_encryption_ctx(encryption_ctx);
    }
}

static void queue_create_encrypted_file(storj_upload_state_t *state)
{
    uv_work_t *work = uv_work_new();
    if (!work) {
        state->error_status = STORJ_MEMORY_ERROR;
        return;
    }

    state->pending_work_count += 1;

    encrypt_file_req_t *req = malloc(sizeof(encrypt_file_req_t));

    req->error_status = 0;
    req->upload_state = state;
    work->data = req;

    int status = uv_queue_work(state->env->loop, (uv_work_t*) work,
                               create_encrypted_file, after_create_encrypted_file);

    if (status) {
        state->error_status = STORJ_QUEUE_ERROR;
    }

    state->creating_encrypted_file = true;
}

static void after_request_frame_id(uv_work_t *work, int status)
{
    frame_request_t *req = work->data;
    storj_upload_state_t *state = req->upload_state;

    state->requesting_frame = false;
    state->pending_work_count -= 1;

    if (status == UV_ECANCELED) {
        state->frame_request_count = 0;
        goto clean_variables;
    }

    state->frame_request_count += 1;

    if (req->status_code == 429 || req->status_code == 420) {

        state->error_status = STORJ_BRIDGE_RATE_ERROR;

    } else if (req->error_status == 0 && req->status_code == 200 && req->frame_id) {

        state->log->info(state->env->log_options, state->handle,
                         "Successfully retrieved frame id: %s", req->frame_id);

        state->frame_id = req->frame_id;

    } else if (state->frame_request_count == 6) {
        state->error_status = STORJ_BRIDGE_FRAME_ERROR;
    }

clean_variables:
    queue_next_work(state);
    free(req);
    free(work);
}

static void request_frame_id(uv_work_t *work)
{
    frame_request_t *req = work->data;
    storj_upload_state_t *state = req->upload_state;

    req->log->info(state->env->log_options,
                   state->handle,
                   "[%s] Requesting file staging frame... (retry: %d)",
                   state->file_name,
                   state->frame_request_count);

    // Prepare the body
    struct json_object *body = json_object_new_object();

    int status_code;
    struct json_object *response = NULL;
    int request_status = fetch_json(req->http_options,
                                    req->options,
                                    "POST",
                                    "/frames",
                                    body,
                                    true,
                                    &response,
                                    &status_code);


    if (request_status) {
        req->log->warn(state->env->log_options, state->handle,
                       "Request frame id error: %i", request_status);
    }

    req->log->debug(state->env->log_options,
                    state->handle,
                    "fn[request_frame_id] - JSON Response: %s",
                    json_object_to_json_string(response));

    struct json_object *frame_id;
    if (!json_object_object_get_ex(response, "id", &frame_id)) {
        req->error_status = STORJ_BRIDGE_JSON_ERROR;
        goto cleanup;
    }

    if (!json_object_is_type(frame_id, json_type_string)) {
        req->error_status = STORJ_BRIDGE_JSON_ERROR;
        goto cleanup;
    }

    char *frame_id_str = (char *)json_object_get_string(frame_id);
    req->frame_id = calloc(strlen(frame_id_str) + 1, sizeof(char));
    if (!req->frame_id) {
        req->error_status = STORJ_MEMORY_ERROR;
        goto cleanup;
    }

    strcpy(req->frame_id, frame_id_str);

cleanup:
    req->status_code = status_code;

    json_object_put(response);
    json_object_put(body);
}

static void queue_request_frame_id(storj_upload_state_t *state)
{
    uv_work_t *work = frame_work_new(NULL, state);
    if (!work) {
        state->error_status = STORJ_MEMORY_ERROR;
        return;
    }

    state->pending_work_count += 1;
    int status = uv_queue_work(state->env->loop, (uv_work_t*) work,
                               request_frame_id, after_request_frame_id);

    if (status) {
        state->error_status = STORJ_QUEUE_ERROR;
    }

    state->requesting_frame = true;
}

static void after_create_parity_shards(uv_work_t *work, int status)
{
    parity_shard_req_t *req = work->data;
    storj_upload_state_t *state = req->upload_state;

    state->pending_work_count -= 1;

    // TODO: Check if file was created
    if (req->error_status != 0) {
        state->log->warn(state->env->log_options, state->handle,
                       "Failed to create parity shards");

        state->awaiting_parity_shards = true;

        state->error_status = STORJ_FILE_PARITY_ERROR;
    } else {
        state->log->info(state->env->log_options, state->handle,
                       "Successfully created parity shards");

        state->parity_file = fopen(state->parity_file_path, "r");

        if (!state->parity_file) {
            state->error_status = STORJ_FILE_READ_ERROR;
        }

    }

clean_variables:
    queue_next_work(state);
    free(work->data);
    free(work);
}

static void create_parity_shards(uv_work_t *work)
{
    parity_shard_req_t *req = work->data;
    storj_upload_state_t *state = req->upload_state;

    state->log->info(state->env->log_options, state->handle,
                   "Creating parity shards");

    // ???
    fec_init();

    uint8_t **data_blocks = NULL;
    uint8_t **fec_blocks = NULL;

    uint8_t *map = NULL;
    int status = 0;

    FILE *encrypted_file = fopen(state->encrypted_file_path, "r");

    if (!encrypted_file) {
        req->error_status = 1;
        state->log->error(state->env->log_options, state->handle,
                          "Unable to open encrypted file");
        goto clean_variables;
    }

    status = map_file(fileno(encrypted_file), state->file_size, &map, true);

    if (status) {
        req->error_status = 1;
        state->log->error(state->env->log_options, state->handle,
                          "Could not create mmap original file: %d", status);
        goto clean_variables;
    }

    uint64_t parity_size = state->total_shards * state->shard_size - state->file_size;

    // determine parity shard location
    char *tmp_folder = NULL;
    if (!state->parity_file_path) {
        req->error_status = 1;
        state->log->error(state->env->log_options, state->handle,
                          "No temp folder set for parity shards");
        goto clean_variables;
    }

    FILE *parity_file = fopen(state->parity_file_path, "w+");
    if (!parity_file) {
        req->error_status = 1;
        state->log->error(state->env->log_options, state->handle,
                          "Could not open parity file [%s]", state->parity_file_path);
        goto clean_variables;
    }

    int falloc_status = allocatefile(fileno(parity_file), parity_size);

    if (falloc_status) {
        req->error_status = 1;
        state->log->error(state->env->log_options, state->handle,
                          "Could not allocate space for mmap parity " \
                          "shard file: %i", falloc_status);
        goto clean_variables;
    }

    uint8_t *map_parity = NULL;
    status = map_file(fileno(parity_file), parity_size, &map_parity, false);

    if (status) {
        req->error_status = 1;
        state->log->error(state->env->log_options, state->handle,
                       "Could not create mmap parity shard file: %d", status);
        goto clean_variables;
    }

    data_blocks = (uint8_t**)malloc(state->total_data_shards * sizeof(uint8_t *));
    if (!data_blocks) {
        req->error_status = 1;
        state->log->error(state->env->log_options, state->handle,
                       "memory error: unable to malloc");
        goto clean_variables;
    }

    for (int i = 0; i < state->total_data_shards; i++) {
        data_blocks[i] = map + i * state->shard_size;
    }

    fec_blocks = (uint8_t**)malloc(state->total_parity_shards * sizeof(uint8_t *));
    if (!fec_blocks) {
        req->error_status = 1;
        state->log->error(state->env->log_options, state->handle,
                       "memory error: unable to malloc");
        goto clean_variables;
    }

    for (int i = 0; i < state->total_parity_shards; i++) {
        fec_blocks[i] = map_parity + i * state->shard_size;
    }

    state->log->debug(state->env->log_options, state->handle,
                      "Encoding parity shards, data_shards: %i, "       \
                      "parity_shards: %i, shard_size: %" PRIu64 ", "    \
                      "file_size: %" PRIu64,
                      state->total_data_shards,
                      state->total_parity_shards,
                      state->shard_size,
                      state->file_size);


    reed_solomon *rs = reed_solomon_new(state->total_data_shards,
                                        state->total_parity_shards);
    reed_solomon_encode2(rs, data_blocks, fec_blocks, state->total_shards,
                         state->shard_size, state->file_size);
    reed_solomon_release(rs);

clean_variables:
    if (data_blocks) {
        free(data_blocks);
    }

    if (fec_blocks) {
        free(fec_blocks);
    }

    if (tmp_folder) {
        free(tmp_folder);
    }

    if (map) {
        unmap_file(map, state->file_size);
    }

    if (map_parity) {
        unmap_file(map_parity, parity_size);
    }

    if (parity_file) {
        fclose(parity_file);
    }

    if (encrypted_file) {
        fclose(encrypted_file);
    }
}


static void queue_create_parity_shards(storj_upload_state_t *state)
{
    uv_work_t *work = uv_work_new();
    if (!work) {
        state->error_status = STORJ_MEMORY_ERROR;
        return;
    }

    state->pending_work_count += 1;

    parity_shard_req_t *req = malloc(sizeof(parity_shard_req_t));

    req->error_status = 0;
    req->upload_state = state;
    work->data = req;

    int status = uv_queue_work(state->env->loop, (uv_work_t*) work,
                               create_parity_shards, after_create_parity_shards);

    if (status) {
        state->error_status = STORJ_QUEUE_ERROR;
    }

    state->awaiting_parity_shards = false;
}

static void after_send_exchange_report(uv_work_t *work, int status)
{
    shard_send_report_t *req = work->data;

    req->state->pending_work_count -= 1;

    if (status == UV_ECANCELED) {
        req->report->send_count = 0;
        req->report->send_status = STORJ_REPORT_AWAITING_SEND;

        goto clean_variables;
    }

    req->report->send_count += 1;

    if (req->status_code == 201) {
        req->state->env->log->info(req->state->env->log_options,
                        req->state->handle,
                         "Successfully sent exchange report for shard %d",
                         req->report->pointer_index);

        req->report->send_status = STORJ_REPORT_NOT_PREPARED; // report has been sent
    } else if (req->report->send_count == 6) {
        req->report->send_status = STORJ_REPORT_NOT_PREPARED; // report failed retries
    } else {
        req->report->send_status = STORJ_REPORT_AWAITING_SEND; // reset report back to unsent
    }

clean_variables:
    queue_next_work(req->state);
    free(work->data);
    free(work);

}

static void send_exchange_report(uv_work_t *work)
{
    shard_send_report_t *req = work->data;
    storj_upload_state_t *state = req->state;

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
    struct json_object *response = NULL;
    int request_status = fetch_json(req->http_options,
                                    req->options, "POST",
                                    "/reports/exchanges", body,
                                    true, &response, &status_code);


    if (request_status) {
        state->log->warn(state->env->log_options, state->handle,
                         "Send exchange report error: %i", request_status);
    }

    req->status_code = status_code;

    // free all memory for body and response
    json_object_put(response);
    json_object_put(body);
}

static void queue_send_exchange_report(storj_upload_state_t *state, int index)
{
    if (state->shard[index].report->send_count == 6) {
        return;
    }

    state->env->log->info(state->env->log_options, state->handle,
                   "Sending exchange report for Shard index %d... (retry: %d)",
                   index,
                  state->shard[index].report->send_count);

    shard_tracker_t *shard = &state->shard[index];

    uv_work_t *work = malloc(sizeof(uv_work_t));
    assert(work != NULL);

    shard_send_report_t *req = malloc(sizeof(shard_send_report_t));

    req->http_options = state->env->http_options;
    req->options = state->env->bridge_options;
    req->status_code = 0;
    req->report = shard->report;
    req->report->send_status = STORJ_REPORT_SENDING;
    req->state = state;
    req->pointer_index = index;

    work->data = req;

    state->pending_work_count += 1;
    int status = uv_queue_work(state->env->loop, (uv_work_t*) work,
                               send_exchange_report, after_send_exchange_report);
    if (status) {
        state->error_status = STORJ_QUEUE_ERROR;
    }
}

static void verify_bucket_id_callback(uv_work_t *work_req, int status)
{
    get_bucket_request_t *req = work_req->data;
    storj_upload_state_t *state = req->handle;

    state->log->info(state->env->log_options, state->handle,
                     "Checking if bucket id [%s] exists", state->bucket_id);

    state->pending_work_count -= 1;
    state->bucket_verify_count += 1;

    if (req->status_code == 200) {
        state->bucket_verified = true;
        goto clean_variables;
    } else if (req->status_code == 404 || req->status_code == 400) {
        state->log->error(state->env->log_options, state->handle,
                         "Bucket [%s] doesn't exist", state->bucket_id);
        state->error_status = STORJ_BRIDGE_BUCKET_NOTFOUND_ERROR;
    } else {
        state->log->error(state->env->log_options, state->handle,
                         "Request failed with status code: %i", req->status_code);

         if (state->bucket_verify_count == 6) {
             state->error_status = STORJ_BRIDGE_REQUEST_ERROR;
             state->bucket_verify_count = 0;
         }

         goto clean_variables;
    }
    state->bucket_verified = true;

clean_variables:
    queue_next_work(state);

    storj_free_get_bucket_request(req);
    free(work_req);
}

static void queue_verify_bucket_id(storj_upload_state_t *state)
{
    state->pending_work_count += 1;
    storj_bridge_get_bucket(state->env, state->bucket_id, state, verify_bucket_id_callback);
}


static void verify_file_name_callback(uv_work_t *work_req, int status)
{
    json_request_t *req = work_req->data;
    storj_upload_state_t *state = req->handle;

    state->pending_work_count -= 1;
    state->file_verify_count += 1;

    if (req->status_code == 404) {
        state->file_verified = true;
        goto clean_variables;
    } else if (req->status_code == 200) {
        state->log->error(state->env->log_options, state->handle,
                          "File [%s] already exists", state->file_name);
        state->error_status = STORJ_BRIDGE_BUCKET_FILE_EXISTS;
    } else {
        state->log->error(state->env->log_options, state->handle,
                          "Request failed with status code: %i", req->status_code);

        if (state->file_verify_count == 6) {
            state->error_status = STORJ_BRIDGE_REQUEST_ERROR;
            state->file_verify_count = 0;
        }

        goto clean_variables;
    }

    state->file_verified = true;

clean_variables:
    queue_next_work(state);

    json_object_put(req->response);
    free(req->path);
    free(req);
    free(work_req);
}

static void verify_file_name(uv_work_t *work)
{
    json_request_t *req = work->data;
    storj_upload_state_t *state = req->handle;
    int status_code = 0;

    state->log->info(state->env->log_options, state->handle,
                     "Checking if file name [%s] already exists...", state->file_name);

    req->error_code = fetch_json(req->http_options,
                                 req->options, req->method, req->path, req->body,
                                 req->auth, &req->response, &status_code);

    req->status_code = status_code;
}

static void queue_verify_file_name(storj_upload_state_t *state)
{
    state->pending_work_count += 1;

    CURL *curl = curl_easy_init();
    if (!curl) {
        state->error_status = STORJ_MEMORY_ERROR;
        return;
    }

    char *escaped = curl_easy_escape(curl, state->encrypted_file_name,
                                     strlen(state->encrypted_file_name));

    if (!escaped) {
        curl_easy_cleanup(curl);
        state->error_status = STORJ_MEMORY_ERROR;
        return;
    }

    char *path = str_concat_many(4, "/buckets/", state->bucket_id,
                                 "/file-ids/", escaped);
    curl_free(escaped);
    curl_easy_cleanup(curl);

    if (!path) {
        state->error_status = STORJ_MEMORY_ERROR;
        return;
    }

    uv_work_t *work = uv_work_new();
    if (!work) {
        state->error_status = STORJ_MEMORY_ERROR;
        return;
    }

    json_request_t *req = malloc(sizeof(json_request_t));
    if (!req) {
        state->error_status = STORJ_MEMORY_ERROR;
        return;
    }

    req->http_options = state->env->http_options;
    req->options = state->env->bridge_options;
    req->method = "GET";
    req->path = path;
    req->auth = true;
    req->body = NULL;
    req->response = NULL;
    req->error_code = 0;
    req->status_code = 0;
    req->handle = state;

    work->data = req;

    int status = uv_queue_work(state->env->loop, (uv_work_t*) work,
                               verify_file_name, verify_file_name_callback);

    if (status) {
        state->error_status = STORJ_QUEUE_ERROR;
        return;
    }
}

// Check if a frame/shard is already being prepared/pushed.
// We want to limit disk reads for dd and network activity
static int check_in_progress(storj_upload_state_t *state, int status)
{
    int active = 0;

    for (int index = 0; index < state->total_shards; index++ ) {
        if (state->shard[index].progress == status) {
            active += 1;
        }
    }

    return active;
}

static void queue_push_frame_and_shard(storj_upload_state_t *state)
{
    for (int index = 0; index < state->total_shards; index++) {

        if (state->shard[index].progress == AWAITING_PUSH_FRAME &&
            state->shard[index].report->send_status == STORJ_REPORT_NOT_PREPARED &&
            check_in_progress(state, PUSHING_FRAME) < state->push_frame_limit) {
            queue_push_frame(state, index);
        }

        if (state->shard[index].progress == AWAITING_PUSH_SHARD &&
            state->shard[index].report->send_status == STORJ_REPORT_NOT_PREPARED &&
            check_in_progress(state, PUSHING_SHARD) < state->push_shard_limit) {
            queue_push_shard(state, index);
        }
    }
}

static void queue_next_work(storj_upload_state_t *state)
{
    storj_log_levels_t *log = state->log;
    storj_log_options_t *log_options = state->env->log_options;
    void *handle = state->handle;
    int *pending_work_count = &state->pending_work_count;

    if (state->canceled) {
        return cleanup_state(state);
    }

    // report any errors
    if (state->error_status != 0) {
        return cleanup_state(state);
    }

    // report upload complete
    if (state->completed_upload) {
        return cleanup_state(state);
    }

    // Verify bucket_id is exists
    if (!state->bucket_verified) {
        queue_verify_bucket_id(state);
        goto finish_up;
    }

    // Verify that the file name doesn't exist
    if (!state->file_verified) {
        queue_verify_file_name(state);
        goto finish_up;
    }

    if (!state->frame_id && !state->requesting_frame) {
        queue_request_frame_id(state);
        goto finish_up;
    }

    if (state->rs) {
        if (!state->encrypted_file) {
            queue_create_encrypted_file(state);
            goto finish_up;
        }

        // Create parity shards using reed solomon
        if (state->awaiting_parity_shards) {
            queue_create_parity_shards(state);
            goto finish_up;
        }
    }

    for (int index = 0; index < state->total_shards; index++ ) {
        if (state->shard[index].progress == AWAITING_PREPARE_FRAME &&
            check_in_progress(state, PREPARING_FRAME) < state->prepare_frame_limit) {
            queue_prepare_frame(state, index);
        }
    }

    // report upload complete
    if (state->completed_shards == state->total_shards &&
        !state->creating_bucket_entry &&
        !state->completed_upload) {
        queue_create_bucket_entry(state);
    }

    for (int index = 0; index < state->total_shards; index++ ) {
        if (state->shard[index].report->send_status == STORJ_REPORT_AWAITING_SEND) {
            queue_send_exchange_report(state, index);
        }
    }

    // NB: This needs to be the last thing, there is a bug with mingw
    // builds and uv_async_init, where leaving a block will cause the state
    // pointer to change values.
    if (state->frame_id) {
        queue_push_frame_and_shard(state);
    }

finish_up:

    log->debug(log_options, handle,
               "Pending work count: %d", *pending_work_count);
}

static void begin_work_queue(uv_work_t *work, int status)
{
    storj_upload_state_t *state = work->data;

    // Load progress bar
    state->progress_cb(0, 0, 0, state->handle);

    state->pending_work_count -= 1;
    queue_next_work(state);

    free(work);
}

static void prepare_upload_state(uv_work_t *work)
{
    storj_upload_state_t *state = work->data;

    // Get the file size, expect to be up to 10tb
#ifdef _WIN32
    struct _stati64 st;

    if(_fstati64(fileno(state->original_file), &st) != 0) {
        state->error_status = STORJ_FILE_INTEGRITY_ERROR;
        return;
    }
#else
    struct stat st;
    if(fstat(fileno(state->original_file), &st) != 0) {
        state->error_status = STORJ_FILE_INTEGRITY_ERROR;
        return;
    }
#endif

    state->file_size = st.st_size;
    if (state->file_size < MIN_SHARD_SIZE) {
        state->rs = false;
    }

    // Set Shard calculations
    state->shard_size = determine_shard_size(state->file_size, 0);
    if (!state->shard_size || state->shard_size == 0) {
        state->error_status = STORJ_FILE_SIZE_ERROR;
        return;
    }

    state->total_data_shards = ceil((double)state->file_size / state->shard_size);
    state->total_parity_shards = (state->rs) ? ceil((double)state->total_data_shards * 2.0 / 3.0) : 0;
    state->total_shards = state->total_data_shards + state->total_parity_shards;

    int tracker_calloc_amount = state->total_shards * sizeof(shard_tracker_t);
    state->shard = malloc(tracker_calloc_amount);
    if (!state->shard) {
        state->error_status = STORJ_MEMORY_ERROR;
        return;
    }

    for (int i = 0; i < state->total_shards; i++) {
        state->shard[i].progress = AWAITING_PREPARE_FRAME;
        state->shard[i].push_frame_request_count = 0;
        state->shard[i].push_shard_request_count = 0;
        state->shard[i].index = i;
        state->shard[i].pointer = farmer_pointer_new();
        if (!state->shard[i].pointer) {
            state->error_status = STORJ_MEMORY_ERROR;
            return;
        }
        state->shard[i].meta = shard_meta_new();
        if (!state->shard[i].meta) {
            state->error_status = STORJ_MEMORY_ERROR;
            return;
        }
        state->shard[i].meta->is_parity = (i + 1 > state->total_data_shards) ? true : false;
        state->shard[i].report = storj_exchange_report_new();
        if (!state->shard[i].report) {
            state->error_status = STORJ_MEMORY_ERROR;
            return;
        }
        state->shard[i].uploaded_size = 0;
        state->shard[i].work = NULL;
    }

    // Get the bucket key to encrypt the filename
    char *bucket_key_as_str = calloc(DETERMINISTIC_KEY_SIZE + 1, sizeof(char));
    generate_bucket_key(state->env->encrypt_options->mnemonic,
                        state->bucket_id,
                        &bucket_key_as_str);

    uint8_t *bucket_key = str2hex(strlen(bucket_key_as_str), bucket_key_as_str);
    if (!bucket_key) {
        state->error_status = STORJ_MEMORY_ERROR;
        return;
    }

    free(bucket_key_as_str);

    // Get file name encryption key with first half of hmac w/ magic
    struct hmac_sha512_ctx ctx1;
    hmac_sha512_set_key(&ctx1, SHA256_DIGEST_SIZE, bucket_key);
    hmac_sha512_update(&ctx1, SHA256_DIGEST_SIZE, BUCKET_META_MAGIC);
    uint8_t key[SHA256_DIGEST_SIZE];
    hmac_sha512_digest(&ctx1, SHA256_DIGEST_SIZE, key);

    // Generate the synthetic iv with first half of hmac w/ bucket and filename
    struct hmac_sha512_ctx ctx2;
    hmac_sha512_set_key(&ctx2, SHA256_DIGEST_SIZE, bucket_key);
    hmac_sha512_update(&ctx2, strlen(state->bucket_id),
                       (uint8_t *)state->bucket_id);
    hmac_sha512_update(&ctx2, strlen(state->file_name),
                       (uint8_t *)state->file_name);
    uint8_t filename_iv[SHA256_DIGEST_SIZE];
    hmac_sha512_digest(&ctx2, SHA256_DIGEST_SIZE, filename_iv);

    free(bucket_key);

    char *encrypted_file_name;
    encrypt_meta(state->file_name, key, filename_iv, &encrypted_file_name);

    state->encrypted_file_name = encrypted_file_name;

    uint8_t *index = NULL;
    char *key_as_str = NULL;

    if (state->index) {
        index = str2hex(strlen(state->index), (char *)state->index);
        if (!index) {
            state->error_status = STORJ_MEMORY_ERROR;
            goto cleanup;
        }
    } else {
        // Get random index used for encryption
        index = calloc(SHA256_DIGEST_SIZE + 1, sizeof(uint8_t));
        if (!index) {
            state->error_status = STORJ_MEMORY_ERROR;
            goto cleanup;
        }
        random_buffer(index, SHA256_DIGEST_SIZE);
    }

    char *index_as_str = hex2str(SHA256_DIGEST_SIZE, index);
    if (!index_as_str) {
        state->error_status = STORJ_MEMORY_ERROR;
        goto cleanup;
    }

    state->index = index_as_str;

    // Caculate the file encryption key based on the index
    key_as_str = calloc(DETERMINISTIC_KEY_SIZE + 1, sizeof(char));
    if (!key_as_str) {
        state->error_status = STORJ_MEMORY_ERROR;
        goto cleanup;
    }

    int key_status = generate_file_key(state->env->encrypt_options->mnemonic,
                                       state->bucket_id,
                                       index_as_str,
                                       &key_as_str);
    if (key_status) {
        switch (key_status) {
            case 2:
                state->error_status = STORJ_HEX_DECODE_ERROR;
                break;
            default:
                state->error_status = STORJ_MEMORY_ERROR;
        }
        goto cleanup;
    }

    uint8_t *encryption_key = str2hex(strlen(key_as_str), key_as_str);
    if (!encryption_key) {
        state->error_status = STORJ_MEMORY_ERROR;
        goto cleanup;
    }
    state->encryption_key = encryption_key;

    uint8_t *encryption_ctr = calloc(AES_BLOCK_SIZE, sizeof(uint8_t));
    if (!encryption_ctr) {
        state->error_status = STORJ_MEMORY_ERROR;
        goto cleanup;
    }
    memcpy(encryption_ctr, index, AES_BLOCK_SIZE);
    state->encryption_ctr = encryption_ctr;

    if (state->rs) {
        state->parity_file_path = create_tmp_name(state, ".parity");
        state->encrypted_file_path = create_tmp_name(state, ".crypt");
    }


cleanup:
    if (key_as_str) {
        free(key_as_str);
    }

    if (index) {
        free(index);
    }

}

char *create_tmp_name(storj_upload_state_t *state, char *extension)
{
    char *tmp_folder = strdup(state->env->tmp_path);
    int encode_len = BASE16_ENCODE_LENGTH(SHA256_DIGEST_SIZE);
    int file_name_len = strlen(state->encrypted_file_name);
    int extension_len = strlen(extension);
    int tmp_folder_len = strlen(tmp_folder);
    if (tmp_folder[tmp_folder_len - 1] == separator()) {
        tmp_folder[tmp_folder_len - 1] = '\0';
        tmp_folder_len -= 1;
    }

    char *path = calloc(
        tmp_folder_len + 1 + encode_len + extension_len + 2,
        sizeof(char)
    );

    // hash and encode name for filesystem use
    struct sha256_ctx ctx;
    uint8_t digest[SHA256_DIGEST_SIZE];
    uint8_t digest_encoded[encode_len + 1];
    sha256_init(&ctx);
    sha256_update(&ctx, file_name_len, state->encrypted_file_name);
    sha256_digest(&ctx, SHA256_DIGEST_SIZE, digest);
    base16_encode_update(digest_encoded, SHA256_DIGEST_SIZE, digest);
    digest_encoded[encode_len] = '\0';

    sprintf(path,
            "%s%c%s%s%c",
            tmp_folder,
            separator(),
            digest_encoded,
            extension,
            '\0');

    free(tmp_folder);
    return path;
}

STORJ_API int storj_bridge_store_file_cancel(storj_upload_state_t *state)
{
    if (state->canceled) {
        return 0;
    }

    state->canceled = true;

    state->error_status = STORJ_TRANSFER_CANCELED;

    // loop over all shards, and cancel any that are queued to be uploaded
    // any uploads that are in-progress will monitor the state->canceled
    // status and exit when set to true
    for (int i = 0; i < state->total_shards; i++) {
        shard_tracker_t *shard = &state->shard[i];
        if (shard->progress == PUSHING_SHARD) {
            uv_cancel((uv_req_t *)shard->work);
        }
    }

    return 0;
}

STORJ_API storj_upload_state_t *storj_bridge_store_file(storj_env_t *env,
                            storj_upload_opts_t *opts,
                            void *handle,
                            storj_progress_cb progress_cb,
                            storj_finished_upload_cb finished_cb)
{
    if (!opts->fd) {
        env->log->error(env->log_options, handle, "Invalid File descriptor");
        return NULL;
    }

    storj_upload_state_t *state = malloc(sizeof(storj_upload_state_t));
    if (!state) {
        return NULL;
    }

    state->env = env;
    if (opts->index && strlen(opts->index) == 64) {
        state->index = opts->index;
    } else {
        state->index = NULL;
    }
    state->file_id = NULL;
    state->file_name = opts->file_name;
    state->encrypted_file_name = NULL;
    state->original_file = opts->fd;
    state->file_size = 0;
    state->bucket_id = opts->bucket_id;
    state->bucket_key = NULL;
    state->completed_shards = 0;
    state->total_shards = 0;
    state->total_data_shards = 0;
    state->total_parity_shards = 0;
    state->shard_size = 0;
    state->total_bytes = 0;
    state->uploaded_bytes = 0;
    state->exclude = NULL;
    state->frame_id = NULL;
    state->hmac_id = NULL;
    state->encryption_key = NULL;
    state->encryption_ctr = NULL;

    state->rs = (opts->rs == false) ? false : true;
    state->awaiting_parity_shards = true;
    state->parity_file_path = NULL;
    state->parity_file = NULL;

    // Only use this if rs after encryption
    state->encrypted_file = NULL;
    state->encrypted_file_path = NULL;
    state->creating_encrypted_file = false;

    state->requesting_frame = false;
    state->completed_upload = false;
    state->creating_bucket_entry = false;
    state->received_all_pointers = false;
    state->final_callback_called = false;
    state->canceled = false;
    state->bucket_verified = false;
    state->file_verified = false;

    state->progress_finished = false;

    state->push_shard_limit = (opts->push_shard_limit > 0) ? (opts->push_shard_limit) : PUSH_SHARD_LIMIT;
    state->push_frame_limit = (opts->push_frame_limit > 0) ? (opts->push_frame_limit) : PUSH_FRAME_LIMIT;
    state->prepare_frame_limit = (opts->prepare_frame_limit > 0) ? (opts->prepare_frame_limit) : PREPARE_FRAME_LIMIT;

    state->frame_request_count = 0;
    state->add_bucket_entry_count = 0;
    state->bucket_verify_count = 0;
    state->file_verify_count = 0;
    state->create_encrypted_file_count = 0;

    state->progress_cb = progress_cb;
    state->finished_cb = finished_cb;
    state->error_status = 0;
    state->log = env->log;
    state->handle = handle;
    state->shard = NULL;
    state->pending_work_count = 0;

    uv_work_t *work = uv_work_new();
    work->data = state;

    state->pending_work_count += 1;

    int status = uv_queue_work(env->loop, (uv_work_t*) work,
                               prepare_upload_state, begin_work_queue);
    if (status) {
        state->error_status = STORJ_QUEUE_ERROR;
    }
    return state;
}
