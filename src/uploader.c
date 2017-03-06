#include "uploader.h"

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
        req->shard_index = *index;
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

    req->shard_meta->index = index;
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

    if (state->file_id) {
        free(state->file_id);
    }

    if (state->file_key) {
        memset_zero(state->file_key, SHA256_DIGEST_SIZE + 1);
        free(state->file_key);
    }

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

    state->finished_cb(state->error_status, state->handle);

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

static uint64_t check_file(storj_env_t *env, const char *filepath)
{
    int r = 0;
    uv_fs_t *stat_req = malloc(sizeof(uv_fs_t));
    if (!stat_req) {
        return 0;
    }

    r = uv_fs_stat(env->loop, stat_req, filepath, NULL);
    if (r < 0) {
        const char *msg = uv_strerror(r);
        free(stat_req);
        return 0;
    }

    long long size = (stat_req->statbuf.st_size);

    free(stat_req);

    return size;
}

static uint64_t determine_shard_size(storj_upload_state_t *state,
                                     int accumulator)
{
    int shard_concurrency;
    uint64_t file_size;

    if (!state->file_size) {
        state->log->error(state->env->log_options, state->handle,
                          "File size is unknown");

        return 0;
    } else {
        file_size = state->file_size;
    }

    if (!state->shard_concurrency) {
        shard_concurrency = 3;
    } else {
        shard_concurrency = state->shard_concurrency;
    }

    accumulator = accumulator ? accumulator : 0;

    // Determine hops back by accumulator
    int hops = ((accumulator - SHARD_MULTIPLES_BACK) < 0 ) ?
        0 : accumulator - SHARD_MULTIPLES_BACK;

    uint64_t byte_multiple = shard_size(accumulator);
    double check = (double) file_size / byte_multiple;

    // Determine if bytemultiple is highest bytemultiple that is still <= size
    if (check > 0 && check <= 1) {

        // Certify the number of concurrency * shard_size doesn't exceed freemem
        //TODO: 1GB max memory
        while (hops > 0 &&
               (MAX_SHARD_SIZE / shard_size(hops) <= shard_concurrency)) {
            hops = hops - 1 <= 0 ? 0 : hops - 1;
        }

        return shard_size(hops);
    }

    // Maximum of 2 ^ 41 * 8 * 1024 * 1024
    if (accumulator > 41) {
        return 0;
    }

    return determine_shard_size(state, ++accumulator);
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
    } else if (state->add_bucket_entry_count == 6) {
        state->error_status = STORJ_BRIDGE_TOKEN_ERROR;
    }

clean_variables:
    queue_next_work(state);
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

    struct json_object *hmac = json_object_new_object();

    json_object *type = json_object_new_string("sha512");
    json_object_object_add(hmac, "type", type);

    json_object *value = json_object_new_string(state->hmac_id);
    json_object_object_add(hmac, "value", value);

    json_object_object_add(body, "hmac", hmac);

    int path_len = strlen(state->bucket_id) + 16;
    char *path = calloc(path_len + 1, sizeof(char));
    if (!path) {
        req->error_status = STORJ_MEMORY_ERROR;
        return;
    }
    sprintf(path, "%s%s%s%c", "/buckets/", state->bucket_id, "/files", '\0');

    int status_code;
    struct json_object *response = NULL;
    int request_status = fetch_json(req->http_options,
                                    req->options,
                                    "POST",
                                    path,
                                    body,
                                    true,
                                    NULL,
                                    &response,
                                    &status_code);

    req->log->debug(state->env->log_options,
                    state->handle,
                    "fn[create_bucket_entry] - JSON Response: %s",
                    json_object_to_json_string(response));


    if (request_status) {
        req->log->warn(state->env->log_options, state->handle,
                       "Create bucket entry error: %i", request_status);
    }


    req->status_code = status_code;

    json_object_put(response);
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
                                  RIPEMD160_DIGEST_SIZE * 2, shard->meta->hash)) {
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

    base16_encode_update(state->hmac_id, SHA512_DIGEST_SIZE, digest_raw);

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
    shard_tracker_t *shard = &state->shard[req->shard_index];

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
                       "Successfully transfered shard index %d",
                       req->shard_index);

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
                            "Failed to push shard %d\n", req->shard_index);

            state->error_status = STORJ_FARMER_REQUEST_ERROR;
        } else {
            req->log->warn(state->env->log_options, state->handle,
                           "Failed to push shard %d... Retrying...",
                           req->shard_index);

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
    shard_tracker_t *shard = &state->shard[req->shard_index];

    req->log->info(state->env->log_options, state->handle,
                   "Transfering Shard index %d... (retry: %d)",
                   req->shard_index,
                   state->shard[req->shard_index].push_shard_request_count);

    int status_code = 0;

    req->start = get_time_milliseconds();

    uint64_t file_position = req->shard_index * state->shard_size;

    // Initialize the encryption context
    storj_encryption_ctx_t *encryption_ctx = prepare_encryption_ctx(state->encryption_ctr,
                                                                    state->encryption_key);
    if (!encryption_ctx) {
        state->error_status = STORJ_MEMORY_ERROR;
        goto clean_variables;
    }
    // Increment the iv to proper placement because we may be reading from the middle of the file
    increment_ctr_aes_iv(encryption_ctx->encryption_ctr, req->shard_index*state->shard_size);

    int req_status = put_shard(req->http_options,
                               shard->pointer->farmer_node_id,
                               "http",
                               shard->pointer->farmer_address,
                               atoi(shard->pointer->farmer_port),
                               shard->meta->hash,
                               shard->meta->size,
                               state->original_file,
                               file_position,
                               encryption_ctx,
                               shard->pointer->token,
                               &status_code,
                               &req->progress_handle,
                               req->canceled);


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
    req->shard_index = index;
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
        state->shard[req->shard_index].push_frame_request_count = 0;
        state->shard[req->shard_index].progress = AWAITING_PUSH_FRAME;
        goto clean_variables;
    }

    // Increment request count every request for retry counts
    state->shard[req->shard_index].push_frame_request_count += 1;

    // Check if we got a 200 status and token
    if ((req->status_code == 200 || req->status_code == 201) &&
        pointer->token != NULL) {

        // Reset for if we need to get a new pointer later
        state->shard[req->shard_index].push_frame_request_count = 0;
        state->shard[req->shard_index].progress = AWAITING_PUSH_SHARD;

        farmer_pointer_t *p = state->shard[req->shard_index].pointer;

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

    } else if (state->shard[req->shard_index].push_frame_request_count == 6) {
        state->error_status = STORJ_BRIDGE_REQUEST_ERROR;
    } else {
        state->shard[req->shard_index].progress = AWAITING_PUSH_FRAME;
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
    shard_meta_t *shard_meta = state->shard[req->shard_index].meta;

    req->log->info(state->env->log_options, state->handle,
                   "Pushing frame for shard index %d... (retry: %d)",
                   req->shard_index,
                   state->shard[req->shard_index].push_frame_request_count);

    // Prepare the body
    struct json_object *body = json_object_new_object();

    // Add shard hash
    json_object *shard_hash = json_object_new_string(shard_meta->hash);
    json_object_object_add(body, "hash", shard_hash);

    // Add shard size
    json_object *shard_size = json_object_new_int64(shard_meta->size);
    json_object_object_add(body, "size", shard_size);

    // Add shard index
    json_object *shard_index = json_object_new_int(shard_meta->index);
    json_object_object_add(body, "index", shard_index);

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
            // TODO safe to return here?
            return;
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

    char resource[strlen(state->frame_id) + 9];
    memset(resource, '\0', strlen(state->frame_id) + 9);
    strcpy(resource, "/frames/");
    strcat(resource, state->frame_id);

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
                                    NULL,
                                    &response,
                                    &status_code);

    if (request_status) {
        req->log->warn(state->env->log_options, state->handle,
                       "Push frame error: %i", request_status);
        req->error_status = STORJ_BRIDGE_REQUEST_ERROR;
        goto clean_variables;
    }

    req->log->debug(state->env->log_options, state->handle,
                    "fn[push_frame] - JSON Response: %s",
                    json_object_to_json_string(response));

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

    // Farmer pointer
    req->shard_index = shard_meta->index;

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
    json_object_put(response);
    json_object_put(body);
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
    state->shard[shard_meta->index].meta->hash =
        calloc(RIPEMD160_DIGEST_SIZE * 2 + 1, sizeof(char));

    if (!state->shard[shard_meta->index].meta->hash) {
        state->error_status = STORJ_MEMORY_ERROR;
        goto clean_variables;
    }

    memcpy(state->shard[shard_meta->index].meta->hash,
           shard_meta->hash,
           RIPEMD160_DIGEST_SIZE * 2);

    req->log->info(state->env->log_options, state->handle,
                  "Shard (%d) hash: %s", shard_meta->index,
                  state->shard[shard_meta->index].meta->hash);

    // Add challenges_as_str
    state->log->debug(state->env->log_options, state->handle,
                      "Challenges for shard index %d",
                      shard_meta->index);

    for (int i = 0; i < STORJ_SHARD_CHALLENGES; i++ ) {
        memcpy(state->shard[shard_meta->index].meta->challenges_as_str[i],
               shard_meta->challenges_as_str[i],
               32);

        state->log->debug(state->env->log_options, state->handle,
                          "Shard %d Challenge [%d]: %s",
                          shard_meta->index,
                          i,
                          state->shard[shard_meta->index].meta->challenges_as_str[i]);
    }

    // Add Merkle Tree leaves.
    state->log->debug(state->env->log_options, state->handle,
                      "Tree for shard index %d",
                      shard_meta->index);

    for (int i = 0; i < STORJ_SHARD_CHALLENGES; i++ ) {
        memcpy(state->shard[shard_meta->index].meta->tree[i],
               shard_meta->tree[i],
               32);

        state->log->debug(state->env->log_options, state->handle,
                          "Shard %d Leaf [%d]: %s", shard_meta->index, i,
                          state->shard[shard_meta->index].meta->tree[i]);
    }

    // Add index
    state->shard[shard_meta->index].meta->index = shard_meta->index;

    // Add size
    state->shard[shard_meta->index].meta->size = shard_meta->size;

    state->log->info(state->env->log_options, state->handle,
                     "Successfully created frame for shard index %d",
                     shard_meta->index);

    state->shard[shard_meta->index].progress = AWAITING_PUSH_FRAME;

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
                   shard_meta->index);

    // Sha256 of encrypted data for calculating shard has
    uint8_t prehash_sha256[SHA256_DIGEST_SIZE];

    // Initialize context for sha256 of encrypted data
    struct sha256_ctx shard_hash_ctx;
    sha256_init(&shard_hash_ctx);

    // Calculate the merkle tree with challenges
    struct sha256_ctx first_sha256_for_leaf[STORJ_SHARD_CHALLENGES];
    for (int i = 0; i < STORJ_SHARD_CHALLENGES; i++ ) {
        sha256_init(&first_sha256_for_leaf[i]);
        sha256_update(&first_sha256_for_leaf[i], 32, (char *)&shard_meta->challenges[i]);
    }

    // Initialize the encryption context
    storj_encryption_ctx_t *encryption_ctx = prepare_encryption_ctx(state->encryption_ctr,
                                                                    state->encryption_key);
    if (!encryption_ctx) {
        state->error_status = STORJ_MEMORY_ERROR;
        goto clean_variables;
    }
    // Increment the iv to proper placement because we may be reading from the middle of the file
    increment_ctr_aes_iv(encryption_ctx->encryption_ctr, shard_meta->index*state->shard_size);

    uint8_t cphr_txt[AES_BLOCK_SIZE * 256];
    memset_zero(cphr_txt, AES_BLOCK_SIZE * 256);
    char read_data[AES_BLOCK_SIZE * 256];
    memset_zero(read_data, AES_BLOCK_SIZE * 256);
    unsigned long int read_bytes = 0;
    unsigned long int total_read = 0;

    do {
        read_bytes = pread(fileno(state->original_file),
                           read_data, AES_BLOCK_SIZE * 256,
                           shard_meta->index*state->shard_size + total_read);

        total_read += read_bytes;

        // Encrypt data
        ctr_crypt(encryption_ctx->ctx, (nettle_cipher_func *)aes256_encrypt,
                  AES_BLOCK_SIZE, encryption_ctx->encryption_ctr, read_bytes,
                  (uint8_t *)cphr_txt, (uint8_t *)read_data);

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
    char *buff2 = calloc(RIPEMD160_DIGEST_SIZE*2 +1, sizeof(char));
    for (int i = 0; i < STORJ_SHARD_CHALLENGES; i++ ) {
        // finish first sha256 for leaf
        sha256_digest(&first_sha256_for_leaf[i], SHA256_DIGEST_SIZE, preleaf_sha256);

        // ripemd160 result of sha256
        ripemd160_of_str(preleaf_sha256, SHA256_DIGEST_SIZE, preleaf_ripemd160);

        // sha256 and ripemd160 again
        ripmd160sha256_as_string(preleaf_ripemd160, RIPEMD160_DIGEST_SIZE, &buff2);

        memcpy(shard_meta->tree[i], buff2, RIPEMD160_DIGEST_SIZE*2 + 1);
    }

clean_variables:
    if (encryption_ctx) {
        free_encryption_ctx(encryption_ctx);
    }

    if (buff2) {
        free(buff2);
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

    // Check if we got a 201 status and token
    if (req->error_status == 0 && req->status_code == 200 && req->frame_id) {

        state->log->info(state->env->log_options, state->handle,
                         "Successfully retrieved frame id");

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
                                    NULL,
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

/**
 * pre_pass - file_key
 * pre_salt - file_id
 */
static int prepare_encryption_key(storj_upload_state_t *state,
                               char *pre_pass,
                               int pre_pass_size,
                               char *pre_salt,
                               int pre_salt_size)
{
    // Convert file key to password
    state->encryption_key = calloc(SHA256_DIGEST_SIZE + 1, sizeof(char));
    if (!state->encryption_key) {
        return 1;
    }

    sha256_of_str((uint8_t *)pre_pass, pre_pass_size, state->encryption_key);
    state->encryption_key[SHA256_DIGEST_SIZE] = '\0';

    // Convert file id to salt
    char salt[RIPEMD160_DIGEST_SIZE + 1];
    memset_zero(salt, RIPEMD160_DIGEST_SIZE + 1);
    ripemd160_of_str((uint8_t *)pre_salt, pre_salt_size, salt);
    salt[RIPEMD160_DIGEST_SIZE] = '\0';

    // We only need the first 16 bytes of the salt because it's CTR mode
    state->encryption_ctr = calloc(AES_BLOCK_SIZE, sizeof(char));
    if (!state->encryption_ctr) {
        return 1;
    }

    memcpy(state->encryption_ctr, salt, AES_BLOCK_SIZE);

    return 0;

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
                                    NULL, NULL, &response, &status_code);


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

static void queue_push_frame_and_shard(storj_upload_state_t *state)
{
    for (int index = 0; index < state->total_shards; index++) {

        if (state->shard[index].progress == AWAITING_PUSH_FRAME &&
            state->shard[index].report->send_status == STORJ_REPORT_NOT_PREPARED) {
            queue_push_frame(state, index);
        }

        if (state->shard[index].progress == AWAITING_PUSH_SHARD &&
            state->shard[index].report->send_status == STORJ_REPORT_NOT_PREPARED) {
            queue_push_shard(state, index);
        }
    }
}

static void verify_bucket_id_callback(uv_work_t *work_req, int status)
{
    json_request_t *req = work_req->data;
    storj_upload_state_t *state = req->handle;

    state->log->info(state->env->log_options, state->handle,
                     "Checking if bucket id [%s] exists", state->bucket_id);

    state->pending_work_count -= 1;
    state->bucket_verify_count += 1;

    if (req->status_code == 200) {
        state->bucket_verified = true;
        goto clean_variables;
    } else if (req->status_code == 404) {
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

    json_object_put(req->response);
    free(req->path);
    free(req);
    free(work_req);
}

static void queue_verify_bucket_id(storj_upload_state_t *state)
{
    state->pending_work_count += 1;
    storj_bridge_get_bucket(state->env, state->bucket_id, state, verify_bucket_id_callback);
}

static void verify_file_id_callback(uv_work_t *work_req, int status)
{
    json_request_t *req = work_req->data;
    storj_upload_state_t *state = req->handle;

    state->log->info(state->env->log_options, state->handle,
                     "Checking if file id [%s] already exists...", state->file_id);

    state->pending_work_count -= 1;
    state->file_verify_count += 1;

    if (req->status_code == 404) {
        state->file_verified = true;
        goto clean_variables;
    } else if (req->status_code == 200) {
        state->log->error(state->env->log_options, state->handle,
                         "File [%s] already exists", state->file_id);
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

static void queue_verify_file_id(storj_upload_state_t *state)
{
    state->pending_work_count += 1;
    storj_bridge_get_file_info(state->env,
                               state->bucket_id,
                               state->file_id,
                               state,
                               verify_file_id_callback);
}

static void queue_next_work(storj_upload_state_t *state)
{
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
        return queue_verify_bucket_id(state);
    }

    if (!state->file_verified) {
        return queue_verify_file_id(state);
    }

    if (!state->frame_id && !state->requesting_frame) {
        queue_request_frame_id(state);
    }

    for (int index = 0; index < state->total_shards; index++ ) {
        if (state->shard[index].progress == AWAITING_PREPARE_FRAME) {
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
}

static void begin_work_queue(uv_work_t *work, int status)
{
    storj_upload_state_t *state = work->data;

    state->pending_work_count -= 1;
    queue_next_work(state);

    free(work);
}

static void prepare_upload_state(uv_work_t *work)
{
    storj_upload_state_t *state = work->data;

    // Get the file size, expect to be up to 10tb
#ifdef _WIN32
    struct __stat64 st;

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

    // Set Shard calculations
    state->shard_size = determine_shard_size(state, 0);
    if (!state->shard_size) {
        state->error_status = STORJ_FILE_SIZE_ERROR;
        return;
    }

    state->total_shards = ceil((double)state->file_size / state->shard_size);

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
    hmac_sha512_update(&ctx2, strlen(state->bucket_id), state->bucket_id);
    hmac_sha512_update(&ctx2, strlen(state->file_name), state->file_name);
    uint8_t filename_iv[SHA256_DIGEST_SIZE];
    hmac_sha512_digest(&ctx2, SHA256_DIGEST_SIZE, filename_iv);

    free(bucket_key);

    char *encrypted_file_name;
    encrypt_meta(state->file_name, key, filename_iv, &encrypted_file_name);

    state->encrypted_file_name = encrypted_file_name;

    // Calculate deterministic file id from encrypted file name
    char *file_id = calloc(FILE_ID_SIZE + 1, sizeof(char));
    if (!file_id) {
        state->error_status = STORJ_MEMORY_ERROR;
        return;
    }

    calculate_file_id(state->bucket_id, state->encrypted_file_name, file_id);

    file_id[FILE_ID_SIZE] = '\0';
    state->file_id = file_id;

    // Caculate the file encryption key based on file id
    char *file_key = calloc(DETERMINISTIC_KEY_SIZE + 1, sizeof(char));
    if (!file_key) {
        state->error_status = STORJ_MEMORY_ERROR;
        return;
    }
    if (generate_file_key(state->env->encrypt_options->mnemonic,
                          state->bucket_id,
                          state->file_id,
                          &file_key)) {
        state->error_status = STORJ_MEMORY_ERROR;
        return;
    }

    file_key[DETERMINISTIC_KEY_SIZE] = '\0';
    state->file_key = file_key;

    prepare_encryption_key(state, file_key, DETERMINISTIC_KEY_SIZE, file_id, FILE_ID_SIZE);
}

int storj_bridge_store_file_cancel(storj_upload_state_t *state)
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

int storj_bridge_store_file(storj_env_t *env,
                            storj_upload_state_t *state,
                            storj_upload_opts_t *opts,
                            void *handle,
                            storj_progress_cb progress_cb,
                            storj_finished_upload_cb finished_cb)
{
    if (opts->shard_concurrency < 1) {
        env->log->error(env->log_options,
                        handle,
                        "Shard Concurrency (%i) can't be less than 1",
                        opts->shard_concurrency);
        return 1;
    } else if (!opts->shard_concurrency) {
        opts->shard_concurrency = 3;
    }

    if (!opts->fd) {
        env->log->error(env->log_options, handle, "Invalid File descriptor");
        return 1;
    }

    // setup upload state
    state->env = env;
    state->shard_concurrency = opts->shard_concurrency;
    state->file_id = NULL;
    state->file_name = opts->file_name;
    state->encrypted_file_name = NULL;
    state->original_file = opts->fd;
    state->file_key = NULL;
    state->file_size = 0;
    state->bucket_id = opts->bucket_id;
    state->bucket_key = NULL;
    state->completed_shards = 0;
    state->total_shards = 0;
    state->shard_size = 0;
    state->total_bytes = 0;
    state->uploaded_bytes = 0;
    state->exclude = NULL;
    state->frame_id = NULL;
    state->hmac_id = NULL;
    state->encryption_key = NULL;
    state->encryption_ctr = NULL;

    state->requesting_frame = false;
    state->completed_upload = false;
    state->creating_bucket_entry = false;
    state->received_all_pointers = false;
    state->final_callback_called = false;
    state->canceled = false;
    state->bucket_verified = false;
    state->file_verified = false;

    state->progress_finished = false;

    state->frame_request_count = 0;
    state->add_bucket_entry_count = 0;
    state->file_verify_count = 0;
    state->bucket_verify_count = 0;

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
    return uv_queue_work(env->loop, (uv_work_t*) work,
                         prepare_upload_state, begin_work_queue);


}
