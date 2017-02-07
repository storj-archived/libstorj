#include "uploader.h"

static uv_work_t *uv_work_new()
{
    uv_work_t *work = malloc(sizeof(uv_work_t));
    assert(work != NULL);
    return work;
}

static uv_work_t *frame_work_new(int *index, storj_upload_state_t *state)
{
    uv_work_t *work = uv_work_new();

    frame_request_t *req = malloc(sizeof(frame_request_t));
    assert(req != NULL);

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
    frame_builder_t *req = malloc(sizeof(frame_builder_t));
    req->shard_meta = malloc(sizeof(shard_meta_t));
    req->upload_state = state;
    req->log = state->log;

    assert(req->shard_meta != NULL);

    req->shard_meta->index = index;
    req->error_status = 0;

    work->data = req;

    return work;
}

static storj_exchange_report_t *storj_exchange_report_new()
{
    storj_exchange_report_t *report = malloc(sizeof(storj_exchange_report_t));
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
    pointer->token = NULL;
    pointer->farmer_user_agent = NULL;
    pointer->farmer_protocol = NULL;
    pointer->farmer_address = NULL;
    pointer->farmer_port = NULL;
    pointer->farmer_node_id = NULL;
    pointer->farmer_last_seen = NULL;

    return pointer;
}

static shard_meta_t *shard_meta_new()
{
    shard_meta_t *meta = calloc(sizeof(shard_meta_t), sizeof(char));
    meta->hash = NULL;

    return meta;
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

    if (farmer_pointer->farmer_last_seen != NULL) {
        free(farmer_pointer->farmer_last_seen);
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

    if (state->exclude) {
        free(state->exclude);
    }

    if (state->tmp_path) {
        // Delete the tmp_path file
        if( access( state->tmp_path, F_OK ) != -1 ) {
            unlink(state->tmp_path);
        }

        free(state->tmp_path);
    }

    if (state->shard) {
        for (int i = 0; i < state->total_shards; i++ ) {

            state->log->debug(state->env->log_options, state->handle,
                              "Cleaning up shard %d", i);

            shard_meta_cleanup(state->shard[i].meta);

            state->log->debug(state->env->log_options, state->handle,
                              "Cleaning up pointers %d", i);

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

static uint64_t check_file(storj_env_t *env, const char *filepath)
{
    int r = 0;
    uv_fs_t *stat_req = malloc(sizeof(uv_fs_t));

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

    uint64_t byteMultiple = shard_size(accumulator);
    double check = (double) file_size / byteMultiple;

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

    json_object *file_name = json_object_new_string(state->file_name);
    json_object_object_add(body, "filename",file_name);

    int path_len = strlen(state->bucket_id) + 16;
    char *path = calloc(path_len + 1, sizeof(char));
    sprintf(path, "%s%s%s%c", "/buckets/", state->bucket_id, "/files", '\0');

    int status_code;
    struct json_object *response = fetch_json(req->http_options,
                                              req->options,
                                              "POST",
                                              path,
                                              body,
                                              true,
                                              NULL,
                                              &status_code);

    req->status_code = status_code;

    json_object_put(response);
    json_object_put(body);
    free(path);
}

static int queue_create_bucket_entry(storj_upload_state_t *state)
{
    uv_work_t *work = uv_work_new();

    post_to_bucket_request_t *req = malloc(sizeof(post_to_bucket_request_t));
    assert(req != NULL);

    req->http_options = state->env->http_options;
    req->options = state->env->bridge_options;
    req->upload_state = state;
    req->error_status = 0;
    req->log = state->log;
    work->data = req;

    state->pending_work_count += 1;
    int status = uv_queue_work(state->env->loop, (uv_work_t*) work,
                               create_bucket_entry, after_create_bucket_entry);

    state->creating_bucket_entry = true;

    return status;
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
    if (req->status_code == 200 || req->status_code == 201 || req->status_code == 304) {

        req->log->info(state->env->log_options, state->handle,
                       "Successfully transfered shard index %d",
                       req->shard_index);

        shard->progress = COMPLETED_PUSH_SHARD;
        state->completed_shards += 1;
        shard->push_shard_request_count = 0;

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

    //get shard_data
    FILE *encrypted_file = fopen(state->tmp_path, "r");
    if (NULL == encrypted_file) {
        req->error_status = STORJ_FILE_INTEGRITY_ERROR;
        return;
    }

    // Encrypted shard read from file
    uint8_t *shard_data = calloc(shard->meta->size, sizeof(char));

    // Bytes read from file
    uint64_t read_bytes = 0;

    int loop_count = 0;

    do {
        if (loop_count == 6) {
            goto clean_variables;
        }

        // Seek to shard's location in file
        fseek(encrypted_file, req->shard_index*state->shard_size, SEEK_SET);
        // Read shard data from file
        read_bytes = fread(shard_data, 1, shard->meta->size, encrypted_file);

        if (read_bytes != shard->meta->size) {
            loop_count += 1;
        }

    } while(read_bytes < shard->meta->size);

    req->start = get_time_milliseconds();

    int req_status = put_shard(req->http_options,
                               shard->pointer->farmer_node_id,
                               "http",
                               shard->pointer->farmer_address,
                               atoi(shard->pointer->farmer_port),
                               shard->meta->hash,
                               shard->meta->size,
                               shard_data,
                               shard->pointer->token,
                               &status_code,
                               &req->progress_handle,
                               req->canceled);


    if (req_status) {
        req->log->error(state->env->log_options, state->handle,
                        "Put shard request error code: %i", req_status);
    }

    req->end = get_time_milliseconds();

    req->status_code = status_code;

clean_variables:
    if (encrypted_file) {
        fclose(encrypted_file);
    }

    if (shard_data) {
        free(shard_data);
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

static int queue_push_shard(storj_upload_state_t *state, int index)
{
    uv_work_t *work = uv_work_new();

    push_shard_request_t *req = malloc(sizeof(push_shard_request_t));
    assert(req != NULL);

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

    state->shard[index].progress = PUSHING_SHARD;

    if (state->shard[index].report->farmer_id != NULL) {
        free(state->shard[index].report);
        state->shard[index].report = storj_exchange_report_new();
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

    return status;
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
    if (req->error_status == 0 &&
        (req->status_code == 200 || req->status_code == 201) &&
        pointer->token != NULL) {

        // Reset for if we need to get a new pointer later
        state->shard[req->shard_index].push_frame_request_count = 0;
        state->shard[req->shard_index].progress = AWAITING_PUSH_SHARD;

        farmer_pointer_t *p = state->shard[req->shard_index].pointer;

        // Add token to shard[].pointer
        p->token = calloc(strlen(pointer->token) + 1, sizeof(char));
        memcpy(p->token, pointer->token, strlen(pointer->token));

        // Add farmer_user_agent to shard[].pointer
        p->farmer_user_agent = calloc(strlen(pointer->farmer_user_agent) + 1,
                                      sizeof(char));
        memcpy(p->farmer_user_agent, pointer->farmer_user_agent,
               strlen(pointer->farmer_user_agent));

        // Add farmer_address to shard[].pointer
        p->farmer_address = calloc(strlen(pointer->farmer_address) + 1,
                                   sizeof(char));
        memcpy(p->farmer_address, pointer->farmer_address,
               strlen(pointer->farmer_address));

        // Add farmer_port to shard[].pointer
        p->farmer_port = calloc(strlen(pointer->farmer_port) + 1, sizeof(char));
        memcpy(p->farmer_port, pointer->farmer_port,
               strlen(pointer->farmer_port));

        // Add farmer_protocol to shard[].pointer
        p->farmer_protocol = calloc(strlen(pointer->farmer_protocol) + 1,
                                    sizeof(char));
        memcpy(p->farmer_protocol, pointer->farmer_protocol,
               strlen(pointer->farmer_protocol));

        // Add farmer_node_id to shard[].pointer
        p->farmer_node_id = calloc(strlen(pointer->farmer_node_id) + 1,
                                   sizeof(char));
        memcpy(p->farmer_node_id, pointer->farmer_node_id,
               strlen(pointer->farmer_node_id));

        // Add farmer_last_seen to shard[].pointer
        p->farmer_last_seen = calloc(strlen(pointer->farmer_last_seen) + 1,
                                     sizeof(char));
        memcpy(p->farmer_last_seen, pointer->farmer_last_seen,
               strlen(pointer->farmer_last_seen));

        state->log->info(
            state->env->log_options,
            state->handle,
            "Contract negotiated with: "
            "{ "
            "\"userAgent: \"%s\", "
            "\"protocol:\" \"%s\", "
            "\"port\": \"%s\", "
            "\"nodeID\": \"%s\", "
            "\"lastSeen\": \"%s\" "
            "}",
            p->farmer_user_agent,
            p->farmer_protocol,
            p->farmer_port,
            p->farmer_node_id,
            p->farmer_last_seen
        );

    } else if (state->shard[req->shard_index].push_frame_request_count == 6) {
        state->error_status = STORJ_BRIDGE_TOKEN_ERROR;
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
    json_object *shard_size = json_object_new_double(shard_meta->size);
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
        strcpy(exclude_list, state->exclude);

        char *node_id = strtok(exclude_list,",");
        while (node_id != NULL)
        {
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
                    "JSON body: %s", json_object_to_json_string(body));

    int status_code;
    struct json_object *response = fetch_json(req->http_options,
                                              req->options,
                                              "PUT",
                                              resource,
                                              body,
                                              true,
                                              NULL,
                                              &status_code);

    req->log->debug(state->env->log_options, state->handle,
                    "JSON Response: %s",
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

    struct json_object *obj_farmer_last_seen;
    if (!json_object_object_get_ex(obj_farmer, "lastSeen",
                                   &obj_farmer_last_seen)) {

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
    memcpy(req->farmer_pointer->token, token, strlen(token));

    // Farmer pointer
    req->shard_index = shard_meta->index;

    // Farmer user agent
    char *farmer_user_agent =
        (char *)json_object_get_string(obj_farmer_user_agent);
    req->farmer_pointer->farmer_user_agent =
        calloc(strlen(farmer_user_agent) + 1, sizeof(char));
    memcpy(req->farmer_pointer->farmer_user_agent,
           farmer_user_agent,
           strlen(farmer_user_agent));

    // Farmer protocol
    char *farmer_protocol = (char *)json_object_get_string(obj_farmer_protocol);
    req->farmer_pointer->farmer_protocol =
        calloc(strlen(farmer_protocol) + 1, sizeof(char));
    memcpy(req->farmer_pointer->farmer_protocol,
           farmer_protocol,
           strlen(farmer_protocol));

    // Farmer address
    char *farmer_address = (char *)json_object_get_string(obj_farmer_address);
    req->farmer_pointer->farmer_address =
        calloc(strlen(farmer_address) + 1, sizeof(char));
    memcpy(req->farmer_pointer->farmer_address,
           farmer_address,
           strlen(farmer_address));

    // Farmer port
    char *farmer_port = (char *)json_object_get_string(obj_farmer_port);
    req->farmer_pointer->farmer_port = calloc(strlen(farmer_port) + 1, sizeof(char));
    memcpy(req->farmer_pointer->farmer_port, farmer_port, strlen(farmer_port));

    // Farmer node id
    char *farmer_node_id = (char *)json_object_get_string(obj_farmer_node_id);
    req->farmer_pointer->farmer_node_id =
        calloc(strlen(farmer_node_id) + 1, sizeof(char));
    memcpy(req->farmer_pointer->farmer_node_id,
           farmer_node_id,
           strlen(farmer_node_id));

    // Farmer last seen
    char *farmer_last_seen =
        (char *)json_object_get_string(obj_farmer_last_seen);
    req->farmer_pointer->farmer_last_seen =
        calloc(strlen(farmer_last_seen) + 1, sizeof(char));
    memcpy(req->farmer_pointer->farmer_last_seen,
           farmer_last_seen,
           strlen(farmer_last_seen));

    // Status code
    req->status_code = status_code;

clean_variables:
    json_object_put(response);
    json_object_put(body);
}

static int queue_push_frame(storj_upload_state_t *state, int index)
{
    if (state->shard[index].pointer->token != NULL) {
        pointer_cleanup(state->shard[index].pointer);
        state->shard[index].pointer = farmer_pointer_new();
    }

    uv_work_t *shard_work = frame_work_new(&index, state);

    state->pending_work_count += 1;
    uv_queue_work(state->env->loop, (uv_work_t*) shard_work,
                  push_frame, after_push_frame);

    state->shard[index].progress = PUSHING_FRAME;

    return 0;
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

    /* set the shard_meta to a struct array in the state for later use. */

    // Add Hash
    state->shard[shard_meta->index].meta->hash =
        calloc(RIPEMD160_DIGEST_SIZE * 2 + 1, sizeof(char));

    memcpy(state->shard[shard_meta->index].meta->hash,
           shard_meta->hash,
           RIPEMD160_DIGEST_SIZE * 2);

    // Add challenges_as_str
    state->log->debug(state->env->log_options, state->handle,
                      "Challenges for shard index %d",
                      shard_meta->index);

    for (int i = 0; i < STORJ_SHARD_CHALLENGES; i++ ) {
        memcpy(state->shard[shard_meta->index].meta->challenges_as_str[i],
               shard_meta->challenges_as_str[i],
               32);

        state->log->debug(state->env->log_options, state->handle,
                          "Challenge [%d]: %s",
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
                          "Leaf [%d]: %s", i,
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

    // Open encrypted file
    FILE *encrypted_file = fopen(state->tmp_path, "r");
    if (NULL == encrypted_file) {
        req->error_status = STORJ_FILE_INTEGRITY_ERROR;
        return;
    }

    // Encrypted shard read from file
    uint8_t *shard_data = calloc(state->shard_size, sizeof(char));
    // Hash of the shard_data
    shard_meta->hash = calloc(RIPEMD160_DIGEST_SIZE*2 + 1, sizeof(char));

    req->log->info(state->env->log_options, state->handle,
                   "Creating frame for shard index %d",
                   shard_meta->index);

    // Bytes read from file
    uint64_t read_bytes = 0;
    int loop_count = 0;

    do {
        if (loop_count == 6) {
            goto clean_variables;
        }
        // Seek to shard's location in file
        fseek(encrypted_file, shard_meta->index*state->shard_size, SEEK_SET);
        // Read shard data from file
        read_bytes = fread(shard_data, 1, state->shard_size, encrypted_file);

        if (read_bytes != shard_meta->index*state->shard_size) {
            loop_count += 1;
        }
    } while(read_bytes < state->shard_size &&
            shard_meta->index != state->total_shards - 1);

    shard_meta->size = read_bytes;

    // Calculate Shard Hash
    ripmd160sha256_as_string(shard_data, shard_meta->size, &shard_meta->hash);

    req->log->info(state->env->log_options, state->handle,
                   "Shard (%d) hash: %s", shard_meta->index,
                   shard_meta->hash);

    // Set the challenges
    for (int i = 0; i < STORJ_SHARD_CHALLENGES; i++ ) {
        uint8_t *buff = malloc(32);
        random_buffer(buff, 32);
        memcpy(shard_meta->challenges[i], buff, 32);

        // Convert the uint8_t challenges to character arrays
        hex2str(32, buff, (char *)shard_meta->challenges_as_str[i]);

        free(buff);
    }

    // Calculate the merkle tree with challenges
    for (int i = 0; i < STORJ_SHARD_CHALLENGES; i++ ) {
        int preleaf_size = 32 + shard_meta->size;
        uint8_t *preleaf = calloc(preleaf_size, sizeof(char));
        memcpy(preleaf, shard_meta->challenges[i], 32);
        memcpy(preleaf+32, shard_data, shard_meta->size);

        char *buff = calloc(RIPEMD160_DIGEST_SIZE*2 +1, sizeof(char));
        double_ripmd160sha256_as_string(preleaf, preleaf_size, &buff);
        memcpy(shard_meta->tree[i], buff, RIPEMD160_DIGEST_SIZE*2 + 1);

        free(preleaf);
        free(buff);
    }

clean_variables:
    if (encrypted_file) {
        fclose(encrypted_file);
    }

    if (shard_data) {
        free(shard_data);
    }
}

static int queue_prepare_frame(storj_upload_state_t *state, int index)
{
    uv_work_t *shard_work = shard_meta_work_new(index, state);

    state->pending_work_count += 1;
    uv_queue_work(state->env->loop, (uv_work_t*) shard_work,
                  prepare_frame, after_prepare_frame);

    state->shard[index].progress = PREPARING_FRAME;

    return 0;
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

    struct json_object *body = json_object_new_object();

    req->log->debug(state->env->log_options,
                    state->handle,
                    "JSON body: %s",
                    json_object_to_json_string(body));

    int status_code;
    struct json_object *response = fetch_json(req->http_options,
                                              req->options,
                                              "POST",
                                              "/frames",
                                              body,
                                              true,
                                              NULL,
                                              &status_code);

    req->log->debug(state->env->log_options,
                    state->handle,
                    "JSON Response: %s",
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
    strcpy(req->frame_id, frame_id_str);

cleanup:
    req->status_code = status_code;

    json_object_put(response);
    json_object_put(body);
}

static int queue_request_frame_id(storj_upload_state_t *state)
{
    uv_work_t *work = frame_work_new(NULL, state);

    state->pending_work_count += 1;
    int status = uv_queue_work(state->env->loop, (uv_work_t*) work,
                               request_frame_id, after_request_frame_id);

    state->requesting_frame = true;

    return status;
}

static void after_encrypt_file(uv_work_t *work, int status)
{
    encrypt_file_meta_t *meta = work->data;
    storj_upload_state_t *state = meta->upload_state;

    state->pending_work_count -= 1;
    state->encrypting_file = false;

    if (status == UV_ECANCELED) {
        state->encrypt_file_count = 0;

        goto clean_variables;
    }

    state->encrypt_file_count += 1;

    if (check_file(state->env, meta->tmp_path) == state->file_size) {
        state->encrypting_file = false;
        state->tmp_path = calloc(strlen(meta->tmp_path) +1, sizeof(char));
        strcpy(state->tmp_path, meta->tmp_path);

        state->log->info(state->env->log_options,
                         state->handle,
                         "Successfully completed file encryption");

    } else if (state->encrypt_file_count == 6) {
        state->error_status = STORJ_FILE_ENCRYPTION_ERROR;
    }

clean_variables:
    queue_next_work(state);
    if (meta->tmp_path) {
        free(meta->tmp_path);
    }

    free(meta);
    free(work);
}

static void encrypt_file(uv_work_t *work)
{
    encrypt_file_meta_t *req = work->data;
    storj_upload_state_t *state = req->upload_state;

    req->log->info(state->env->log_options,
                   state->handle,
                   "[%s] Encrypting file... (retry: %d)",
                   state->file_name,
                   state->encrypt_file_count);

    // Set tmp file
    if (state->env->encrypt_options->tmp_path) {
        int file_name_len = strlen(state->file_name);
        char *tmp_folder = strdup(state->env->encrypt_options->tmp_path);
        int tmp_folder_len = strlen(tmp_folder);
        if (tmp_folder[tmp_folder_len - 1] == separator()) {
            tmp_folder[tmp_folder_len - 1] = '\0';
        }

        char *tmp_path = calloc(
            tmp_folder_len + 2 + file_name_len + 6 + 1,
            sizeof(char)
        );

        sprintf(tmp_path,
            "%s%c%s%s%c",
            tmp_folder,
            separator(),
            state->file_name,
            ".crypt",
            '\0');

        req->tmp_path = tmp_path;

        free(tmp_folder);
    } else {
        req->log->error(state->env->log_options, state->handle,
                        "No valid temp path set");

        state->error_status = STORJ_FILE_WRITE_ERROR;
    }

    // Convert file key to password
    uint8_t *pass = calloc(SHA256_DIGEST_SIZE + 1, sizeof(char));
    sha256_of_str((uint8_t *)req->file_key, DETERMINISTIC_KEY_SIZE, pass);
    pass[SHA256_DIGEST_SIZE] = '\0';

    // Convert file id to salt
    uint8_t *salt = calloc(RIPEMD160_DIGEST_SIZE + 1, sizeof(char));
    ripemd160_of_str((uint8_t *)req->file_id, FILE_ID_SIZE, salt);
    salt[RIPEMD160_DIGEST_SIZE] = '\0';

    // Encrypt file
    struct aes256_ctx *ctx = calloc(sizeof(struct aes256_ctx), sizeof(char));
    aes256_set_encrypt_key(ctx, pass);
    // We only need the first 16 bytes of the salt because it's CTR mode
    char *iv = calloc(AES_BLOCK_SIZE, sizeof(char));
    memcpy(iv, salt, AES_BLOCK_SIZE);

    // Load original file and tmp file
    FILE *original_file = state->original_file;
    FILE *encrypted_file = fopen(req->tmp_path, "w+");

    char clr_txt[AES_BLOCK_SIZE * 256 + 1];
    char cphr_txt[AES_BLOCK_SIZE * 256 + 1];

    memset(clr_txt, '\0', AES_BLOCK_SIZE * 256 + 1);
    memset(cphr_txt, '\0', AES_BLOCK_SIZE * 256 + 1);

    if (original_file) {
        size_t bytes_read = 0;
        // read up to sizeof(buffer) bytes
        while ((bytes_read = fread(clr_txt, 1, AES_BLOCK_SIZE * 256,
                                   original_file)) > 0) {

            ctr_crypt(ctx, (nettle_cipher_func *)aes256_encrypt,
                      AES_BLOCK_SIZE, (uint8_t *)iv, bytes_read,
                      (uint8_t *)cphr_txt, (uint8_t *)clr_txt);

            if (!encrypted_file) {

                req->log->warn(state->env->log_options,
                               state->handle,
                               "Pointer to %s dropped.", req->tmp_path);

                goto clean_variables;
            }

            fwrite(
                cphr_txt,
                bytes_read,
                1,
                encrypted_file
            );

            memset(clr_txt, '\0', AES_BLOCK_SIZE * 256 + 1);
            memset(cphr_txt, '\0', AES_BLOCK_SIZE * 256 + 1);
        }
    }

clean_variables:

    if (encrypted_file) {
        fclose(encrypted_file);
    }

    free(ctx);
    free(iv);
    free(salt);
    free(pass);
}

static int queue_encrypt_file(storj_upload_state_t *state)
{
    uv_work_t *work = uv_work_new();

    encrypt_file_meta_t *req = malloc(sizeof(encrypt_file_meta_t));
    assert(req != NULL);

    req->file_id = state->file_id;
    req->file_key = state->file_key;
    req->file_name = state->file_name;
    req->original_file = state->original_file;
    req->file_size = state->file_size;
    req->upload_state = state;
    req->log = state->log;

    work->data = req;

    state->pending_work_count += 1;
    int status = uv_queue_work(state->env->loop, (uv_work_t*) work,
                               encrypt_file, after_encrypt_file);

    state->encrypting_file = true;

    return status;
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
    uv_queue_work(state->env->loop, (uv_work_t*) work,
                  send_exchange_report, after_send_exchange_report);
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

    // Encrypt the file
    if (!state->tmp_path && !state->encrypting_file) {
        queue_encrypt_file(state);
    }

    if (!state->frame_id && !state->requesting_frame) {
        queue_request_frame_id(state);
    }

    if (state->tmp_path) {
        for (int index = 0; index < state->total_shards; index++ ) {
            if (state->shard[index].progress == AWAITING_PREPARE_FRAME) {
                queue_prepare_frame(state, index);
            }
        }
    }

    if (state->frame_id && state->tmp_path) {
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
    struct stat st;

    if(fstat(fileno(state->original_file), &st) != 0) {
        state->error_status = STORJ_FILE_INTEGRITY_ERROR;
        return;
    }

    state->file_size = st.st_size;

    // Set Shard calculations
    state->shard_size = determine_shard_size(state, 0);
    state->total_shards = ceil((double)state->file_size / state->shard_size);

    int tracker_calloc_amount = state->total_shards * sizeof(shard_tracker_t);
    state->shard = calloc(tracker_calloc_amount, sizeof(char));

    for (int i = 0; i< state->total_shards; i++) {
        state->shard[i].pointer = farmer_pointer_new();
        state->shard[i].meta = shard_meta_new();
        state->shard[i].progress = AWAITING_PREPARE_FRAME;
        state->shard[i].index = i;
        state->shard[i].push_frame_request_count = 0;
        state->shard[i].report = storj_exchange_report_new();
        state->shard[i].work = NULL;
    }


    // Generate encryption key && Calculate deterministic file id
    char *file_id = calloc(FILE_ID_SIZE + 1, sizeof(char));
    char *file_key = calloc(DETERMINISTIC_KEY_SIZE + 1, sizeof(char));

    calculate_file_id(state->bucket_id, state->file_name, &file_id);

    file_id[FILE_ID_SIZE] = '\0';
    state->file_id = file_id;

    generate_file_key(state->env->encrypt_options->mnemonic, state->bucket_id,
                      state->file_id, &file_key);

    file_key[DETERMINISTIC_KEY_SIZE] = '\0';
    state->file_key = file_key;
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
    if (opts->file_concurrency < 1) {
        env->log->error(env->log_options,
                        handle,
                        "File Concurrency (%i) can't be less than 1",
                        opts->file_concurrency);
        return 1;
    } else if (!opts->file_concurrency) {
        opts->file_concurrency = 1;
    }

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
    state->file_concurrency = opts->file_concurrency;
    state->shard_concurrency = opts->shard_concurrency;
    state->file_name = opts->file_name;
    state->bucket_id = opts->bucket_id;
    state->original_file = opts->fd;
    state->env = env;
    state->log = env->log;
    state->progress_cb = progress_cb;
    state->finished_cb = finished_cb;
    state->handle = handle;

    // TODO: find a way to default
    state->frame_request_count = 0;
    state->encrypt_file_count = 0;
    state->add_bucket_entry_count = 0;
    state->error_status = 0;
    state->encrypting_file = false;
    state->requesting_frame = false;
    state->requesting_token = false;
    state->tmp_path = NULL;
    state->frame_id = NULL;
    state->exclude = NULL;
    state->total_shards = 0;
    state->completed_shards = 0;
    state->uploaded_bytes = 0;
    state->final_callback_called = false;
    state->received_all_pointers = false;
    state->completed_upload = false;
    state->creating_bucket_entry = false;
    state->canceled = false;
    state->pending_work_count = 0;
    state->progress_finished = false;


    uv_work_t *work = uv_work_new();
    work->data = state;

    state->pending_work_count += 1;
    return uv_queue_work(env->loop, (uv_work_t*) work,
                         prepare_upload_state, begin_work_queue);
}
