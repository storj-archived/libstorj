#include "storj.h"
#include "http.h"

// TODO memory cleanup

// TODO move to a header file for downloader
static void queue_next_work(storj_download_state_t *state);

static request_token(uv_work_t *work)
{
    token_request_download_t *req = work->data;

    char *path = ne_concat("/buckets/", req->bucket_id, "/tokens", NULL);

    struct json_object *body = json_object_new_object();
    json_object *op_string = json_object_new_string(BUCKET_OP[BUCKET_PULL]);
    json_object_object_add(body, "operation", op_string);

    int *status_code;
    struct json_object *response = fetch_json(req->options,
                                              "POST",
                                              path,
                                              body,
                                              true,
                                              NULL,
                                              &status_code);

    struct json_object *token_value;
    if (!json_object_object_get_ex(response, "token", &token_value)) {
        //TODO error
    }

    if (!json_object_is_type(token_value, json_type_string) == 1) {
        // TODO error
    }

    req->token = (char *)json_object_get_string(token_value);
    req->status_code = status_code;

    free(token_value);
    free(response);
    free(body);
}

static after_request_token(uv_work_t *work, int status)
{

    token_request_download_t *req = work->data;

    req->state->requesting_token = false;

    // TODO check status

    if (req->status_code == 201) {
        req->state->token = req->token;
    } else {
        // TODO retry logic
        req->state->error_status = 1;
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

    req->options = state->env->bridge_options;
    req->bucket_id = state->bucket_id;

    req->state = state;

    work->data = req;

    int status = uv_queue_work(state->env->loop, (uv_work_t*) work,
                               request_token, after_request_token);

    // TODO check status
    state->requesting_token = true;

    return status;

}

static void request_pointers(uv_work_t *work)
{
    json_request_download_t *req = work->data;

    int *status_code;
    req->response = fetch_json(req->options, req->method, req->path, req->body,
                               req->auth, req->token, &status_code);

    // TODO clear integer from pointer warning
    req->status_code = status_code;
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

            struct json_object *pointer = json_object_array_get_idx(res, i);
            // TODO error if not an object

            struct json_object* token_value;
            if (!json_object_object_get_ex(pointer, "token", &token_value)) {
                // TODO error
            }
            char *token = (char *)json_object_get_string(token_value);

            struct json_object* hash_value;
            if (!json_object_object_get_ex(pointer, "hash", &hash_value)) {
                // TODO error
            }
            char *hash = (char *)json_object_get_string(hash_value);

            struct json_object* size_value;
            if (!json_object_object_get_ex(pointer, "size", &size_value)) {
                // TODO error
            }
            uint64_t size = json_object_get_int64(size_value);


            struct json_object* index_value;
            if (!json_object_object_get_ex(pointer, "index", &index_value)) {
                // TODO error
            }
            unsigned int index = json_object_get_int(index_value);

            struct json_object* farmer_value;
            if (!json_object_object_get_ex(pointer, "farmer", &farmer_value)) {
                // TODO error
            }
            // TODO error if not an object

            struct json_object* address_value;
            if (!json_object_object_get_ex(farmer_value, "address",
                                           &address_value)) {
                // TODO error
            }
            char *address = (char *)json_object_get_string(address_value);

            struct json_object* port_value;
            if (!json_object_object_get_ex(farmer_value, "port", &port_value)) {
                // TODO error
            }
            unsigned int port = json_object_get_int(port_value);

            free(token_value);
            free(hash_value);
            free(size_value);
            free(index_value);
            free(address_value);
            free(port_value);
            free(pointer);

            // get the relative index
            int j = i + prev_total_pointers;

            state->pointers[j].token = token;
            state->pointers[j].shard_hash = hash;
            state->pointers[j].size = size;
            // TODO enum types for pointer status:
            // -1: error states (less than zero)
            //  0: created
            //  1: being downloaded
            //  2: downloaded
            //  3: being written
            //  4: written
            state->pointers[j].status = 0;
            state->pointers[j].index = index;
            state->pointers[j].farmer_address = address;
            state->pointers[j].farmer_port = port;
        }
    }

}

static void after_request_pointers(uv_work_t *work, int status)
{
    // TODO check status

    json_request_download_t *req = work->data;

    req->state->requesting_pointers = false;

    // expired token
    req->state->token = NULL;

    // TODO error enum types for below

    if (status != 0)  {
        req->state->error_status = 1;
    } else if (req->status_code != 200) {
        req->state->error_status = 1;
    } else if (!json_object_is_type(req->response, json_type_array)) {
        req->state->error_status = 1;
    } else {
        // TODO error check
        append_pointers_to_state(req->state, req->response);
    }

    queue_next_work(req->state);

    free(work->data);
    free(work);
}

static int queue_request_pointers(storj_download_state_t *state)
{
    if (state->requesting_pointers) {
        return 0;
    }

    // TODO queue request to replace pointer if any pointers have failure

    uv_work_t *work = malloc(sizeof(uv_work_t));
    assert(work != NULL);

    json_request_download_t *req = malloc(sizeof(json_request_download_t));
    assert(req != NULL);

    char query_args[32];
    ne_snprintf(query_args, 20, "?limit=6&skip=%i", state->total_pointers);
    char *path = ne_concat("/buckets/", state->bucket_id, "/files/",
                           state->file_id, query_args, NULL);

    req->options = state->env->bridge_options;
    req->method = "GET";
    req->path = path;
    req->body = NULL;
    req->auth = true;
    req->token = state->token;

    req->state = state;

    work->data = req;

    int status = uv_queue_work(state->env->loop, (uv_work_t*) work,
                               request_pointers, after_request_pointers);

    // TODO check status
    state->requesting_pointers = true;

    return status;

}

static void request_shard(uv_work_t *work)
{
    shard_request_download_t *req = work->data;

    int *status_code;

    if (fetch_shard(req->farmer_proto, req->farmer_host, req->farmer_port,
                    req->shard_hash, req->shard_total_bytes,
                    req->shard_data, req->token, &status_code)) {

        // TODO enum error types
        req->status_code = -1;
    } else {
        req->status_code = status_code;
    }
}

static void after_request_shard(uv_work_t *work, int status)
{
    // TODO check status

    shard_request_download_t *req = work->data;

    req->state->resolving_shards -= 1;

    if (req->status_code != 200) {
        // TODO do not set state->error_status and retry the shard download
        req->state->error_status = -1;
        req->state->pointers[req->pointer_index].status = -1;
        return;
    }

    // TODO update downloaded bytes

    req->state->pointers[req->pointer_index].status = 2;
    req->state->pointers[req->pointer_index].shard_data = req->shard_data;

    queue_next_work(req->state);

    free(work->data);
    free(work);
}

static int queue_request_shards(storj_download_state_t *state)
{
    int i = 0;

    while (state->resolving_shards < STORJ_DOWNLOAD_CONCURRENCY &&
           i < state->total_pointers) {

        storj_pointer_t *pointer = &state->pointers[i];

        if (pointer->status <= 0) {
            shard_request_download_t *req = malloc(sizeof(shard_request_download_t));
            assert(req != NULL);

            req->farmer_proto = "http";
            req->farmer_host = pointer->farmer_address;
            req->farmer_port = pointer->farmer_port;
            req->shard_hash = pointer->shard_hash;
            req->shard_total_bytes = pointer->size;
            req->token = pointer->token;

            // TODO assert max bytes for shard
            req->shard_data = calloc(pointer->size, sizeof(char));

            req->pointer_index = pointer->index;

            req->state = state;

            uv_work_t *work = malloc(sizeof(uv_work_t));
            assert(work != NULL);

            work->data = req;

            state->resolving_shards += 1;
            pointer->status = 1;

            uv_queue_work(state->env->loop, (uv_work_t*) work,
                          request_shard, after_request_shard);
        }

        i++;
    }
}

static void write_shard(uv_work_t *work)
{
    shard_request_write_t *req = work->data;
    req->status_code = 0;

    if (req->shard_total_bytes != fwrite(req->shard_data,
                                         sizeof(char),
                                         req->shard_total_bytes,
                                         req->destination)) {

        req->status_code = ferror(req->destination);
    }
}

static void after_write_shard(uv_work_t *work, int status)
{
    // TODO check status

    shard_request_write_t *req = work->data;

    req->state->writing = false;

    if (req->status_code) {
        // write failure
        req->state->error_status = req->status_code;
    } else {
        // write success
        req->state->pointers[req->pointer_index].status = 4;

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

        if (pointer->status < 2) {
            break;
        }

        if (pointer->status == 2) {
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
            pointer->status = 3;

            uv_queue_work(state->env->loop, (uv_work_t*) work,
                          write_shard, after_write_shard);
            break;
        }

        i++;

    }
}

static void queue_next_work(storj_download_state_t *state)
{
    // report any errors
    if (state->error_status != 0) {
        // TODO make sure that finished_cb is not called multiple times
        state->finished_cb(state->error_status, state->destination);

        free(state->pointers);
        free(state);
        return;
    }

    queue_write_next_shard(state);

    // report progress of download
    if (state->total_bytes > 0 && state->downloaded_bytes > 0) {
        state->progress_cb(state->downloaded_bytes / state->total_bytes);
    }

    // report download complete
    if (state->pointers_completed &&
        state->completed_shards == state->total_shards) {

        state->finished_cb(0, state->destination);

        free(state->pointers);
        free(state);
        return;
    }

    if (!state->token && !state->pointers_completed) {
        queue_request_bucket_token(state);
    }

    if (state->token && !state->pointers_completed) {
        queue_request_pointers(state);
    }

    queue_request_shards(state);
}

int storj_bridge_resolve_file(storj_env_t *env,
                              char *bucket_id,
                              char *file_id,
                              FILE *destination,
                              storj_progress_cb progress_cb,
                              storj_finished_cb finished_cb)
{

    // setup download state
    storj_download_state_t *state = malloc(sizeof(storj_download_state_t));
    state->total_bytes = 0;
    state->downloaded_bytes = 0;
    state->env = env;
    state->file_id = file_id;
    state->bucket_id = bucket_id;
    state->destination = destination;
    state->progress_cb = progress_cb;
    state->finished_cb = finished_cb;
    state->total_shards = 0;
    state->completed_shards = 0;
    state->resolving_shards = 0;
    state->total_pointers = 0;
    state->pointers_completed = false;
    state->requesting_pointers = false;
    state->error_status = 0;
    state->writing = false;
    state->token = NULL;
    state->requesting_token = false;

    // start download
    queue_next_work(state);
}
