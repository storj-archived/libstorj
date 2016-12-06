#include "storj.h"
#include "http.h"

// TODO memory cleanup

// TODO move to a header file for downloader
static void queue_remaining_work(storj_download_state_t *state);

static void request_pointers(uv_work_t *work)
{
    json_request_download_t *req = work->data;

    int *status_code;
    req->response = fetch_json(req->options, req->method, req->path, req->body,
                               req->auth, &status_code);

    // TODO clear integer from pointer warning
    req->status_code = status_code;
}

static void append_pointers_to_state(storj_download_state_t *state,
                                     struct json_object *response)
{
    int length = json_object_array_length(response);

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

        for (int i = prev_total_pointers; i < total_pointers; i++) {
            struct json_object *pointer = json_object_array_get_idx(response, i);
            // TODO error if not an object

            struct json_object* token_value;
            if (!json_object_object_get_ex(pointer, "token", &token_value)) {
                // TODO error
            }
            char* token = (char *)json_object_get_string(token_value);

            struct json_object* hash_value;
            if (!json_object_object_get_ex(pointer, "hash", &hash_value)) {
                // TODO error
            }
            char* hash = (char *)json_object_get_string(hash_value);

            struct json_object* size_value;
            if (!json_object_object_get_ex(pointer, "size", &size_value)) {
                // TODO error
            }
            uint64_t size = json_object_get_int64(size_value);

            free(token_value);
            free(hash_value);
            free(size_value);
            free(pointer);

            state->pointers[i].token = token;
            state->pointers[i].hash = hash;
            state->pointers[i].size = size;
            state->pointers[i].status = 0;

            // farmer_address
            // farmer_port
        }
    }

}

static void after_request_pointers(uv_work_t *work, int status)
{
    json_request_download_t *req = work->data;

    // TODO error enum types for below

    if (status != 0)  {
        req->state->status = 1;
    } else if (req->status_code != 200) {
        req->state->status = 1;
    } else if (!json_object_is_type(req->response, json_type_array)) {
        req->state->status = 1;
    } else {
        // TODO error check
        append_pointers_to_state(req->state, req->response);
    }

    queue_remaining_work(req->state);
}

static void request_shard()
{
    // TODO
}

static void after_request_shard(uv_work_t *work, int status)
{

    json_request_download_t *req = work->data;

    // TODO check status code
    // TODO update pointer status if there was an error to not completed
    // TODO update pointer status for this shard
    // TODO update downloaded bytes
    // TODO update completed shards
    // TODO decrement resolving shards

    queue_remaining_work(req->state);
}

static int queue_request_pointers(storj_download_state_t *state)
{
    // setup work
    uv_work_t *work = malloc(sizeof(uv_work_t));
    assert(work != NULL);

    // setup work request
    json_request_download_t *req = malloc(sizeof(json_request_download_t));
    assert(req != NULL);

    // pointer request path
    char query_args[32];
    ne_snprintf(query_args, 20, "?limit=6&skip=%i", state->total_pointers);
    char *path = ne_concat("/buckets/", state->bucket_id, "/files/",
                           state->file_id, query_args, NULL);

    req->options = state->env->bridge_options;
    req->method = "GET";
    req->path = path;
    req->body = NULL;
    req->auth = true;

    // pass the download state to track progress
    req->state = state;

    // assign request to work
    work->data = req;

    return uv_queue_work(state->env->loop, (uv_work_t*) work,
                         request_pointers, after_request_pointers);

}

static int queue_request_shard()
{
    // create work data with state
    // TODO queue work to get shard, and assign shard_callback
}

static void queue_remaining_work(storj_download_state_t *state)
{
    // report any errors
    if (state->status != 0) {
        state->finished_cb(state->status);
        return;
    }

    // report progress of download
    if (state->total_bytes > 0 && state->downloaded_bytes > 0) {
        state->progress_cb(state->downloaded_bytes / state->total_bytes);
    }

    // report download complete
    if (state->pointers_completed &&
        state->completed_shards == state->total_shards) {

        state->finished_cb(0);
        return;
    }

    if (!state->pointers_completed) {
        queue_request_pointers(state);
        // TODO queue request to replace pointer if any pointers have failure
    }

    if (state->resolving_shards < STORJ_DEFAULT_DOWNLOAD_CONCURRENCY) {
        // TODO loop over pointers and queue shards requests
    }
}

int storj_bridge_resolve_file(storj_env_t *env,
                              char *bucket_id,
                              char *file_id,
                              char *dst_path,
                              storj_progress_cb progress_cb,
                              storj_finished_cb finished_cb)
{

    // setup download state
    storj_download_state_t *state = malloc(sizeof(storj_download_state_t));
    state->env = env;
    state->status = 0;
    state->dst_path = dst_path;
    state->bucket_id = bucket_id;
    state->file_id = file_id;
    state->progress_cb = progress_cb;
    state->finished_cb = finished_cb;
    state->total_pointers = 0;

    // start download
    queue_remaining_work(state);
}
