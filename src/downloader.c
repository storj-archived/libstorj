#include "storj.h"
#include "http.h"
#include "utils.h"
#include "crypto.h"

#define STORJ_DOWNLOAD_CONCURRENCY 4

// TODO memory cleanup

// TODO move to a header file for downloader
static void queue_next_work(storj_download_state_t *state);

static void request_token(uv_work_t *work)
{
    token_request_token_t *req = work->data;

    char *path = ne_concat("/buckets/", req->bucket_id, "/tokens", NULL);

    struct json_object *body = json_object_new_object();
    json_object *op_string = json_object_new_string(req->bucket_op);
    json_object_object_add(body, "operation", op_string);

    int status_code = 0;
    struct json_object *response = fetch_json(req->options,
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

    token_request_token_t *req = work->data;

    req->download_state->requesting_token = false;

    if (status != 0) {
        req->download_state->error_status = STORJ_BRIDGE_TOKEN_ERROR;
    } else if (req->status_code == 201) {
        req->download_state->token = req->token;
    } else if (req->error_status){
        req->download_state->error_status = req->error_status;
    } else {
        // TODO retry logic
        req->download_state->error_status = STORJ_BRIDGE_TOKEN_ERROR;
    }

    queue_next_work(req->download_state);

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

    token_request_token_t *req = malloc(sizeof(token_request_token_t));
    assert(req != NULL);

    req->options = state->env->bridge_options;
    req->bucket_id = state->bucket_id;
    req->bucket_op = (char *)BUCKET_OP[BUCKET_PULL];
    req->download_state = state;
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

    int status_code;
    req->response = fetch_json(req->options, req->method, req->path, req->body,
                               req->auth, req->token, &status_code);

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
            if (!json_object_is_type(pointer, json_type_object)) {
                state->error_status = STORJ_BRIDGE_JSON_ERROR;
                return;
            }

            struct json_object* token_value;
            if (!json_object_object_get_ex(pointer, "token", &token_value)) {
                state->error_status = STORJ_BRIDGE_JSON_ERROR;
                return;
            }
            char *token = (char *)json_object_get_string(token_value);

            struct json_object* hash_value;
            if (!json_object_object_get_ex(pointer, "hash", &hash_value)) {
                state->error_status = STORJ_BRIDGE_JSON_ERROR;
                return;
            }
            char *hash = (char *)json_object_get_string(hash_value);

            struct json_object* size_value;
            if (!json_object_object_get_ex(pointer, "size", &size_value)) {
                state->error_status = STORJ_BRIDGE_JSON_ERROR;
                return;
            }
            uint64_t size = json_object_get_int64(size_value);


            struct json_object* index_value;
            if (!json_object_object_get_ex(pointer, "index", &index_value)) {
                state->error_status = STORJ_BRIDGE_JSON_ERROR;
                return;
            }
            uint32_t index = json_object_get_int(index_value);

            struct json_object* farmer_value;
            if (!json_object_object_get_ex(pointer, "farmer", &farmer_value)) {
                state->error_status = STORJ_BRIDGE_JSON_ERROR;
                return;
            }
            if (!json_object_is_type(farmer_value, json_type_object)) {
                state->error_status = STORJ_BRIDGE_JSON_ERROR;
                return;
            }

            struct json_object* address_value;
            if (!json_object_object_get_ex(farmer_value, "address",
                                           &address_value)) {
                state->error_status = STORJ_BRIDGE_JSON_ERROR;
                return;
            }
            char *address = (char *)json_object_get_string(address_value);

            struct json_object* port_value;
            if (!json_object_object_get_ex(farmer_value, "port", &port_value)) {
                state->error_status = STORJ_BRIDGE_JSON_ERROR;
                return;
            }
            uint32_t port = json_object_get_int(port_value);

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
            state->pointers[j].status = POINTER_CREATED;
            state->pointers[j].index = index;
            state->pointers[j].farmer_address = address;
            state->pointers[j].farmer_port = port;

            if (!state->shard_size) {
                // TODO make sure all except last shard is the same size
                state->shard_size = size;
            };

        }
    }

}

static void after_request_pointers(uv_work_t *work, int status)
{
    json_request_download_t *req = work->data;

    req->state->requesting_pointers = false;

    // expired token
    req->state->token = NULL;

    if (status != 0)  {
        req->state->error_status = STORJ_BRIDGE_TOKEN_ERROR;
    } else if (req->status_code != 200) {
        req->state->error_status = STORJ_BRIDGE_TOKEN_ERROR;
    } else if (!json_object_is_type(req->response, json_type_array)) {
        req->state->error_status = STORJ_BRIDGE_JSON_ERROR;
    } else {
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

    int status_code;

    if (fetch_shard(req->farmer_proto, req->farmer_host, req->farmer_port,
                    req->shard_hash, req->shard_total_bytes,
                    req->shard_data, req->token, &status_code)) {

        // TODO enum error types
        req->status_code = -1;
    } else {

        // Decrypt the shard
        if (req->decrypt_key && req->decrypt_ctr) {
            struct aes256_ctx *ctx = malloc(sizeof(struct aes256_ctx));
            aes256_set_encrypt_key(ctx, req->decrypt_key);
            ctr_crypt(ctx, (nettle_cipher_func *)aes256_encrypt,
                      AES_BLOCK_SIZE, req->decrypt_ctr,
                      req->shard_total_bytes, req->shard_data, req->shard_data);
        }

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
        req->state->error_status = STORJ_FARMER_REQUEST_ERROR;
        req->state->pointers[req->pointer_index].status = POINTER_ERROR;
        return;
    }

    // TODO update downloaded bytes

    req->state->pointers[req->pointer_index].status = POINTER_DOWNLOADED;
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

        if (pointer->status <= POINTER_CREATED) {
            shard_request_download_t *req = malloc(sizeof(shard_request_download_t));
            assert(req != NULL);

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

            uv_work_t *work = malloc(sizeof(uv_work_t));
            assert(work != NULL);

            work->data = req;

            state->resolving_shards += 1;
            pointer->status = POINTER_BEING_DOWNLOADED;

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
                              storj_finished_download_cb finished_cb)
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
    state->error_status = STORJ_TRANSFER_OK;
    state->writing = false;
    state->token = NULL;
    state->requesting_token = false;
    state->shard_size = 0;

    // determine the decryption key
    if (!env->encrypt_options || !env->encrypt_options->mnemonic) {
        state->decrypt_key = NULL;
        state->decrypt_ctr = NULL;
    } else {
        char *file_key = calloc(DETERMINISTIC_KEY_SIZE + 1, sizeof(char));
        generate_file_key(env->encrypt_options->mnemonic, bucket_id,
                          file_id, &file_key);
        file_key[DETERMINISTIC_KEY_SIZE] = '\0';

        uint8_t *file_key_as_hex = calloc(DETERMINISTIC_KEY_HEX_SIZE + 1,
                                          sizeof(uint8_t));
        str2hex(DETERMINISTIC_KEY_HEX_SIZE, file_key, file_key_as_hex);

        uint8_t *decrypt_key = calloc(SHA256_DIGEST_SIZE + 1, sizeof(uint8_t));
        sha256_of_str(file_key_as_hex, DETERMINISTIC_KEY_HEX_SIZE, decrypt_key);
        decrypt_key[SHA256_DIGEST_SIZE] = '\0';

        state->decrypt_key = decrypt_key;

        uint8_t *file_id_as_hex = calloc(FILE_ID_HEX_SIZE + 1, sizeof(uint8_t));
        str2hex(FILE_ID_HEX_SIZE, file_id, file_id_as_hex);

        uint8_t *file_id_hash = calloc(RIPEMD160_DIGEST_SIZE + 1, sizeof(uint8_t));
        ripemd160_of_str(file_id_as_hex, FILE_ID_HEX_SIZE, file_id_hash);
        file_id_hash[RIPEMD160_DIGEST_SIZE] = '\0';

        uint8_t *decrypt_ctr = calloc(AES_BLOCK_SIZE, sizeof(uint8_t));
        memcpy(decrypt_ctr, file_id_hash, AES_BLOCK_SIZE);

        state->decrypt_ctr = decrypt_ctr;
    };

    // start download
    queue_next_work(state);
}
