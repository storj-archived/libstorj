#include "storj.h"
#include "http.h"
#include "utils.h"
#include "crypto.h"

#define MAX_SHARD_SIZE 1073741824
#define SHARD_MULTIPLES_BACK 5

static void queue_next_work(storj_upload_state_t *state);
static int queue_request_bucket_token(storj_upload_state_t *state);
static void after_request_token(uv_work_t *work, int status);
static void request_token(uv_work_t *work);
static int queue_request_frame(storj_upload_state_t *state);
static void request_frame(uv_work_t *work);
static void after_request_frame(uv_work_t *work);

static uv_work_t *uv_work_new()
{
    uv_work_t *work = malloc(sizeof(uv_work_t));
    assert(work != NULL);
    return work;
}

static void cleanup_state(storj_upload_state_t *state)
{
    state->final_callback_called = true;
    state->finished_cb(state->error_status);

    if (state->file_id) {
        free(state->file_id);
    }

    if (state->file_key) {
        free(state->file_key);
    }

    free(state);
}

static uint64_t check_file(storj_env_t *env, char *filepath)
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

static uint64_t determine_shard_size(storj_upload_state_t *state, int accumulator)
{
    int shard_concurrency;
    uint64_t file_size;

    if (!state->file_size) {
      // TODO: Log the error
      printf("Cannot determine shard size when there is no file size.\n");
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
    int hops = ((accumulator - SHARD_MULTIPLES_BACK) < 0 ) ? 0: accumulator - SHARD_MULTIPLES_BACK;
    uint64_t byteMultiple = shard_size(accumulator);
    double check = (double) file_size / byteMultiple;

    // Determine if bytemultiple is highest bytemultiple that is still <= size
    if (check > 0 && check <= 1) {

      // Certify the number of concurrency * shard_size doesn't exceed freemem
      while (
        hops > 0 &&
        (MAX_SHARD_SIZE / shard_size(hops) <= shard_concurrency) //TODO: 1GB max memory
      ) {
        hops = hops - 1 <= 0 ? 0 : hops - 1;
      }

      return shard_size(hops);
    }

    return determine_shard_size(&state, ++accumulator);
}

static void after_request_frame(uv_work_t *work)
{
    frame_request_t *req = work->data;

    req->upload_state->frame_request_count += 1;

    // Check if we got a 201 status and token
    if (req->error_status == 0 && req->status_code == 200 && req->frame_id) {
        req->upload_state->requesting_frame = false;
        req->upload_state->frame_id = req->frame_id;
    } else if (req->upload_state->frame_request_count == 6) {
        req->upload_state->error_status = STORJ_BRIDGE_FRAME_ERROR;
    } else {
        queue_request_frame(req->upload_state);
    }

    queue_next_work(req->upload_state);

    free(req);
    free(work);
}

static void request_frame(uv_work_t *work)
{
    frame_request_t *req = work->data;

    printf("[%s] Creating file staging frame... (retry: %d)\n",
            req->upload_state->file_name,
            req->upload_state->frame_request_count);

    struct json_object *body = json_object_new_object();

    int status_code;
    struct json_object *response = fetch_json(req->options,
                                              "POST",
                                              "/frames",
                                              body,
                                              true,
                                              NULL,
                                              &status_code);

    struct json_object *frame_id;
    if (!json_object_object_get_ex(response, "id", &frame_id)) {
      req->error_status = STORJ_BRIDGE_JSON_ERROR;
    }

    if (!json_object_is_type(frame_id, json_type_string) == 1) {
      req->error_status = STORJ_BRIDGE_JSON_ERROR;
    }

    req->frame_id = (char *)json_object_get_string(frame_id);
    req->status_code = status_code;

    json_object_put(response);
    json_object_put(body);
}

static int queue_request_frame(storj_upload_state_t *state)
{
    uv_work_t *work = uv_work_new();

    frame_request_t *req = malloc(sizeof(frame_request_t));
    assert(req != NULL);

    req->options = state->env->bridge_options;
    req->upload_state = state;
    req->error_status = 0;
    work->data = req;

    int status = uv_queue_work(state->env->loop, (uv_work_t*) work,
                               request_frame, after_request_frame);

    state->requesting_frame = true;

    return status;
}

static void after_encrypt_file(uv_work_t *work)
{
    encrypt_file_meta_t *meta = work->data;

    meta->upload_state->encrypting_file = false;

    // TODO: Check if meta->tmp_path is the same size as meta->file_path
    meta->upload_state->tmp_path = meta->tmp_path;

    free(meta);
    free(work);
}

static void encrypt_file(uv_work_t *work)
{
    encrypt_file_meta_t *meta = work->data;

    // Set tmp file
    int tmp_len = strlen(meta->file_path) + strlen(".crypt");
    char *tmp_path = calloc(tmp_len + 1, sizeof(char));
    strcpy(tmp_path, meta->file_path);
    strcat(tmp_path, ".crypt");
    meta->tmp_path = tmp_path;

    // Convert file key to password
    uint8_t *pass = calloc(SHA256_DIGEST_SIZE + 1, sizeof(char));
    sha256_of_str(meta->file_key, DETERMINISTIC_KEY_SIZE, pass);
    pass[SHA256_DIGEST_SIZE] = '\0';

    // Convert file id to salt
    uint8_t *salt = calloc(RIPEMD160_DIGEST_SIZE + 1, sizeof(char));
    ripemd160_of_str(meta->file_id, FILE_ID_SIZE, salt);
    salt[RIPEMD160_DIGEST_SIZE] = '\0';

    // Encrypt file
    struct aes256_ctx *ctx = calloc(sizeof(struct aes256_ctx), sizeof(char));
    aes256_set_encrypt_key(ctx, pass);
    // We only need the first 16 bytes of the salt because it's CTR mode
    char *iv = calloc(AES_BLOCK_SIZE, sizeof(char));
    memcpy(iv, salt, AES_BLOCK_SIZE);

    // Load original file and tmp file
    FILE *original_file;
    FILE *encrypted_file;
    original_file = fopen(meta->file_path, "r");
    encrypted_file = fopen(meta->tmp_path, "w+");

    char clr_txt[512 + 1];
    char cphr_txt[512 + 1];

    memset(clr_txt, '\0', 513);
    memset(cphr_txt, '\0', 513);

    if (original_file) {
        size_t bytesRead = 0;
        // read up to sizeof(buffer) bytes
        while ((bytesRead = fread(clr_txt, 1, AES_BLOCK_SIZE * 30, original_file)) > 0) {
            ctr_crypt(ctx,
                      aes256_encrypt,
                      AES_BLOCK_SIZE,
                      iv,
                      bytesRead,
                      cphr_txt,
                      clr_txt);

            fwrite(cphr_txt, bytesRead, 1, encrypted_file);

            memset(clr_txt, '\0', 513);
            memset(cphr_txt, '\0', 513);
        }
    }

    fclose(original_file);
    fclose(encrypted_file);

    free(tmp_path);
    free(ctx);
    free(iv);
    free(salt);
    free(pass);
}

static int queue_encrypt_file(storj_upload_state_t *state)
{
    uv_work_t *work = uv_work_new();

    encrypt_file_meta_t *meta = malloc(sizeof(encrypt_file_meta_t));
    assert(meta != NULL);

    meta->file_id = state->file_id;
    meta->file_key = state->file_key;
    meta->file_name = state->file_name;
    meta->file_path = state->file_path;
    meta->file_size = state->file_size;
    meta->upload_state = state;
    work->data = meta;

    int status = uv_queue_work(state->env->loop, (uv_work_t*) work,
                               encrypt_file, after_encrypt_file);

    // TODO check status
    state->encrypting_file = true;

    return status;
}

static void after_request_token(uv_work_t *work, int status)
{
    token_request_token_t *req = work->data;

    req->upload_state->token_request_count += 1;

    // Check if we got a 201 status and token
    if (req->error_status == 0 && req->status_code == 201 && req->token) {
        req->upload_state->requesting_token = false;
        req->upload_state->token = req->token;
    } else if (req->upload_state->token_request_count == 6) {
        req->upload_state->error_status = STORJ_BRIDGE_TOKEN_ERROR;
    } else {
        queue_request_bucket_token(req->upload_state);
    }

    queue_next_work(req->upload_state);

    free(req);
    free(work);
}

static void request_token(uv_work_t *work)
{
    token_request_token_t *req = work->data;

    printf("[%s] Creating storage token... (retry: %d)\n",
            req->upload_state->file_name,
            req->upload_state->token_request_count);

    int path_len = strlen(req->bucket_id) + 17;
    char *path = calloc(path_len + 1, sizeof(char));
    sprintf(path, "%s%s%s%c", "/buckets/", req->bucket_id, "/tokens", '\0');

    struct json_object *body = json_object_new_object();
    json_object *op_string = json_object_new_string(req->bucket_op);
    json_object_object_add(body, "operation", op_string);

    int status_code;
    struct json_object *response = fetch_json(req->options,
                                              "POST",
                                              path,
                                              body,
                                              true,
                                              NULL,
                                              &status_code);

    struct json_object *token_value;
    if (!json_object_object_get_ex(response, "token", &token_value)) {
        req->error_status = STORJ_BRIDGE_JSON_ERROR;
    }

    if (!json_object_is_type(token_value, json_type_string) == 1) {
        req->error_status = STORJ_BRIDGE_JSON_ERROR;
    }

    req->token = (char *)json_object_get_string(token_value);
    req->status_code = status_code;

    free(path);
    json_object_put(response);
    json_object_put(body);
}

static int queue_request_bucket_token(storj_upload_state_t *state)
{
    uv_work_t *work = uv_work_new();

    token_request_token_t *req = malloc(sizeof(token_request_token_t));
    assert(req != NULL);

    req->options = state->env->bridge_options;
    req->bucket_id = state->bucket_id;
    req->bucket_op = BUCKET_OP[BUCKET_PUSH];
    req->upload_state = state;
    req->error_status = 0;
    work->data = req;

    int status = uv_queue_work(state->env->loop, (uv_work_t*) work,
                               request_token, after_request_token);

    // TODO check status
    state->requesting_token = true;

    return status;
}

static void queue_next_work(storj_upload_state_t *state)
{
    // report any errors
    if (state->error_status != 0) {
        return cleanup_state(state);
    }

    // report progress of upload
    if (state->file_size > 0 && state->uploaded_bytes > 0) {
        state->progress_cb(state->uploaded_bytes / state->total_bytes);
    }

    // report upload complete
    if (state->completed_shards == state->total_shards) {
        return cleanup_state(state);
    }

    // Make sure we get a PUSH token
    if (!state->token && !state->requesting_token) {
        queue_request_bucket_token(state);
    }

    if (!state->frame_id && !state->requesting_frame) {
        queue_request_frame(state);
    }

    // Encrypt the file
    if (!state->tmp_path && !state->encrypting_file) {
        queue_encrypt_file(state);
    }

}

static void begin_work_queue(uv_work_t *work)
{
    storj_upload_state_t *state = work->data;

    queue_next_work(state);

    free(work);
}

static void prepare_upload_state(uv_work_t *work)
{
    storj_upload_state_t *state = work->data;

    if (strrchr(state->file_path, separator())) {
        state->file_name = strrchr(state->file_path, separator());
        // Remove '/' from the front if exists by pushing the pointer up
        if (state->file_name[0] == separator()) state->file_name++;
    } else {
        state->file_name = state->file_path;
    }

    // Get the file size
    state->file_size = check_file(state->env, state->file_path); // Expect to be up to 10tb
    if (state->file_size < 1) {
        state->error_status = STORJ_FILE_INTEGRITY_ERROR;
        return;
    }

    // Set Shard calculations
    state->shard_size = determine_shard_size(state, 0);
    state->total_shards = ceil((double)state->file_size / state->shard_size);

    // Generate encryption key && Calculate deterministic file id
    char *file_id = calloc(FILE_ID_SIZE + 1, sizeof(char));
    char *file_key = calloc(DETERMINISTIC_KEY_SIZE + 1, sizeof(char));

    calculate_file_id(state->bucket_id, state->file_name, &file_id);

    file_id[FILE_ID_SIZE] = '\0';
    state->file_id = file_id;

    generate_file_key(state->mnemonic, state->bucket_id, state->file_id, &file_key);

    file_key[DETERMINISTIC_KEY_SIZE] = '\0';
    state->file_key = file_key;
}

int storj_bridge_store_file(storj_env_t *env,
                            storj_upload_opts_t *opts,
                            storj_progress_cb progress_cb,
                            storj_finished_upload_cb finished_cb)
{
    if (opts->file_concurrency < 1) {
        printf("\nFile Concurrency (%i) can't be less than 1", opts->file_concurrency);
        return ERROR;
    } else if (!opts->file_concurrency) {
        opts->file_concurrency = 1;
    }

    if (opts->shard_concurrency < 1) {
        printf("\nShard Concurrency (%i) can't be less than 1", opts->shard_concurrency);
        return ERROR;
    } else if (!opts->shard_concurrency) {
        opts->shard_concurrency = 3;
    }

    // setup upload state
    storj_upload_state_t *state = malloc(sizeof(storj_upload_state_t));
    state->file_concurrency = opts->file_concurrency;
    state->shard_concurrency = opts->shard_concurrency;
    state->uploaded_bytes = 0;
    state->env = env;
    state->file_path = opts->file_path;
    state->bucket_id = opts->bucket_id;
    state->progress_cb = progress_cb;
    state->finished_cb = finished_cb;
    state->total_shards = 0;
    state->completed_shards = 0;
    state->final_callback_called = false;
    state->mnemonic = opts->mnemonic;
    state->error_status = 0;
    state->writing = false;
    state->encrypting_file = false;
    state->requesting_frame = false;
    state->requesting_token = false;
    state->token = NULL;
    state->tmp_path = NULL;
    state->frame_id = NULL;

    // TODO: find a way to default at 0
    state->token_request_count = 0;
    state->frame_request_count = 0;

    uv_work_t *work = uv_work_new();
    work->data = state;

    return uv_queue_work(env->loop, (uv_work_t*) work, prepare_upload_state, begin_work_queue);
}
