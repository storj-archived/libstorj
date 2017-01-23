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
    if (index != NULL) {
        req->shard_index = *index;
        req->farmer_pointer = calloc(sizeof(farmer_pointer_t), sizeof(char));
    }

    work->data = req;

    return work;
}

static uv_work_t *shard_state_new(int index, storj_upload_state_t *state)
{
    uv_work_t *work = uv_work_new();
    frame_builder_t *frame_builder = malloc(sizeof(frame_builder_t));
    frame_builder->shard_meta = malloc(sizeof(shard_meta_t));
    frame_builder->upload_state = state;

    assert(frame_builder->shard_meta != NULL);

    frame_builder->shard_meta->index = index;
    frame_builder->error_status = 0;

    work->data = frame_builder;

    return work;
}

static void shard_state_cleanup(shard_meta_t *shard_meta)
{
    if (shard_meta->hash != NULL) {
        free(shard_meta->hash);
    }

    free(shard_meta);
}

static void pointer_cleanup(farmer_pointer_t *farmer_pointer)
{
    if (farmer_pointer->hash != NULL) {
        free(farmer_pointer->hash);
    }

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
    state->final_callback_called = true;
    state->finished_cb(state->error_status, state->handle);

    if (state->file_id) {
        free(state->file_id);
    }

    if (state->file_key) {
        free(state->file_key);
    }

    if (state->token) {
        free(state->token);
    }

    if (state->frame_id) {
        free(state->frame_id);
    }

    if (state->shard_meta) {
        for (int i = 0; i < state->total_shards; i++ ) {
            printf("Cleaning up shard %d\n", i);
            shard_state_cleanup(&state->shard_meta[i]);
        }

        free(state->shard_meta);
    }

    if (state->farmer_pointers) {
        for (int i = 0; i < state->total_shards; i++ ) {
            printf("Cleaning up pointers %d\n", i);
            pointer_cleanup(&state->farmer_pointers[i]);
        }

        free(state->farmer_pointers);
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

    return determine_shard_size(state, ++accumulator);
}

static void after_push_frame(uv_work_t *work, int status)
{
    frame_request_t *req = work->data;
    storj_upload_state_t *state = req->upload_state;
    farmer_pointer_t *pointer = req->farmer_pointer;

    // Check if we got a 201 status and token
    if (req->error_status == 0 && req->status_code == 201 && pointer->token) {

        // Add hash to farmer_pointers
        state->farmer_pointers[pointer->shard_index].hash = calloc(strlen(pointer->hash) + 1, sizeof(char));
        memcpy(state->farmer_pointers[pointer->shard_index].hash, pointer->hash, strlen(pointer->hash));

        // Add token to farmer_pointers
        state->farmer_pointers[pointer->shard_index].token = calloc(strlen(pointer->token) + 1, sizeof(char));
        memcpy(state->farmer_pointers[pointer->shard_index].token, pointer->token, strlen(pointer->token));

        // Add shard_index to farmer_pointers
        state->farmer_pointers[pointer->shard_index].shard_index = pointer->shard_index;

        // Add farmer_user_agent to farmer_pointers
        state->farmer_pointers[pointer->shard_index].farmer_user_agent = calloc(strlen(pointer->farmer_user_agent) + 1, sizeof(char));
        memcpy(state->farmer_pointers[pointer->shard_index].farmer_user_agent, pointer->farmer_user_agent, strlen(pointer->farmer_user_agent));

        // Add farmer_address to farmer_pointers
        state->farmer_pointers[pointer->shard_index].farmer_address = calloc(strlen(pointer->farmer_address) + 1, sizeof(char));
        memcpy(state->farmer_pointers[pointer->shard_index].farmer_address, pointer->farmer_address, strlen(pointer->farmer_address));

        // Add farmer_port to farmer_pointers
        state->farmer_pointers[pointer->shard_index].farmer_port = calloc(strlen(pointer->farmer_port) + 1, sizeof(char));
        memcpy(state->farmer_pointers[pointer->shard_index].farmer_port, pointer->farmer_port, strlen(pointer->farmer_port));

        // Add farmer_protocol to farmer_pointers
        state->farmer_pointers[pointer->shard_index].farmer_protocol = calloc(strlen(pointer->farmer_protocol) + 1, sizeof(char));
        memcpy(state->farmer_pointers[pointer->shard_index].farmer_protocol, pointer->farmer_protocol, strlen(pointer->farmer_protocol));

        // Add farmer_node_id to farmer_pointers
        state->farmer_pointers[pointer->shard_index].farmer_node_id = calloc(strlen(pointer->farmer_node_id) + 1, sizeof(char));
        memcpy(state->farmer_pointers[pointer->shard_index].farmer_node_id, pointer->farmer_node_id, strlen(pointer->farmer_node_id));

        // Add farmer_last_seen to farmer_pointers
        state->farmer_pointers[pointer->shard_index].farmer_last_seen = calloc(strlen(pointer->farmer_last_seen) + 1, sizeof(char));
        memcpy(state->farmer_pointers[pointer->shard_index].farmer_last_seen, pointer->farmer_last_seen, strlen(pointer->farmer_last_seen));
    }

    queue_next_work(req->upload_state);

    pointer_cleanup(req->farmer_pointer);
    free(req);
    free(work);
}

static void push_frame(uv_work_t *work)
{
    frame_request_t *req = work->data;
    storj_upload_state_t *state = req->upload_state;
    shard_meta_t *shard_meta = &state->shard_meta[req->shard_index];
    printf("Pushing frame for shard index %d\n", req->shard_index);

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
    for (int i = 0; i < CHALLENGES; i++ ) {
        json_object_array_add(challenges, json_object_new_string(shard_meta->challenges_as_str[i]));
    }
    json_object_object_add(body, "challenges", challenges);

    // Add Tree
    json_object *tree = json_object_new_array();
    for (int i = 0; i < CHALLENGES; i++ ) {
        json_object_array_add(tree, json_object_new_string(shard_meta->tree[i]));
    }
    json_object_object_add(body, "tree", tree);

    // Add exclude
    json_object *exclude = json_object_new_array();
    json_object_object_add(body, "exclude", exclude);

    char resource[strlen(state->frame_id) + 9];
    memset(resource, '\0', strlen(state->frame_id) + 9);
    strcpy(resource, "/frames/");
    strcat(resource, state->frame_id);

    int status_code;
    struct json_object *response = fetch_json(req->http_options,
                                              req->options,
                                              "PUT",
                                              resource,
                                              body,
                                              true,
                                              NULL,
                                              &status_code);

    struct json_object *obj_token;
    if (!json_object_object_get_ex(response, "token", &obj_token)) {
        req->error_status = STORJ_BRIDGE_JSON_ERROR;
        goto clean_variables;
    }

    struct json_object *obj_hash;
    if (!json_object_object_get_ex(response, "hash", &obj_hash)) {
        req->error_status = STORJ_BRIDGE_JSON_ERROR;
        goto clean_variables;
    }

    struct json_object *obj_farmer;
    if (!json_object_object_get_ex(response, "farmer", &obj_farmer)) {
        req->error_status = STORJ_BRIDGE_JSON_ERROR;
        goto clean_variables;
    }

    struct json_object *obj_farmer_address;
    if (!json_object_object_get_ex(obj_farmer, "address", &obj_farmer_address)) {
        req->error_status = STORJ_BRIDGE_JSON_ERROR;
        goto clean_variables;
    }

    struct json_object *obj_farmer_port;
    if (!json_object_object_get_ex(obj_farmer, "port", &obj_farmer_port)) {
        req->error_status = STORJ_BRIDGE_JSON_ERROR;
        goto clean_variables;
    }

    struct json_object *obj_farmer_user_agent;
    if (!json_object_object_get_ex(obj_farmer, "userAgent", &obj_farmer_user_agent)) {
        req->error_status = STORJ_BRIDGE_JSON_ERROR;
        goto clean_variables;
    }

    struct json_object *obj_farmer_protocol;
    if (!json_object_object_get_ex(obj_farmer, "protocol", &obj_farmer_protocol)) {
        req->error_status = STORJ_BRIDGE_JSON_ERROR;
        goto clean_variables;
    }

    struct json_object *obj_farmer_node_id;
    if (!json_object_object_get_ex(obj_farmer, "nodeID", &obj_farmer_node_id)) {
        req->error_status = STORJ_BRIDGE_JSON_ERROR;
        goto clean_variables;
    }

    struct json_object *obj_farmer_last_seen;
    if (!json_object_object_get_ex(obj_farmer, "lastSeen", &obj_farmer_last_seen)) {
        req->error_status = STORJ_BRIDGE_JSON_ERROR;
        goto clean_variables;
    }

    if (!json_object_is_type(obj_token, json_type_string) == 1) {
        req->error_status = STORJ_BRIDGE_JSON_ERROR;
        goto clean_variables;
    }

    char *token = (char *)json_object_get_string(obj_token);

    req->farmer_pointer->token = calloc(strlen(token) + 1, sizeof(char));
    memcpy(req->farmer_pointer->token, token, strlen(token));

    char *hash = (char *)json_object_get_string(obj_hash);
    req->farmer_pointer->hash = calloc(strlen(hash) + 1, sizeof(char));
    memcpy(req->farmer_pointer->hash, hash, strlen(hash));

    req->farmer_pointer->shard_index = shard_meta->index;

    char *farmer_user_agent = (char *)json_object_get_string(obj_farmer_user_agent);
    req->farmer_pointer->farmer_user_agent = calloc(strlen(farmer_user_agent) + 1, sizeof(char));
    memcpy(req->farmer_pointer->farmer_user_agent, farmer_user_agent, strlen(farmer_user_agent));

    char *farmer_protocol = (char *)json_object_get_string(obj_farmer_protocol);
    req->farmer_pointer->farmer_protocol = calloc(strlen(farmer_protocol) + 1, sizeof(char));
    memcpy(req->farmer_pointer->farmer_protocol, farmer_protocol, strlen(farmer_protocol));

    char *farmer_address = (char *)json_object_get_string(obj_farmer_address);
    req->farmer_pointer->farmer_address = calloc(strlen(farmer_address) + 1, sizeof(char));
    memcpy(req->farmer_pointer->farmer_address, farmer_address, strlen(farmer_address));

    char *farmer_port = (char *)json_object_get_string(obj_farmer_port);
    req->farmer_pointer->farmer_port = calloc(strlen(hash) + 1, sizeof(char));
    memcpy(req->farmer_pointer->farmer_port, farmer_port, strlen(farmer_port));

    char *farmer_node_id = (char *)json_object_get_string(obj_farmer_node_id);
    req->farmer_pointer->farmer_node_id = calloc(strlen(farmer_node_id) + 1, sizeof(char));
    memcpy(req->farmer_pointer->farmer_node_id, farmer_node_id, strlen(farmer_node_id));

    char *farmer_last_seen = (char *)json_object_get_string(obj_farmer_last_seen);
    req->farmer_pointer->farmer_last_seen = calloc(strlen(farmer_last_seen) + 1, sizeof(char));
    memcpy(req->farmer_pointer->farmer_last_seen, farmer_last_seen, strlen(farmer_last_seen));

    req->status_code = status_code;

clean_variables:
    json_object_put(response);
    json_object_put(body);
}

static int queue_push_frame(storj_upload_state_t *state, int index)
{
    uv_work_t *shard_work[state->total_shards];

    shard_work[index] = frame_work_new(&index, state);
    uv_queue_work(state->env->loop, (uv_work_t*) shard_work[index], push_frame, after_push_frame);

    state->pushing_frame = true;

    return 0;
}

static void after_create_frame(uv_work_t *work, int status)
{
    frame_builder_t *frame_builder = work->data;
    shard_meta_t *shard_meta = frame_builder->shard_meta;
    storj_upload_state_t *state = frame_builder->upload_state;

    state->shards_hashed += 1;

    if (state->shards_hashed == state->total_shards) {
        state->hashing_shards = false;
        state->completed_shard_hash = true;
    }

    // set the shard_meta to a struct array in the state for later use.

    // Add Hash
    state->shard_meta[shard_meta->index].hash = calloc(RIPEMD160_DIGEST_SIZE*2 + 1, sizeof(char));
    memcpy(state->shard_meta[shard_meta->index].hash, shard_meta->hash, RIPEMD160_DIGEST_SIZE*2);

    // Add challenges_as_str
    for (int i = 0; i < CHALLENGES; i++ ) {
        memcpy(state->shard_meta[shard_meta->index].challenges_as_str[i], shard_meta->challenges_as_str[i], 32);
    }

    // Add Merkle Tree leaves.
    for (int i = 0; i < CHALLENGES; i++ ) {
        memcpy(state->shard_meta[shard_meta->index].tree[i], shard_meta->tree[i], 32);
    }

    // Add index
    state->shard_meta[shard_meta->index].index = shard_meta->index;

    // Add size
    state->shard_meta[shard_meta->index].size = shard_meta->size;

    queue_next_work(state);

    shard_state_cleanup(shard_meta);
    free(frame_builder);
    free(work);
}

static void create_frame(uv_work_t *work)
{
    frame_builder_t *frame_builder = work->data;
    shard_meta_t *shard_meta = frame_builder->shard_meta;
    storj_upload_state_t *state = frame_builder->upload_state;

    // Open encrypted file
    FILE *encrypted_file = fopen(state->tmp_path, "r");
    if (NULL == encrypted_file) {
        frame_builder->error_status = STORJ_FILE_INTEGRITY_ERROR;
        return;
    }

    // Encrypted shard read from file
    uint8_t *shard_data = calloc(state->shard_size, sizeof(char));
    // Hash of the shard_data
    shard_meta->hash = calloc(RIPEMD160_DIGEST_SIZE*2 + 1, sizeof(char));
    // Bytes read from file
    uint64_t read_bytes;

    printf("Creating frame for shard index %d\n", shard_meta->index);

    read_bytes = 0;

    // TODO: make sure we only loop a certain number of times
    do {
        // Seek to shard's location in file
        fseek(encrypted_file, shard_meta->index*state->shard_size, SEEK_SET);
        // Read shard data from file
        read_bytes = fread(shard_data, 1, state->shard_size, encrypted_file);
    } while(read_bytes < state->shard_size && shard_meta->index != state->total_shards - 1);

    shard_meta->size = read_bytes;

    // Calculate Shard Hash
    ripmd160sha256_as_string(shard_data, shard_meta->size, &shard_meta->hash);

    printf("Shard (%d) hash: %s\n", shard_meta->index, shard_meta->hash);

    // Set the challenges
    for (int i = 0; i < CHALLENGES; i++ ) {
        uint8_t *buff = malloc(32);
        random_buffer(buff, 32);
        memcpy(shard_meta->challenges[i], buff, 32);

        // Convert the uint8_t challenges to character arrays
        hex2str(32, buff, (char *)shard_meta->challenges_as_str[i]);

        free(buff);
    }

    // Calculate the merkle tree with challenges
    for (int i = 0; i < CHALLENGES; i++ ) {
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

    fclose(encrypted_file);
    free(shard_data);
}

static int queue_create_frame(storj_upload_state_t *state, int index)
{
    uv_work_t *shard_work[state->total_shards];

    shard_work[index] = shard_state_new(index, state);
    uv_queue_work(state->env->loop, (uv_work_t*) shard_work[index], create_frame, after_create_frame);

    state->hashing_shards = true;

    return 0;
}

static void after_request_frame(uv_work_t *work, int status)
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
    struct json_object *response = fetch_json(req->http_options,
                                              req->options,
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

    char *frame_id_str = (char *)json_object_get_string(frame_id);
    req->frame_id = calloc(strlen(frame_id_str) + 1, sizeof(char));
    strcpy(req->frame_id, frame_id_str);
    req->status_code = status_code;

    json_object_put(response);
    json_object_put(body);
}

static int queue_request_frame(storj_upload_state_t *state)
{
    uv_work_t *work = frame_work_new(NULL, state);

    int status = uv_queue_work(state->env->loop, (uv_work_t*) work,
                               request_frame, after_request_frame);

    state->requesting_frame = true;

    return status;
}

static void after_encrypt_file(uv_work_t *work, int status)
{
    encrypt_file_meta_t *meta = work->data;
    storj_upload_state_t *state = meta->upload_state;

    state->encrypt_file_count += 1;

    if (check_file(state->env, meta->tmp_path) == state->file_size) {
        state->encrypting_file = false;
        state->completed_encryption = true;
        state->tmp_path = meta->tmp_path;
    } else if (state->encrypt_file_count == 6) {
        state->error_status = STORJ_FILE_ENCRYPTION_ERROR;
    } else {
        queue_encrypt_file(state);
    }

    queue_next_work(state);

    free(meta);
    free(work);
}

static void encrypt_file(uv_work_t *work)
{
    encrypt_file_meta_t *meta = work->data;

    printf("[%s] Encrypting file... (retry: %d)\n",
            meta->upload_state->file_name,
            meta->upload_state->encrypt_file_count);

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
                      (nettle_cipher_func *)aes256_encrypt,
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
    request_token_t *req = work->data;

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
    request_token_t *req = work->data;

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
    struct json_object *response = fetch_json(req->http_options,
                                              req->options,
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

    char *token_value_str = (char *)json_object_get_string(token_value);
    req->token = calloc(strlen(token_value_str) + 1, sizeof(char));
    strcpy(req->token, token_value_str);
    req->status_code = status_code;

    free(path);
    json_object_put(response);
    json_object_put(body);
}

static int queue_request_bucket_token(storj_upload_state_t *state)
{
    uv_work_t *work = uv_work_new();

    request_token_t *req = malloc(sizeof(request_token_t));
    assert(req != NULL);

    req->http_options = state->env->http_options;
    req->options = state->env->bridge_options;
    req->bucket_id = state->bucket_id;
    req->bucket_op = (char *)BUCKET_OP[BUCKET_PUSH];
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
        state->progress_cb(state->uploaded_bytes / state->total_bytes,
                           state->uploaded_bytes,
                           state->total_bytes,
                           state->handle);
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
    } else if (state->frame_id && state->completed_encryption && !state->hashing_shards && !state->completed_shard_hash) {
        for (int index = 0; index < state->total_shards; index++ ) {
            queue_create_frame(state, index);
        }
    } else if (state->completed_shard_hash && !state->pushing_frame){
        for (int index = 0; index < state->total_shards; index++ ) {
            queue_push_frame(state, index);
        }
        // return cleanup_state(state);
    }

    // Encrypt the file
    if (!state->tmp_path && !state->encrypting_file) {
        queue_encrypt_file(state);
    }

}

static void begin_work_queue(uv_work_t *work, int status)
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
    state->shard_meta = calloc(state->total_shards * sizeof(shard_meta_t), sizeof(char));
    state->farmer_pointers = calloc(state->total_shards * sizeof(farmer_pointer_t), sizeof(char));

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
                            void *handle,
                            storj_progress_cb progress_cb,
                            storj_finished_upload_cb finished_cb)
{
    if (opts->file_concurrency < 1) {
        printf("\nFile Concurrency (%i) can't be less than 1", opts->file_concurrency);
        return 1;
    } else if (!opts->file_concurrency) {
        opts->file_concurrency = 1;
    }

    if (opts->shard_concurrency < 1) {
        printf("\nShard Concurrency (%i) can't be less than 1", opts->shard_concurrency);
        return 1;
    } else if (!opts->shard_concurrency) {
        opts->shard_concurrency = 3;
    }

    // setup upload state
    storj_upload_state_t *state = malloc(sizeof(storj_upload_state_t));
    state->file_concurrency = opts->file_concurrency;
    state->shard_concurrency = opts->shard_concurrency;
    state->env = env;
    state->file_path = opts->file_path;
    state->bucket_id = opts->bucket_id;
    state->progress_cb = progress_cb;
    state->finished_cb = finished_cb;
    state->mnemonic = opts->mnemonic;

    // TODO: find a way to default
    state->token_request_count = 0;
    state->frame_request_count = 0;
    state->encrypt_file_count = 0;
    state->shards_hashed = 0;
    state->completed_encryption = false;
    state->completed_shard_hash = false;
    state->error_status = 0;
    state->writing = false;
    state->encrypting_file = false;
    state->requesting_frame = false;
    state->requesting_token = false;
    state->pushing_frame = false;
    state->hashing_shards = false;
    state->token = NULL;
    state->tmp_path = NULL;
    state->frame_id = NULL;
    state->total_shards = 0;
    state->completed_shards = 0;
    state->uploaded_bytes = 0;
    state->final_callback_called = false;

    state->handle = handle;

    uv_work_t *work = uv_work_new();
    work->data = state;

    return uv_queue_work(env->loop, (uv_work_t*) work, prepare_upload_state, begin_work_queue);
}
