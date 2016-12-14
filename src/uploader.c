#include "storj.h"

// static uv_work_t *uv_work_new()
// {
//     uv_work_t *work = malloc(sizeof(uv_work_t));
//     assert(work != NULL);
//     return work;
// }
//
// static request_token(uv_work_t *work)
// {
//     storj_upload_work_data_t *work_data = work->data;
//     storj_upload_opts_t *opts = &work_data->opts;
//
//     char *path = ne_concat("/buckets/", opts->bucket_id, "/tokens", NULL);
//
//     struct json_object *body = json_object_new_object();
//     json_object *op_string = json_object_new_string(BUCKET_OP[BUCKET_PUSH]);
//     json_object_object_add(body, "operation", op_string);
//
//     int *status_code;
//     struct json_object *response = fetch_json(env->bridge_options,
//                                               "POST",
//                                               path,
//                                               body,
//                                               true,
//                                               NULL,
//                                               &status_code);
//
//     struct json_object *token_value;
//     if (!json_object_object_get_ex(response, "token", &token_value)) {
//         //TODO error
//     }
//
//     if (!json_object_is_type(token_value, json_type_string) == 1) {
//         // TODO error
//     }
//
//     opts->token = (char *)json_object_get_string(token_value);
//     opts->token_status_code = status_code;
//
//     // Free the json
//     // json_object_put(response);
//     // json_object_put(token_value);
//     // json_object_put(body);
//     // json_object_put(op_string);
// }
//
// void uploader_callback(uv_work_t *work, int status)
// {
//     storj_upload_work_data_t *work_data = work->data;
//     storj_upload_opts_t *opts = &work_data->opts;
//
//     printf("Token status Code: %d\n", opts->token_status_code);
//     printf("Token: %s\n", opts->token);
// }
//
// static void begin_upload_work(uv_work_t *work)
// {
//     int err;
//
//     storj_upload_work_data_t *work_data = work->data;
//     storj_env_t *env = &work_data->env;
//     storj_upload_opts_t *opts = &work_data->opts;
//
//
//
//
//     opts->shard_size = determine_shard_size(opts, 0);
//     opts->shard_num = ceil((double)opts->file_size / opts->shard_size);
//
//     // Calculate deterministic file id
//     char *file_id_buff = malloc(FILE_ID_SIZE + 1);
//     calculate_file_id(opts->bucket_id, opts->file_name, &file_id_buff);
//     opts->file_id = file_id_buff;
//     opts->file_id[FILE_ID_SIZE] = '\0';
//
//     // Generate encryption key
//     char *file_id = calloc(FILE_ID_SIZE + 1, sizeof(char));
//     char *file_key = calloc(DETERMINISTIC_KEY_SIZE + 1, sizeof(char));
//
//     calculate_file_id(opts->bucket_id, opts->file_name, &file_id);
//     file_id[FILE_ID_SIZE] = '\0';
//     opts->file_id = file_id;
//     generate_file_key(opts->mnemonic, opts->bucket_id, file_id, &file_key);
//     file_key[DETERMINISTIC_KEY_SIZE] = '\0';
//
//     // Set tmp file
//     int tmp_len = strlen(opts->file_path) + strlen(".crypt");
//     char tmp_path[tmp_len];
//     memset(tmp_path, '\0', tmp_len);
//     strcpy(tmp_path, opts->file_path);
//     strcat(tmp_path, ".crypt");
//     opts->tmp_path = tmp_path;
//
//     // Encrypt file
//     struct aes256_ctx ctx;
//     uint8_t *file_key_as_hex = calloc(DETERMINISTIC_KEY_SIZE/2 + 1, sizeof(char));
//     str2hex(DETERMINISTIC_KEY_SIZE/2, file_key, file_key_as_hex);
//     aes256_set_decrypt_key(&ctx, file_key_as_hex);
//
//     request_token(work_data);
//
//     // Load original file and tmp file
//     // FILE *original_file;
//     // FILE *encrypted_file;
//     // original_file = fopen(opts->file_path, "r");
//     // encrypted_file = fopen(opts->tmp_path, "w+");
//     //
//     // size_t bytesRead = 0;
//     // int i = 0;
//     // char buffer[512];
//     // memset(buffer, '\0', sizeof(buffer));
//     //
//     // // Read bytes of the original file, encrypt them, and write to the tmp file
//     // if (original_file != NULL) {
//     //   // read up to sizeof(buffer) bytes
//     //   while ((bytesRead = fread(buffer, 1, sizeof(buffer), original_file)) > 0) {
//     //     aes256_encrypt(&ctx, sizeof(buffer), buffer, buffer);
//     //     fputs(buffer, encrypted_file);
//     //     memset(buffer, '\0', sizeof(buffer));
//     //     i++;
//     //   }
//     // }
//     //
//     // // TODO: upload file
//     //
//     // fclose(original_file);
//     // fclose(encrypted_file);
//     //
//     // unlink(encrypted_file);
//     free(file_id);
//     free(file_id_buff);
//
//
// }
//
//
//




static void queue_next_work(storj_upload_state_t *state)
{
    // report any errors
    if (state->error_status != 0) {
        // TODO make sure that finished_cb is not called multiple times
        state->finished_cb(state->error_status);
        state->final_callback_called = true;

        free(state);
        return;
    }

    // queue_write_next_shard(state);
    //
    // // report progress of download
    // if (state->total_bytes > 0 && state->uploaded_bytes > 0) {
    //     state->progress_cb(state->uploaded_bytes / state->total_bytes);
    // }
    //
    // // report download complete
    // if (state->pointers_completed &&
    //     state->completed_shards == state->total_shards) {
    //
    //     state->finished_cb(0, state->destination);
    //
    //     free(state->pointers);
    //     free(state);
    //     return;
    // }
    //
    // if (!state->token && !state->pointers_completed) {
    //     queue_request_bucket_token(state);
    // }
    //
    // if (state->token && !state->pointers_completed) {
    //     queue_request_pointers(state);
    // }
    //
    // queue_request_shards(state);
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

    // setup download state
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
    state->error_status = 0;
    state->writing = false;
    state->token = NULL;
    state->requesting_token = false;
    state->final_callback_called = false;

    // Set File Name
    state->file_name = strrchr(state->file_path, '/');
    // Remove '/' from the front if exists by pushing the pointer up
    if (state->file_name[0] == '/') state->file_name++;

    // Get the file size
    state->file_size = check_file(env, state->file_path); // Expect to be up to 10tb
    if (state->file_size < 1) {
        printf("Invalid file: %s\n", state->file_path);
        return ERROR; //cleanup
    }

    // start download
    queue_next_work(state);
}
