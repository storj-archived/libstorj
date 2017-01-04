/**
 * @file uploader.h
 * @brief Storj upload methods and definitions.
 *
 * Structures and functions useful for uploading files.
 */
#ifndef STORJ_UPLOADER_H
#define STORJ_UPLOADER_H

#include "storj.h"
#include "http.h"
#include "utils.h"
#include "crypto.h"

#define MAX_SHARD_SIZE 1073741824
#define SHARD_MULTIPLES_BACK 5
#define CHALLENGES 4

typedef struct {
    storj_env_t *env;
    uint32_t file_concurrency;
    uint32_t shard_concurrency;
    char *file_id;
    char *file_name;
    char *file_path;
    char *file_key;
    uint64_t file_size;
    char *tmp_path;
    char *bucket_id;
    char *bucket_key;
    uint32_t completed_shards;
    uint32_t total_shards;
    uint64_t shard_size;
    uint64_t total_bytes;
    uint64_t uploaded_bytes;
    bool hashing_shards;
    bool completed_shard_hash;
    bool writing;
    bool encrypting_file;
    bool completed_encryption;
    char *token;
    bool requesting_token;
    char *frame_id;
    bool requesting_frame;
    int token_request_count;
    int frame_request_count;
    int encrypt_file_count;
    bool final_callback_called;
    storj_progress_cb progress_cb;
    storj_finished_upload_cb finished_cb;
    char *mnemonic;
    int error_status;
} storj_upload_state_t;

typedef struct {
    char *hash;
    char **challenges;
    char **tree;
    int shard_index;
    /* state should not be modified in worker threads */
    storj_upload_state_t *upload_state;
    int status_code;
    int error_status;
} shard_meta_t;

typedef struct {
   char *file_id;
   char *file_key;
   char *file_path;
   char *file_name;
   char *tmp_path;
   uint64_t file_size;
   storj_upload_state_t *upload_state;
} encrypt_file_meta_t;

typedef struct {
    storj_bridge_options_t *options;
    char *token;
    char *bucket_id;
    char *bucket_op;
    /* state should not be modified in worker threads */
    storj_upload_state_t *upload_state;
    int status_code;
    int error_status;
} token_request_token_t;

typedef struct {
    storj_bridge_options_t *options;
    /* state should not be modified in worker threads */
    storj_upload_state_t *upload_state;
    char *frame_id;
    int status_code;
    int error_status;
} frame_request_t;

inline char separator()
{
#ifdef _WIN32
    return '\\';
#else
    return '/';
#endif
}

static void queue_next_work(storj_upload_state_t *state);

static int queue_request_bucket_token(storj_upload_state_t *state);
static int queue_request_frame(storj_upload_state_t *state);
static int queue_encrypt_file(storj_upload_state_t *state);
static int queue_create_frame(storj_upload_state_t *state);

static void request_token(uv_work_t *work);
static void request_frame(uv_work_t *work);
static void encrypt_file(uv_work_t *work);
static void create_frame(uv_work_t *work);

static void after_request_token(uv_work_t *work, int status);
static void after_request_frame(uv_work_t *work, int status);
static void after_encrypt_file(uv_work_t *work, int status);
static void after_create_frame(uv_work_t *work, int status);

#endif /* STORJ_UPLOADER_H */
