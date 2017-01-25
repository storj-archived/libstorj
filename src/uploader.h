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
#define STORJ_NULL -1

typedef struct {
    char *hash;
    char *challenges[CHALLENGES][32];
    char *challenges_as_str[CHALLENGES][64 + 1];
    // Merkle Tree leaves. Each leaf is size of RIPEMD160 hash
    char *tree[2*CHALLENGES - 1][RIPEMD160_DIGEST_SIZE*2 + 1];
    int index;
    uint64_t size;
} shard_meta_t;

typedef struct {
    char *token;
    char *farmer_user_agent;
    char *farmer_protocol;
    char *farmer_address;
    char *farmer_port;
    char *farmer_node_id;
    char *farmer_last_seen;
} farmer_pointer_t;

typedef struct {
    bool pushed_shard;
    bool pushing_shard;
    bool creating_frame;
    bool created_frame;
    bool pushed_frame;
    bool pushing_frame;
    int pushing_frame_request_count;
    int pushing_shard_request_count;
    int index;
    farmer_pointer_t *pointer;
    shard_meta_t *meta;
} shard_tracker_t;

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
    bool completed_upload;
    bool encrypting_file;
    bool completed_encryption;
    bool creating_bucket_entry;
    int add_bucket_entry_count;
    char *token;
    bool requesting_token;
    char *frame_id;
    bool requesting_frame;
    bool received_all_pointers;
    int token_request_count;
    int frame_request_count;
    int encrypt_file_count;
    bool final_callback_called;
    storj_progress_cb progress_cb;
    storj_finished_upload_cb finished_cb;
    int error_status;
    storj_log_levels_t *log;
    void *handle;
    shard_tracker_t *shard;
} storj_upload_state_t;

typedef struct {
    /* state should not be modified in worker threads */
    storj_upload_state_t *upload_state;
    int status_code;
    int error_status;
    shard_meta_t *shard_meta;
    storj_log_levels_t *log;
} frame_builder_t;

typedef struct {
    char *file_id;
    char *file_key;
    char *file_path;
    char *file_name;
    char *tmp_path;
    uint64_t file_size;
    storj_upload_state_t *upload_state;
    storj_log_levels_t *log;
} encrypt_file_meta_t;

typedef struct {
    storj_http_options_t *http_options;
    storj_bridge_options_t *options;
    int status_code;
    int error_status;
    storj_log_levels_t *log;
    int shard_index;

    /* state should not be modified in worker threads */
    storj_upload_state_t *upload_state;
} push_shard_request_t;

typedef struct {
    storj_http_options_t *http_options;
    storj_bridge_options_t *options;
    char *token;
    char *bucket_id;
    char *bucket_op;
    /* state should not be modified in worker threads */
    storj_upload_state_t *upload_state;
    int status_code;
    int error_status;
    storj_log_levels_t *log;
} request_token_t;

typedef struct {
    storj_http_options_t *http_options;
    storj_bridge_options_t *options;
    /* state should not be modified in worker threads */
    storj_upload_state_t *upload_state;
    char *frame_id;
    int status_code;
    int error_status;

    // Add shard to frame
    int shard_index;
    farmer_pointer_t *farmer_pointer;

    storj_log_levels_t *log;
} frame_request_t;

typedef struct {
  storj_http_options_t *http_options;
  storj_bridge_options_t *options;
  /* state should not be modified in worker threads */
  storj_upload_state_t *upload_state;
  int status_code;
  int error_status;
  storj_log_levels_t *log;
} post_to_bucket_request_t;

static inline char separator()
{
#ifdef _WIN32
    return '\\';
#else
    return '/';
#endif
}

static farmer_pointer_t *farmer_pointer_new();
static shard_meta_t *shard_meta_new();
static uv_work_t *shard_meta_work_new(int index, storj_upload_state_t *state);
static uv_work_t *frame_work_new(int *index, storj_upload_state_t *state);
static uv_work_t *uv_work_new();

static void shard_meta_cleanup(shard_meta_t *shard_meta);
static void pointer_cleanup(farmer_pointer_t *farmer_pointer);
static void cleanup_state(storj_upload_state_t *state);

static void queue_next_work(storj_upload_state_t *state);

static int queue_request_bucket_token(storj_upload_state_t *state);
static int queue_request_frame(storj_upload_state_t *state);
static int queue_encrypt_file(storj_upload_state_t *state);
static int queue_create_frame(storj_upload_state_t *state, int index);
static int queue_push_frame(storj_upload_state_t *state, int index);
static int queue_push_shard(storj_upload_state_t *state, int index);
static int queue_create_bucket_entry(storj_upload_state_t *state);

static void request_token(uv_work_t *work);
static void request_frame(uv_work_t *work);
static void encrypt_file(uv_work_t *work);
static void create_frame(uv_work_t *work);
static void push_frame(uv_work_t *work);
static void push_shard(uv_work_t *work);
static void create_bucket_entry(uv_work_t *work);

static void after_request_token(uv_work_t *work, int status);
static void after_request_frame(uv_work_t *work, int status);
static void after_encrypt_file(uv_work_t *work, int status);
static void after_create_frame(uv_work_t *work, int status);
static void after_push_frame(uv_work_t *work, int status);
static void after_push_shard(uv_work_t *work, int status);
static void after_create_bucket_entry(uv_work_t *work, int status);

#endif /* STORJ_UPLOADER_H */
