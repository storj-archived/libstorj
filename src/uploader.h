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
#define SHARD_MULTIPLES_BACK 4
#define STORJ_NULL -1
#define STORJ_MAX_REPORT_TRIES 2

typedef enum {
    CANCELED = 0,
    AWAITING_PREPARE_FRAME = 1,
    PREPARING_FRAME = 2,
    AWAITING_PUSH_FRAME = 3,
    PUSHING_FRAME = 4,
    AWAITING_PUSH_SHARD = 5,
    PUSHING_SHARD = 6,
    COMPLETED_PUSH_SHARD = 7
} storj_state_progress_t;

typedef struct {
    /* state should not be modified in worker threads */
    storj_upload_state_t *upload_state;
    int status_code;
    int error_status;
    shard_meta_t *shard_meta;
    storj_log_levels_t *log;
} frame_builder_t;

typedef struct {
    storj_http_options_t *http_options;
    storj_bridge_options_t *options;
    int status_code;
    int error_status;
    storj_log_levels_t *log;
    int shard_index;
    uv_async_t progress_handle;
    uint64_t start;
    uint64_t end;

    /* state should not be modified in worker threads */
    storj_upload_state_t *upload_state;
    bool *canceled;
} push_shard_request_t;

typedef struct {
    storj_http_options_t *http_options;
    storj_bridge_options_t *options;
    char *token;
    const char *bucket_id;
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

typedef struct {
    uint32_t pointer_index;
    storj_http_options_t *http_options;
    storj_bridge_options_t *options;
    int status_code;
    storj_exchange_report_t *report;
    /* state should not be modified in worker threads */
    storj_upload_state_t *state;
} shard_send_report_t;

static farmer_pointer_t *farmer_pointer_new();
static shard_meta_t *shard_meta_new();
static uv_work_t *shard_meta_work_new(int index, storj_upload_state_t *state);
static uv_work_t *frame_work_new(int *index, storj_upload_state_t *state);
static uv_work_t *uv_work_new();
static int prepare_encryption_key(storj_upload_state_t *state,
                               char *pre_pass,
                               int pre_pass_size,
                               char *pre_salt,
                               int pre_salt_size);

static uint64_t check_file(storj_env_t *env, const char *filepath);

static void shard_meta_cleanup(shard_meta_t *shard_meta);
static void pointer_cleanup(farmer_pointer_t *farmer_pointer);
static void cleanup_state(storj_upload_state_t *state);
static void free_encryption_ctx(storj_encryption_ctx_t *ctx);

static void queue_next_work(storj_upload_state_t *state);

static void queue_request_frame_id(storj_upload_state_t *state);
static void queue_prepare_frame(storj_upload_state_t *state, int index);
static void queue_push_frame(storj_upload_state_t *state, int index);
static void queue_push_shard(storj_upload_state_t *state, int index);
static void queue_create_bucket_entry(storj_upload_state_t *state);
static void queue_send_exchange_report(storj_upload_state_t *state, int index);

static void request_token(uv_work_t *work);
static void request_frame_id(uv_work_t *work);
static void prepare_frame(uv_work_t *work);
static void push_frame(uv_work_t *work);
static void push_shard(uv_work_t *work);
static void create_bucket_entry(uv_work_t *work);
static void send_exchange_report(uv_work_t *work);

static void after_request_token(uv_work_t *work, int status);
static void after_request_frame_id(uv_work_t *work, int status);
static void after_prepare_frame(uv_work_t *work, int status);
static void after_push_frame(uv_work_t *work, int status);
static void after_push_shard(uv_work_t *work, int status);
static void after_create_bucket_entry(uv_work_t *work, int status);
static void after_send_exchange_report(uv_work_t *work, int status);

#endif /* STORJ_UPLOADER_H */
