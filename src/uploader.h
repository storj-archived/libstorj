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
#include "rs.h"

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

typedef enum {
    PREPARE_FRAME_LIMIT = 1,
    PUSH_FRAME_LIMIT = 32,
    PUSH_SHARD_LIMIT = 32
} storj_state_progress_limits_t;

typedef enum {
    NONE = 0,
    RS_BEFORE_ENCRYPTION = 1,
    RS_AFTER_ENCRYPTION = 2
} storj_erasure_t;

typedef struct {
    /* state should not be modified in worker threads */
    storj_upload_state_t *upload_state;
    int status_code;
    int error_status;
    shard_meta_t *shard_meta;
    // Position in shard meta array
    int shard_meta_index;
    // Either parity file pointer or original file
    FILE *shard_file;
    storj_log_levels_t *log;
} frame_builder_t;

typedef struct {
    int error_status;
    /* state should not be modified in worker threads */
    storj_upload_state_t *upload_state;
} parity_shard_req_t;

typedef struct {
    int error_status;
    /* state should not be modified in worker threads */
    storj_upload_state_t *upload_state;
} encrypt_file_req_t;

typedef struct {
    storj_http_options_t *http_options;
    storj_bridge_options_t *options;
    int status_code;
    int error_status;
    storj_log_levels_t *log;
    int shard_index;
    int shard_meta_index;
    FILE *shard_file;
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
    int shard_meta_index;
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

static int check_in_progress(storj_upload_state_t *state, int status);
char *create_tmp_name(storj_upload_state_t *state, char *extension);

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
static void queue_create_encrypted_file(storj_upload_state_t *state);

static void request_token(uv_work_t *work);
static void request_frame_id(uv_work_t *work);
static void prepare_frame(uv_work_t *work);
static void push_frame(uv_work_t *work);
static void push_shard(uv_work_t *work);
static void create_bucket_entry(uv_work_t *work);
static void send_exchange_report(uv_work_t *work);
static void create_encrypted_file(uv_work_t *work);

static void after_request_token(uv_work_t *work, int status);
static void after_request_frame_id(uv_work_t *work, int status);
static void after_prepare_frame(uv_work_t *work, int status);
static void after_push_frame(uv_work_t *work, int status);
static void after_push_shard(uv_work_t *work, int status);
static void after_create_bucket_entry(uv_work_t *work, int status);
static void after_send_exchange_report(uv_work_t *work, int status);
static void after_create_encrypted_file(uv_work_t *work, int status);

static void queue_verify_bucket_id(storj_upload_state_t *state);
static void queue_verify_file_id(storj_upload_state_t *state);
static void verify_bucket_id_callback(uv_work_t *work_req, int status);
static void verify_file_id_callback(uv_work_t *work_req, int status);

#endif /* STORJ_UPLOADER_H */
