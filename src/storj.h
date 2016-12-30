/**
 * @file storj.h
 * @brief Storj library.
 *
 * Implements functionality to upload and download files from the Storj
 * distributed network.
 */

#ifndef STORJ_H
#define STORJ_H

#ifdef __cplusplus
extern "C" {
#endif

#include <assert.h>
#include <json-c/json.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <uv.h>


inline char separator()
{
#ifdef _WIN32
    return '\\';
#else
    return '/';
#endif
}

#ifdef _WIN32
#include <time.h>
#endif

#define ERROR 1
#define OK 0

// File transfer success
#define STORJ_TRANSFER_OK 0

// Bridge related errors 1000 to 1999
#define STORJ_BRIDGE_REQUEST_ERROR 1000
#define STORJ_BRIDGE_AUTH_ERROR 1001
#define STORJ_BRIDGE_TOKEN_ERROR 1002
#define STORJ_BRIDGE_TIMEOUT_ERROR 1003
#define STORJ_BRIDGE_INTERNAL_ERROR 1004
#define STORJ_BRIDGE_RATE_ERROR 1005
#define STORJ_BRIDGE_BUCKET_NOTFOUND_ERROR 1006
#define STORJ_BRIDGE_FILE_NOTFOUND_ERROR 1007
#define STORJ_BRIDGE_JSON_ERROR 1008
#define STORJ_BRIDGE_FRAME_ERROR 1009
#define STORJ_BRIDGE_POINTER_ERROR 1010
#define STORJ_BRIDGE_REPOINTER_ERROR 1011

// Farmer related errors 2000 to 2999
#define STORJ_FARMER_REQUEST_ERROR 2000
#define STORJ_FARMER_TIMEOUT_ERROR 2001
#define STORJ_FARMER_AUTH_ERROR 2002
#define STORJ_FARMER_EXHAUSTED_ERROR 2003

// File related errors 3000 to 3999
#define STORJ_FILE_INTEGRITY_ERROR 3000
#define STORJ_FILE_WRITE_ERROR 3001
#define STORJ_FILE_ENCRYPTION_ERROR 3002

// Exchange report codes
#define STORJ_REPORT_SUCCESS 1000;
#define STORJ_REPORT_FAILURE 1100;

// Exchange report messages
#define STORJ_REPORT_FAILED_INTEGRITY "FAILED_INTEGRITY"
#define STORJ_REPORT_SHARD_DOWNLOADED "SHARD_DOWNLOADED"
#define STORJ_REPORT_SHARD_UPLOADED "SHARD_UPLOADED"
#define STORJ_REPORT_DOWNLOAD_ERROR "DOWNLOAD_ERROR"
#define STORJ_REPORT_UPLOAD_ERROR "TRANSFER_FAILED"

typedef struct {
    char *proto;
    char *host;
    int port;
    char *user;
    char *pass;
} storj_bridge_options_t;

typedef struct storj_encrypt_options {
    char *mnemonic;
} storj_encrypt_options_t;

typedef struct storj_env {
    storj_bridge_options_t *bridge_options;
    storj_encrypt_options_t *encrypt_options;
    uv_loop_t *loop;
} storj_env_t;

typedef struct {
    storj_bridge_options_t *options;
    char *method;
    char *path;
    bool auth;
    struct json_object *body;
    struct json_object *response;
    int status_code;
} json_request_t;

typedef enum {
    BUCKET_PUSH,
    BUCKET_PULL
} storj_bucket_op_t;

static const char *BUCKET_OP[] = { "PUSH", "PULL" };

typedef struct {
    char *data_hash;
    char *reporter_id;
    char *farmer_id;
    char *client_id;
    uint64_t start;
    uint64_t end;
    unsigned int code;
    char *message;
    unsigned int send_status;
    unsigned int send_count;
    uint32_t pointer_index;
} storj_exchange_report_t;

typedef struct {
} storj_shard_tree;

typedef struct {
} storj_shard_challenges;

typedef struct {
    int index;
    char *hash;
    uint64_t size;
    storj_shard_tree tree;
    storj_shard_challenges challenges;
} storj_shard_t;

typedef void (*storj_progress_cb)(double progress);
typedef void (*storj_finished_download_cb)(int status, FILE *fd);
typedef void (*storj_finished_upload_cb)(int error_status);

typedef struct {
    unsigned int replace_count;
    char *token;
    char *shard_hash;
    char *shard_data;
    uint32_t index;
    int status;
    uint64_t size;
    uint64_t downloaded_size;
    char *farmer_address;
    int farmer_port;
    storj_exchange_report_t *report;
} storj_pointer_t;

typedef enum {
    POINTER_BEING_REPLACED = -3,
    POINTER_ERROR_REPORTED = -2,
    POINTER_ERROR = -1,
    POINTER_CREATED = 0,
    POINTER_BEING_DOWNLOADED = 1,
    POINTER_DOWNLOADED = 2,
    POINTER_BEING_WRITTEN = 3,
    POINTER_WRITTEN = 4
} storj_pointer_status_t;

typedef struct {
    uint64_t total_bytes;
    storj_env_t *env;
    char *file_id;
    char *bucket_id;
    FILE *destination;
    storj_progress_cb progress_cb;
    storj_finished_download_cb finished_cb;
    bool finished;
    uint64_t shard_size;
    uint32_t total_shards;
    uint32_t completed_shards;
    uint32_t resolving_shards;
    storj_pointer_t *pointers;
    char *excluded_farmer_ids;
    uint32_t total_pointers;
    bool pointers_completed;
    bool requesting_pointers;
    int error_status;
    bool writing;
    char *token;
    bool requesting_token;
    uint8_t *decrypt_key;
    uint8_t *decrypt_ctr;
} storj_download_state_t;

typedef struct {
    int code;
    char *message;
} storj_error_t;

typedef struct {
    char *frame_id;
} storj_frame_t;

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
   char *file_id;
   char *file_key;
   char *file_path;
   char *file_name;
   char *tmp_path;
   uint64_t file_size;
   storj_upload_state_t *upload_state;
} encrypt_file_meta_t;

typedef struct {
    int file_concurrency;
    int shard_concurrency;
    char *bucket_id;
    char *file_path;
    char *key_pass;
    char *mnemonic;
} storj_upload_opts_t;

typedef struct {
    storj_bridge_options_t *options;
    char *token;
    char *bucket_id;
    char *bucket_op;
    /* state should not be modified in worker threads */
    storj_download_state_t *download_state;
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

typedef struct {
    char *shard_data;
    ssize_t shard_total_bytes;
    int error_status;
    FILE *destination;
    uint32_t pointer_index;
    /* state should not be modified in worker threads */
    storj_download_state_t *state;
} shard_request_write_t;

typedef struct {
    char *farmer_proto;
    char *farmer_host;
    int farmer_port;
    char *shard_hash;
    uint32_t pointer_index;
    char *token;
    uint64_t start;
    uint64_t end;
    uint64_t shard_total_bytes;
    uv_async_t progress_handle;
    uint64_t byte_position;
    uint8_t *decrypt_key;
    uint8_t *decrypt_ctr;
    char *shard_data;
    /* state should not be modified in worker threads */
    storj_download_state_t *state;
    int status_code;
} shard_request_download_t;

typedef struct {
    uint32_t pointer_index;
    uint64_t bytes;
    /* state should not be modified in worker threads */
    storj_download_state_t *state;
} shard_download_progress_t;

typedef struct {
    uint32_t pointer_index;
    storj_bridge_options_t *options;
    int status_code;
    storj_exchange_report_t *report;
    /* state should not be modified in worker threads */
    storj_download_state_t *state;
} shard_send_report_t;

typedef struct {
    storj_bridge_options_t *options;
    uint32_t pointer_index;
    char *token;
    char *bucket_id;
    char *file_id;
    char *excluded_farmer_ids;
    /* state should not be modified in worker threads */
    storj_download_state_t *state;
    struct json_object *response;
    int status_code;
} json_request_replace_pointer_t;

typedef struct {
    storj_bridge_options_t *options;
    char *method;
    char *path;
    bool auth;
    char *token;
    struct json_object *body;
    struct json_object *response;
    /* state should not be modified in worker threads */
    storj_download_state_t *state;
    int status_code;
} json_request_download_t;

storj_env_t *storj_init_env(storj_bridge_options_t *options,
                            storj_encrypt_options_t *encrypt_options);

/**
 * @brief Get the error message for an error code
 *
 * This function will return a error message associated with a storj
 * error code.
 *
 * @param[in] error_code The storj error code integer
 * @return A char pointer with error message
 */
char *storj_strerror(int error_code);

/**
 * @brief Get Storj bridge API information.
 *
 * This function will get general information about the storj bridge api.
 * The network i/o is performed in a thread pool with a libuv loop, and the
 * response is available in the first argument to the callback function.
 *
 * @param[in] env The storj environment struct
 * @param[in] cb A function called with response when complete
 * @return A non-zero error value on failure and 0 on success.
 */
int storj_bridge_get_info(storj_env_t *env, uv_after_work_cb cb);

/**
 * @brief List available buckets for a user.
 *
 * @param[in] env The storj environment struct
 * @param[in] cb A function called with response when complete
 * @return A non-zero error value on failure and 0 on success.
 */
int storj_bridge_get_buckets(storj_env_t *env, uv_after_work_cb cb);

/**
 * @brief Create a bucket.
 *
 * @param[in] env The storj environment struct
 * @param[in] cb A function called with response when complete
 * @return A non-zero error value on failure and 0 on success.
 */
int storj_bridge_create_bucket(storj_env_t *env,
                               char *name,
                               uv_after_work_cb cb);

/**
 * @brief Delete a bucket.
 *
 * @param[in] env The storj environment struct
 * @param[in] cb A function called with response when complete
 * @return A non-zero error value on failure and 0 on success.
 */
int storj_bridge_delete_bucket(storj_env_t *env, char *id, uv_after_work_cb cb);

/**
 * @brief Get a list of all files in a bucket.
 *
 * @param[in] env The storj environment struct
 * @param[in] cb A function called with response when complete
 * @return A non-zero error value on failure and 0 on success.
 */
int storj_bridge_list_files(storj_env_t *env, char *id, uv_after_work_cb cb);

/**
 * @brief Create a PUSH or PULL bucket token.
 *
 * @param[in] env The storj environment struct
 * @param[in] cb A function called with response when complete
 * @return A non-zero error value on failure and 0 on success.
 */
int storj_bridge_create_bucket_token(storj_env_t *env,
                                     char *bucket_id,
                                     storj_bucket_op_t operation,
                                     uv_after_work_cb cb);

/**
 * @brief Get pointers with locations to file shards.
 *
 * @param[in] env The storj environment struct
 * @param[in] cb A function called with response when complete
 * @return A non-zero error value on failure and 0 on success.
 */
int storj_bridge_get_file_pointers(storj_env_t *env,
                                   char *bucket_id,
                                   char *file_id,
                                   uv_after_work_cb cb);

/**
 * @brief Delete a file in a bucket.
 *
 * @param[in] env The storj environment struct
 * @param[in] cb A function called with response when complete
 * @return A non-zero error value on failure and 0 on success.
 */
int storj_bridge_delete_file(storj_env_t *env,
                             char *bucket_id,
                             char *file_id,
                             uv_after_work_cb cb);

/**
 * @brief Create a file frame
 *
 * @param[in] env The storj environment struct
 * @param[in] cb A function called with response when complete
 * @return A non-zero error value on failure and 0 on success.
 */
int storj_bridge_create_frame(storj_env_t *env, uv_after_work_cb cb);

/**
 * @brief List available file frames
 *
 * @param[in] env The storj environment struct
 * @param[in] cb A function called with response when complete
 * @return A non-zero error value on failure and 0 on success.
 */
int storj_bridge_get_frames(storj_env_t *env, uv_after_work_cb cb);

/**
 * @brief Get information for a file frame
 *
 * @param[in] env The storj environment struct
 * @param[in] cb A function called with response when complete
 * @return A non-zero error value on failure and 0 on success.
 */
int storj_bridge_get_frame(storj_env_t *env,
                           char *frame_id,
                           uv_after_work_cb cb);

/**
 * @brief Delete a file frame
 *
 * @param[in] env The storj environment struct
 * @param[in] cb A function called with response when complete
 * @return A non-zero error value on failure and 0 on success.
 */
int storj_bridge_delete_frame(storj_env_t *env,
                              char *frame_id,
                              uv_after_work_cb cb);

/**
 * @brief Add a shard to a frame
 *
 * @param[in] env The storj environment struct
 * @param[in] cb A function called with response when complete
 * @return A non-zero error value on failure and 0 on success.
 */
int storj_bridge_add_shard_to_frame(storj_env_t *env,
                                    char *frame_id,
                                    storj_shard_t *shard,
                                    uv_after_work_cb cb);

/**
 * @brief Get metadata for a file
 *
 * @param[in] env The storj environment struct
 * @param[in] cb A function called with response when complete
 * @return A non-zero error value on failure and 0 on success.
 */
int storj_bridge_get_file_info(storj_env_t *env,
                               char *bucket_id,
                               char *file_id,
                               uv_after_work_cb cb);

int storj_bridge_store_file(storj_env_t *env,
                           storj_upload_opts_t *opts,
                           storj_progress_cb progress_cb,
                           storj_finished_upload_cb finished_cb);

/**
 * @brief Download a file
 *
 * @param[in] bucket_id Character array of bucket id
 * @param[in] file_id Character array of file id
 * @param[out] destination A file descriptor of the destination
 * @return A non-zero error value on failure and 0 on success.
 */
int storj_bridge_resolve_file(storj_env_t *env,
                              char *bucket_id,
                              char *file_id,
                              FILE *destination,
                              storj_progress_cb progress_cb,
                              storj_finished_download_cb finished_cb);
#ifdef __cplusplus
}
#endif

#endif /* STORJ_H */
