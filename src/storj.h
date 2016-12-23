/**
 * @file storj.h
 * @brief Storj library.
 *
 * Implements functionality to upload and download files from the Storj
 * distributed network.
 */
#ifndef STORJ_H
#define STORJ_H

#include <assert.h>
#include <json-c/json.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <uv.h>

#ifdef _WIN32
#include <time.h>
#define PATH_SEPARATOR "\\"
#else
#define PATH_SEPARATOR "/"
#endif

// TODO use 0 for success
#define ERROR 0
#define OK 1

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

// Farmer related errors 2000 to 2999
#define STORJ_FARMER_REQUEST_ERROR 2000
#define STORJ_FARMER_TIMEOUT_ERROR 2001
#define STORJ_FARMER_AUTH_ERROR 2002

// File related errors 3000 to 3999
#define STORJ_FILE_INTEGRITY_ERROR 3000
#define STORJ_FILE_WRITE_ERROR 3001

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

typedef enum { false, true } storj_boolean_t;

typedef struct {
    storj_bridge_options_t *options;
    char *method;
    char *path;
    storj_boolean_t auth;
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
typedef void (*storj_finished_upload_cb)(int error_code);

typedef struct {
    char *token;
    char *shard_hash;
    char **shard_data;
    uint32_t index;
    int status;
    uint64_t size;
    char *farmer_address;
    int farmer_port;
} storj_pointer_t;

typedef enum {
    POINTER_ERROR = -1,
    POINTER_CREATED = 0,
    POINTER_BEING_DOWNLOADED = 1,
    POINTER_DOWNLOADED = 2,
    POINTER_BEING_WRITTEN = 3,
    POINTER_WRITTEN = 4
} storj_pointer_status_t;

typedef struct {
    uint64_t total_bytes;
    uint64_t downloaded_bytes;
    storj_env_t *env;
    char *file_id;
    char *bucket_id;
    FILE *destination;
    storj_progress_cb progress_cb;
    storj_finished_download_cb finished_cb;
    uint32_t total_shards;
    uint32_t completed_shards;
    uint32_t resolving_shards;
    storj_pointer_t *pointers;
    uint32_t total_pointers;
    storj_boolean_t pointers_completed;
    storj_boolean_t requesting_pointers;
    int error_status;
    storj_boolean_t writing;
    char *token;
    storj_boolean_t requesting_token;
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
    storj_boolean_t writing;
    storj_boolean_t encrypting_file;
    char *token;
    storj_boolean_t requesting_token;
    storj_frame_t *frame;
    storj_boolean_t requesting_frame;
    int token_request_count;
    storj_boolean_t final_callback_called;
    storj_progress_cb progress_cb;
    storj_finished_upload_cb finished_cb;
    char *mnemonic;
    int error_code;
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
    char **shard_data;
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
    ssize_t shard_total_bytes;
    char *shard_data;
    /* state should not be modified in worker threads */
    storj_download_state_t *state;
    int status_code;
} shard_request_download_t;

typedef struct {
    storj_bridge_options_t *options;
    char *method;
    char *path;
    storj_boolean_t auth;
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

#endif /* STORJ_H */
