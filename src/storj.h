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
#include <nettle/aes.h>
#include <nettle/ripemd160.h>
#include <nettle/hmac.h>
#include <nettle/pbkdf2.h>
#include <nettle/sha.h>
#include <json-c/json.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <uv.h>
#include <math.h>

#ifdef _WIN32
#include <time.h>
#endif

#define ERROR 0
#define OK 1
#define FILE_ID_SIZE 24
#define DETERMINISTIC_KEY_SIZE 64
#define SHARD_MULTIPLES_BACK 5
#define STORJ_DOWNLOAD_CONCURRENCY 4

typedef struct {
    char *proto;
    char *host;
    int port;
    char *user;
    char *pass;
} storj_bridge_options_t;

typedef struct storj_env {
    storj_bridge_options_t *bridge_options;
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

typedef enum {BUCKET_PUSH, BUCKET_PULL} storj_bucket_op_t;
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
typedef void (*storj_finished_cb)(int status, FILE *fd);

typedef struct {
    char *token;
    char *shard_hash;
    char **shard_data;
    unsigned int index;
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
    storj_finished_cb finished_cb;
    unsigned int total_shards;
    unsigned int completed_shards;
    unsigned int resolving_shards;
    storj_pointer_t *pointers;
    unsigned int total_pointers;
    storj_boolean_t pointers_completed;
    storj_boolean_t requesting_pointers;
    int error_status;
    storj_boolean_t writing;
    char *token;
    storj_boolean_t requesting_token;
} storj_download_state_t;

typedef struct {
    storj_bridge_options_t *options;
    char *token;
    char *bucket_id;
    /* state should not be modified in worker threads */
    storj_download_state_t *state;
    int status_code;
} token_request_download_t;

typedef struct {
    char **shard_data;
    ssize_t shard_total_bytes;
    int status_code;
    FILE *destination;
    unsigned int pointer_index;
    /* state should not be modified in worker threads */
    storj_download_state_t *state;
} shard_request_write_t;

typedef struct {
    char *farmer_proto;
    char *farmer_host;
    int farmer_port;
    char *shard_hash;
    unsigned int pointer_index;
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

typedef struct {
    int file_concurrency;
    int shard_concurrency;
    int redundancy;
    int shard_num;
    unsigned long long file_size;
    unsigned long long shard_size;
    char *bucket_id;
    char *file_path;
    char *tmp_path;
    char *file_id;
    char *file_name;
    char *key_pass;
    char *mnemonic;
} storj_upload_opts_t;

typedef struct {
    storj_env_t env;
    storj_upload_opts_t opts;
    uv_fs_t *open_req;
    uv_fs_t *read_req;
} storj_upload_work_data_t;

storj_env_t *storj_init_env(storj_bridge_options_t *options);

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
                            storj_upload_opts_t *opts);

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
                              storj_finished_cb finished_cb);

int storj_bridge_replicate_file(storj_env_t *env, uv_after_work_cb cb);

unsigned long long check_file(storj_env_t *env, char *filepath);

int sha256_of_str(const uint8_t *str, int str_len, uint8_t *digest);

int ripemd160_of_str(const uint8_t *str, int str_len, uint8_t *digest);

void pbkdf2_hmac_sha512(unsigned key_length,
                        const uint8_t *key,
                        unsigned iterations,
                        unsigned salt_length, const uint8_t *salt,
                        unsigned length, uint8_t *dst);

void random_buffer(uint8_t *buf, size_t len);

unsigned long long determine_shard_size(storj_upload_opts_t *opts,
                                        int accumulator);

unsigned long long shardSize(int hops);

/**
 * @brief Calculate file id by sha256ripemd160
 *
 * @param[in] bucket Character array of bucket id
 * @param[in] file_name Character array of file name
 * @param[out] buffer 12 byte character array that is the file's id
 * @return A non-zero error value on failure and 0 on success.
 */
int calculate_file_id(char *bucket, char *file_name, char **buffer);

/**
 * @brief Generate a bucket's key
 *
 * @param[in] Character array of the mnemonic
 * @param[in] bucket_id Character array of bucket id
 * @param[out] bucket_key 64 byte character array that is the bucket's key
 * @return A non-zero error value on failure and 0 on success.
 */
int generate_bucket_key(char *mnemonic, char *bucket_id, char **bucket_key);

/**
 * @brief Generate a file's key
 *
 * @param[in] Character array of the mnemonic
 * @param[in] bucket_id Character array of bucket id
 * @param[in] file_id Character array of file id
 * @param[out] file_key 64 byte character array that is the bucket's key
 * @return A non-zero error value on failure and 0 on success.
 */
int generate_file_key(char *mnemonic,
                      char *bucket_id,
                      char *file_id,
                      char **file_key);

/**
 * @brief Calculate deterministic key by getting sha512 of key + id
 *
 * @param[in] Character array of the key
 * @param[in] key_len Integer value of length of key
 * @param[in] id Character array id
 * @param[out] buffer 64 byte character array of the deterministic key
 * @return A non-zero error value on failure and 0 on success.
 */
int get_deterministic_key(char *key, int key_len, char *id, char **buffer);

#endif /* STORJ_H */
