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
#include <stdarg.h>
#include <string.h>
#include <uv.h>
#include <curl/curl.h>

#ifdef _WIN32
#include <time.h>
#endif

#ifndef _WIN32
#include <sys/mman.h>
#include <unistd.h>
#endif

// File transfer success
#define STORJ_TRANSFER_OK 0
#define STORJ_TRANSFER_CANCELED 1

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
#define STORJ_FARMER_INTEGRITY_ERROR 2004

// File related errors 3000 to 3999
#define STORJ_FILE_INTEGRITY_ERROR 3000
#define STORJ_FILE_WRITE_ERROR 3001
#define STORJ_FILE_ENCRYPTION_ERROR 3002
#define STORJ_FILE_SIZE_ERROR 3003

// Memory related errors
#define STORJ_MEMORY_ERROR 4000

// Queue related errors
#define STORJ_QUEUE_ERROR 5000

// Exchange report codes
#define STORJ_REPORT_SUCCESS 1000
#define STORJ_REPORT_FAILURE 1100

// Exchange report messages
#define STORJ_REPORT_FAILED_INTEGRITY "FAILED_INTEGRITY"
#define STORJ_REPORT_SHARD_DOWNLOADED "SHARD_DOWNLOADED"
#define STORJ_REPORT_SHARD_UPLOADED "SHARD_UPLOADED"
#define STORJ_REPORT_DOWNLOAD_ERROR "DOWNLOAD_ERROR"
#define STORJ_REPORT_UPLOAD_ERROR "TRANSFER_FAILED"

#define STORJ_SHARD_CHALLENGES 4

typedef enum {
    STORJ_REPORT_NOT_PREPARED = 0,
    STORJ_REPORT_AWAITING_SEND = 1,
    STORJ_REPORT_SENDING = 2,
    STORJ_REPORT_SENT = 3
} exchange_report_status_t;

/** @brief Bridge configuration options
 *
 * Proto can be "http" or "https", and the user/pass are used for
 * basic authentication to a Storj bridge.
 */
typedef struct {
    const char *proto;
    const char *host;
    int port;
    const char *user;
    const char *pass;
} storj_bridge_options_t;

/** @brief File encryption options
 *
 * The mnemonic is a BIP39 secret code used for generating keys for file
 * encryption and decryption.
 */
typedef struct storj_encrypt_options {
    const char *mnemonic;
    const char *tmp_path;
} storj_encrypt_options_t;



/** @brief HTTP configuration options
 *
 * Settings for making HTTP requests
 */
typedef struct storj_http_options {
    const char *user_agent;
    const char *proxy_url;
} storj_http_options_t;

/** @brief A function signature for logging
 */
typedef void (*storj_logger_fn)(const char *message, int level, void *handle);

/** @brief Logging configuration options
 *
 * Settings for logging
 */
typedef struct storj_log_options {
    storj_logger_fn logger;
    int level;
} storj_log_options_t;

/** @brief A function signature for logging
 */
typedef void (*storj_logger_format_fn)(storj_log_options_t *options,
                                       void *handle,
                                       const char *format, ...);

/** @brief Functions for all logging levels
 */
typedef struct storj_log_levels {
    storj_logger_format_fn debug;
    storj_logger_format_fn info;
    storj_logger_format_fn warn;
    storj_logger_format_fn error;
} storj_log_levels_t;

/** @brief A structure for a Storj user environment.
 *
 * This is the highest level structure and holds many commonly used options
 * and the event loop for queuing work.
 */
typedef struct storj_env {
    storj_bridge_options_t *bridge_options;
    storj_encrypt_options_t *encrypt_options;
    storj_http_options_t *http_options;
    storj_log_options_t *log_options;
    uv_loop_t *loop;
    storj_log_levels_t *log;
} storj_env_t;

/** @brief A structure for queueing json request work
 */
typedef struct {
    storj_http_options_t *http_options;
    storj_bridge_options_t *options;
    char *method;
    char *path;
    bool auth;
    struct json_object *body;
    struct json_object *response;
    int error_code;
    int status_code;
    void *handle;
} json_request_t;

typedef enum {
    BUCKET_PUSH,
    BUCKET_PULL
} storj_bucket_op_t;

static const char *BUCKET_OP[] = { "PUSH", "PULL" };

/** @brief A data structure that represents an exchange report
 *
 * These are sent at the end of an exchange with a farmer to report the
 * performance and reliability of farmers.
 */
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

/** @brief A function signature for download/upload progress callback
 */
typedef void (*storj_progress_cb)(double progress,
                                  uint64_t bytes,
                                  uint64_t total_bytes,
                                  void *handle);

/** @brief A function signature for a download complete callback
 */
typedef void (*storj_finished_download_cb)(int status, FILE *fd, void *handle);

/** @brief A function signature for an upload complete callback
 */
typedef void (*storj_finished_upload_cb)(int error_status, void *handle);

/** @brief A structure that represents a pointer to a shard
 *
 * A shard is an encrypted piece of a file, a pointer holds all necessary
 * information to retrieve a shard from a farmer, including the IP address
 * and port of the farmer, as well as a token indicating a transfer has been
 * authorized. Other necessary information such as the expected hash of the
 * data, and the index position in the file is also included.
 *
 * The data can be replaced with new farmer contact, in case of failure, and the
 * total number of replacements can be tracked.
 */
typedef struct {
    unsigned int replace_count;
    char *token;
    char *shard_hash;
    char *shard_data;
    uint32_t index;
    int status;
    uint64_t size;
    uint64_t downloaded_size;
    char *farmer_id;
    char *farmer_address;
    int farmer_port;
    storj_exchange_report_t *report;
    uv_work_t *work;
} storj_pointer_t;

/** @brief A structure for file upload options
 */
typedef struct {
    int shard_concurrency;
    const char *bucket_id;
    const char *file_name;
    FILE *fd;
} storj_upload_opts_t;

/** @brief A structure that keeps state between multiple worker threads,
 * and for referencing a download to apply actions to an in-progress download.
 *
 * After work has been completed in a thread, its after work callback will
 * update and modify the state and then queue the next set of work based on the
 * changes, and added to the event loop. The state is all managed within one
 * thread, the event loop thread, and any work that is performed in another
 * thread should not modify this structure directly, but should pass a
 * reference to it, so that once the work is complete the state can be updated.
 */
typedef struct {
    uint64_t total_bytes;
    storj_env_t *env;
    const char *file_id;
    const char *bucket_id;
    FILE *destination;
    storj_progress_cb progress_cb;
    storj_finished_download_cb finished_cb;
    bool finished;
    bool canceled;
    uint64_t shard_size;
    uint32_t total_shards;
    uint32_t completed_shards;
    uint32_t resolving_shards;
    storj_pointer_t *pointers;
    char *excluded_farmer_ids;
    uint32_t total_pointers;
    bool pointers_completed;
    uint32_t pointer_fail_count;
    bool requesting_pointers;
    int error_status;
    bool writing;
    char *token;
    bool requesting_token;
    uint32_t token_fail_count;
    uint8_t *decrypt_key;
    uint8_t *decrypt_ctr;
    uint32_t pending_work_count;
    storj_log_levels_t *log;
    void *handle;
} storj_download_state_t;


typedef struct {
    char *hash;
    char *challenges[STORJ_SHARD_CHALLENGES][32];
    char *challenges_as_str[STORJ_SHARD_CHALLENGES][64 + 1];
    // Merkle Tree leaves. Each leaf is size of RIPEMD160 hash
    char *tree[2 * STORJ_SHARD_CHALLENGES - 1][20 * 2 + 1];
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
} farmer_pointer_t;

typedef struct {
    int progress;
    int push_frame_request_count;
    int push_shard_request_count;
    int index;
    farmer_pointer_t *pointer;
    shard_meta_t *meta;
    storj_exchange_report_t *report;
    uint64_t uploaded_size;
    uv_work_t *work;
} shard_tracker_t;

typedef struct {
    storj_env_t *env;
    uint32_t shard_concurrency;
    char *file_id;
    const char *file_name;
    FILE *original_file;
    char *file_key;
    uint64_t file_size;
    char *tmp_path;
    const char *bucket_id;
    char *bucket_key;
    uint32_t completed_shards;
    uint32_t total_shards;
    uint64_t shard_size;
    uint64_t total_bytes;
    uint64_t uploaded_bytes;
    char *exclude;
    char *frame_id;

    bool requesting_frame;
    bool completed_upload;
    bool encrypting_file;
    bool creating_bucket_entry;
    bool received_all_pointers;
    bool final_callback_called;
    bool canceled;

    bool progress_finished;

    int frame_request_count;
    int encrypt_file_count;
    int add_bucket_entry_count;

    storj_progress_cb progress_cb;
    storj_finished_upload_cb finished_cb;
    int error_status;
    storj_log_levels_t *log;
    void *handle;
    shard_tracker_t *shard;
    int pending_work_count;
} storj_upload_state_t;

/**
 * @brief Initialize a Storj environment
 *
 * This will setup an event loop for queueing further actions, as well
 * as define necessary configuration options for communicating with Storj
 * bridge, and for encrypting/decrypting files.
 *
 * @param[in] options - Storj Bridge API options
 * @param[in] encrypt_options - File encryption options
 * @param[in] http_options - HTTP settings
 * @param[in] log_options - Logging settings
 * @return A null value on error, otherwise a storj_env pointer.
 */
storj_env_t *storj_init_env(storj_bridge_options_t *options,
                            storj_encrypt_options_t *encrypt_options,
                            storj_http_options_t *http_options,
                            storj_log_options_t *log_options);


/**
 * @brief Destroy a Storj environment
 *
 * This will free all memory for the Storj environment and zero out any memory
 * with sensitive information, such as passwords and encryption keys.
 *
 * The event loop must be closed before this method should be used.
 *
 * @param [in] env
 */
int storj_destroy_env(storj_env_t *env);

/**
 * @brief Will encrypt and write options to disk
 *
 * This will encrypt bridge and encryption options to disk using a key
 * derivation function on a passphrase.
 *
 * @param[in] filepath - The file path to save the options
 * @param[in] passphrase - Used to encrypt options to disk
 * @param[in] bridge_user - The bridge username
 * @param[in] bridge_pass - The bridge password
 * @param[in] mnemonic - The file encryption mnemonic
 * @return A non-zero value on error, zero on success.
 */
int storj_encrypt_write_auth(const char *filepath,
                             const char *passhrase,
                             const char *bridge_user,
                             const char *bridge_pass,
                             const char *mnemonic);


/**
 * @brief Will encrypt options to disk
 *
 * This will encrypt bridge and encryption using a key
 * derivation function on a passphrase.
 *
 * @param[in] passphrase - Used to encrypt options to disk
 * @param[in] bridge_user - The bridge username
 * @param[in] bridge_pass - The bridge password
 * @param[in] mnemonic - The file encryption mnemonic
 * @param[out] buffer - The destination buffer
 * @return A non-zero value on error, zero on success.
 */
int storj_encrypt_auth(const char *passhrase,
                       const char *bridge_user,
                       const char *bridge_pass,
                       const char *mnemonic,
                       char **buffer);

/**
 * @brief Will read and decrypt options from disk
 *
 * This will decrypt bridge and encryption options from disk from
 * the passphrase.
 *
 * @param[in] filepath - The file path to read the options
 * @param[in] passphrase - Used to encrypt options to disk
 * @param[out] bridge_user - The bridge username
 * @param[out] bridge_pass - The bridge password
 * @param[out] mnemonic - The file encryption mnemonic
 * @return A non-zero value on error, zero on success.
 */
int storj_decrypt_read_auth(const char *filepath,
                            const char *passphrase,
                            char **bridge_user,
                            char **bridge_pass,
                            char **mnemonic);

/**
 * @brief Will decrypt options
 *
 * This will decrypt bridge and encryption options using key derived
 * from a passphrase.
 *
 * @param[in] buffer - The encrypted buffer
 * @param[in] passphrase - Used to encrypt options to disk
 * @param[out] bridge_user - The bridge username
 * @param[out] bridge_pass - The bridge password
 * @param[out] mnemonic - The file encryption mnemonic
 * @return A non-zero value on error, zero on success.
 */
int storj_decrypt_auth(const char *buffer,
                       const char *passphrase,
                       char **bridge_user,
                       char **bridge_pass,
                       char **mnemonic);


/**
 * @brief Will get the current unix timestamp in milliseconds
 *
 * @return A unix timestamp
 */
uint64_t storj_util_timestamp();

/**
 * @brief Will generate a new random mnemonic
 *
 * This will generate a new random mnemonic with 128 to 256 bits
 * of entropy.
 *
 * @param[in] strength - The bits of entropy
 * @param[out] buffer - The destination of the mnemonic
 * @return A non-zero value on error, zero on success.
 */
int storj_mnemonic_generate(int strength, char **buffer);

/**
 * @brief Will check that a mnemonic is valid
 *
 * This will check that a mnemonic has been entered correctly by verifying
 * the checksum, and that words are a part of the list.
 *
 * @param[in] strength - The bits of entropy
 * @return Will return true on success and false failure
 */
bool storj_mnemonic_check(const char *mnemonic);

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
 * @param[in] handle A pointer that will be available in the callback
 * @param[in] cb A function called with response when complete
 * @return A non-zero error value on failure and 0 on success.
 */
int storj_bridge_get_info(storj_env_t *env,
                          void *handle,
                          uv_after_work_cb cb);

/**
 * @brief List available buckets for a user.
 *
 * @param[in] env The storj environment struct
 * @param[in] handle A pointer that will be available in the callback
 * @param[in] cb A function called with response when complete
 * @return A non-zero error value on failure and 0 on success.
 */
int storj_bridge_get_buckets(storj_env_t *env,
                             void *handle,
                             uv_after_work_cb cb);

/**
 * @brief Create a bucket.
 *
 * @param[in] env The storj environment struct
 * @param[in] name The name of the bucket
 * @param[in] handle A pointer that will be available in the callback
 * @param[in] cb A function called with response when complete
 * @return A non-zero error value on failure and 0 on success.
 */
int storj_bridge_create_bucket(storj_env_t *env,
                               const char *name,
                               void *handle,
                               uv_after_work_cb cb);

/**
 * @brief Delete a bucket.
 *
 * @param[in] env The storj environment struct
 * @param[in] id The bucket id
 * @param[in] handle A pointer that will be available in the callback
 * @param[in] cb A function called with response when complete
 * @return A non-zero error value on failure and 0 on success.
 */
int storj_bridge_delete_bucket(storj_env_t *env,
                               const char *id,
                               void *handle,
                               uv_after_work_cb cb);

/**
 * @brief Get a list of all files in a bucket.
 *
 * @param[in] env The storj environment struct
 * @param[in] id The bucket id
 * @param[in] handle A pointer that will be available in the callback
 * @param[in] cb A function called with response when complete
 * @return A non-zero error value on failure and 0 on success.
 */
int storj_bridge_list_files(storj_env_t *env,
                            const char *id,
                            void *handle,
                            uv_after_work_cb cb);

/**
 * @brief Create a PUSH or PULL bucket token.
 *
 * @param[in] env The storj environment struct
 * @param[in] bucket_id The bucket id
 * @param[in] operation The type of operation PUSH or PULL
 * @param[in] handle A pointer that will be available in the callback
 * @param[in] cb A function called with response when complete
 * @return A non-zero error value on failure and 0 on success.
 */
int storj_bridge_create_bucket_token(storj_env_t *env,
                                     const char *bucket_id,
                                     storj_bucket_op_t operation,
                                     void *handle,
                                     uv_after_work_cb cb);

/**
 * @brief Get pointers with locations to file shards.
 *
 * @param[in] env The storj environment struct
 * @param[in] bucket_id The bucket id
 * @param[in] file_id The bucket id
 * @param[in] handle A pointer that will be available in the callback
 * @param[in] cb A function called with response when complete
 * @return A non-zero error value on failure and 0 on success.
 */
int storj_bridge_get_file_pointers(storj_env_t *env,
                                   const char *bucket_id,
                                   const char *file_id,
                                   void *handle,
                                   uv_after_work_cb cb);

/**
 * @brief Delete a file in a bucket.
 *
 * @param[in] env The storj environment struct
 * @param[in] bucket_id The bucket id
 * @param[in] file_id The bucket id
 * @param[in] handle A pointer that will be available in the callback
 * @param[in] cb A function called with response when complete
 * @return A non-zero error value on failure and 0 on success.
 */
int storj_bridge_delete_file(storj_env_t *env,
                             const char *bucket_id,
                             const char *file_id,
                             void *handle,
                             uv_after_work_cb cb);

/**
 * @brief Create a file frame
 *
 * @param[in] env The storj environment struct
 * @param[in] handle A pointer that will be available in the callback
 * @param[in] cb A function called with response when complete
 * @return A non-zero error value on failure and 0 on success.
 */
int storj_bridge_create_frame(storj_env_t *env,
                              void *handle,
                              uv_after_work_cb cb);

/**
 * @brief List available file frames
 *
 * @param[in] env The storj environment struct
 * @param[in] handle A pointer that will be available in the callback
 * @param[in] cb A function called with response when complete
 * @return A non-zero error value on failure and 0 on success.
 */
int storj_bridge_get_frames(storj_env_t *env,
                            void *handle,
                            uv_after_work_cb cb);

/**
 * @brief Get information for a file frame
 *
 * @param[in] env The storj environment struct
 * @param[in] frame_id The frame id
 * @param[in] handle A pointer that will be available in the callback
 * @param[in] cb A function called with response when complete
 * @return A non-zero error value on failure and 0 on success.
 */
int storj_bridge_get_frame(storj_env_t *env,
                           const char *frame_id,
                           void *handle,
                           uv_after_work_cb cb);

/**
 * @brief Delete a file frame
 *
 * @param[in] env The storj environment struct
 * @param[in] frame_id The frame id
 * @param[in] handle A pointer that will be available in the callback
 * @param[in] cb A function called with response when complete
 * @return A non-zero error value on failure and 0 on success.
 */
int storj_bridge_delete_frame(storj_env_t *env,
                              const char *frame_id,
                              void *handle,
                              uv_after_work_cb cb);

/**
 * @brief Get metadata for a file
 *
 * @param[in] env The storj environment struct
 * @param[in] bucket_id The bucket id
 * @param[in] file_id The bucket id
 * @param[in] handle A pointer that will be available in the callback
 * @param[in] cb A function called with response when complete
 * @return A non-zero error value on failure and 0 on success.
 */
int storj_bridge_get_file_info(storj_env_t *env,
                               const char *bucket_id,
                               const char *file_id,
                               void *handle,
                               uv_after_work_cb cb);

/**
 * @brief Get mirror data for a file
 *
 * @param[in] env The storj environment struct
 * @param[in] bucket_id The bucket id
 * @param[in] file_id The bucket id
 * @param[in] handle A pointer that will be available in the callback
 * @param[in] cb A function called with response when complete
 * @return A non-zero error value on failure and 0 on success.
 */
int storj_bridge_list_mirrors(storj_env_t *env,
                              const char *bucket_id,
                              const char *file_id,
                              void *handle,
                              uv_after_work_cb cb);

/**
 * @brief Will cancel an upload
 *
 * @param[in] state A pointer to the the upload state
 * @return A non-zero error value on failure and 0 on success.
 */
int storj_bridge_store_file_cancel(storj_upload_state_t *state);

/**
 * @brief Upload a file
 *
 * @param[in] env A pointer to environment
 * @param[in] state A pointer to the the upload state
 * @param[in] opts The options for the upload
 * @param[in] handle A pointer that will be available in the callback
 * @param[in] progress_cb Function called with progress updates
 * @param[in] finished_cb Function called when download finished
 * @return A non-zero error value on failure and 0 on success.
 */
int storj_bridge_store_file(storj_env_t *env,
                            storj_upload_state_t *state,
                            storj_upload_opts_t *opts,
                            void *handle,
                            storj_progress_cb progress_cb,
                            storj_finished_upload_cb finished_cb);


/**
 * @brief Will cancel a download
 *
 * @param[in] state A pointer to the the download state
 * @return A non-zero error value on failure and 0 on success.
 */
int storj_bridge_resolve_file_cancel(storj_download_state_t *state);

/**
 * @brief Download a file
 *
 * @param[in] env A pointer to environment
 * @param[in] state A pointer to the the download state
 * @param[in] bucket_id Character array of bucket id
 * @param[in] file_id Character array of file id
 * @param[in] destination File descriptor of the destination
 * @param[in] handle A pointer that will be available in the callback
 * @param[in] progress_cb Function called with progress updates
 * @param[in] finished_cb Function called when download finished
 * @return A non-zero error value on failure and 0 on success.
 */
int storj_bridge_resolve_file(storj_env_t *env,
                              storj_download_state_t *state,
                              const char *bucket_id,
                              const char *file_id,
                              FILE *destination,
                              void *handle,
                              storj_progress_cb progress_cb,
                              storj_finished_download_cb finished_cb);

/**
 * @brief Register a user
 *
 * @param[in] env The storj environment struct
 * @param[in] email the user's email
 * @param[in] password the user's password
 * @param[in] handle A pointer that will be available in the callback
 * @param[in] cb A function called with response when complete
 * @return A non-zero error value on failure and 0 on success.
 */
int storj_bridge_register(storj_env_t *env,
                          const char *email,
                          const char *password,
                          void *handle,
                          uv_after_work_cb cb);

static inline char separator()
{
#ifdef _WIN32
    return '\\';
#else
    return '/';
#endif
}

#ifdef __cplusplus
}
#endif

#endif /* STORJ_H */
