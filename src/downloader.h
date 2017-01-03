/**
 * @file downloader.h
 * @brief Storj download methods and definitions.
 *
 * Structures and functions useful for downloading files.
 */
#ifndef STORJ_DOWNLOADER_H
#define STORJ_DOWNLOADER_H

#include "storj.h"
#include "http.h"
#include "utils.h"
#include "crypto.h"

#define STORJ_DOWNLOAD_CONCURRENCY 4
#define STORJ_DEFAULT_MIRRORS 5
#define STORJ_MAX_REPORT_TRIES 2
#define STORJ_MAX_TOKEN_TRIES 3
#define STORJ_MAX_POINTER_TRIES 2

/** @brief Enumerable that defines that status of a pointer
 *
 * A pointer will begin as created, and move forward until an error
 * occurs, in which case it will start moving backwards from the error
 * state until it has been replaced and reset back to created. This process
 * can continue until success.
 */
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

/** @brief A structure that keeps state between multiple worker threads.
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
    uint32_t pointer_fail_count;
    bool requesting_pointers;
    int error_status;
    bool writing;
    char *token;
    bool requesting_token;
    uint32_t token_fail_count;
    uint8_t *decrypt_key;
    uint8_t *decrypt_ctr;
} storj_download_state_t;

/** @brief A structure for sharing data with worker threads for writing
 * a shard to a file decriptor.
 */
typedef struct {
    char *shard_data;
    ssize_t shard_total_bytes;
    int error_status;
    FILE *destination;
    uint32_t pointer_index;
    /* state should not be modified in worker threads */
    storj_download_state_t *state;
} shard_request_write_t;

/** @brief A structure for sharing data with worker threads for downloading
 * shards from farmers.
 */
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

/** @brief A structure for sharing data with worker threads for sending
 * exchange reports to the bridge.
 */
typedef struct {
    uint32_t pointer_index;
    storj_bridge_options_t *options;
    int status_code;
    storj_exchange_report_t *report;
    /* state should not be modified in worker threads */
    storj_download_state_t *state;
} shard_send_report_t;

/** @brief A structure for sharing data with worker threads for replacing a
 * pointer with a new farmer.
 */
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

/** @brief A structure for sharing data with worker threads for making JSON
 * requests with the bridge.
 */
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

/** @brief A structure for sharing data with worker threads for requesting
 * a bucket operation token from the bridge.
 */
typedef struct {
    storj_bridge_options_t *options;
    char *token;
    char *bucket_id;
    char *bucket_op;
    /* state should not be modified in worker threads */
    storj_download_state_t *state;
    int status_code;
    int error_status;
} token_request_download_t;

/** @brief A method that determines the next work necessary to download a file
 *
 * This method is called after each individual work is complete, and will
 * determine and queue the next set of work that needs to be completed. Once
 * the file is completely downloaded, it will call the finished callback.
 *
 * This method should only be called with in the main loop thread.
 */
static void queue_next_work(storj_download_state_t *state);

#endif /* STORJ_DOWNLOADER_H */
