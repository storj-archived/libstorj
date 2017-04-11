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

#define STORJ_DOWNLOAD_CONCURRENCY 24
#define STORJ_DOWNLOAD_WRITESYNC_CONCURRENCY 4
#define STORJ_DEFAULT_MIRRORS 5
#define STORJ_MAX_REPORT_TRIES 2
#define STORJ_MAX_TOKEN_TRIES 3
#define STORJ_MAX_POINTER_TRIES 2
#define STORJ_MAX_INFO_TRIES 6

/** @brief Enumerable that defines that status of a pointer
 *
 * A pointer will begin as created, and move forward until an error
 * occurs, in which case it will start moving backwards from the error
 * state until it has been replaced and reset back to created. This process
 * can continue until success.
 */
typedef enum {
    POINTER_MISSING_RECOVERY = -5,
    POINTER_MISSING = -4,
    POINTER_BEING_REPLACED = -3,
    POINTER_ERROR_REPORTED = -2,
    POINTER_ERROR = -1,
    POINTER_CREATED = 0,
    POINTER_BEING_DOWNLOADED = 1,
    POINTER_DOWNLOADED = 2,
    POINTER_BEING_WRITTEN = 3,
    POINTER_WRITTEN = 4
} storj_pointer_status_t;

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
    storj_http_options_t *http_options;
    char *farmer_id;
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
    bool write_async;
    char *shard_data;
    /* state should not be modified in worker threads */
    storj_download_state_t *state;
    int error_status;
    bool *canceled;
} shard_request_download_t;

/** @brief A structure for sharing data with worker threads for sending
 * exchange reports to the bridge.
 */
typedef struct {
    uint32_t pointer_index;
    storj_http_options_t *http_options;
    storj_bridge_options_t *options;
    int status_code;
    storj_exchange_report_t *report;
    /* state should not be modified in worker threads */
    storj_download_state_t *state;
} shard_send_report_t;

typedef struct {
    storj_http_options_t *http_options;
    storj_bridge_options_t *options;
    int status_code;
    const char *bucket_id;
    const char *file_id;
    int error_status;
    storj_file_meta_t *info;
    /* state should not be modified in worker threads */
    storj_download_state_t *state;
} file_info_request_t;

/** @brief A structure for sharing data with worker threads for replacing a
 * pointer with a new farmer.
 */
typedef struct {
    storj_http_options_t *http_options;
    storj_bridge_options_t *options;
    uint32_t pointer_index;
    char *token;
    const char *bucket_id;
    const char *file_id;
    char *excluded_farmer_ids;
    /* state should not be modified in worker threads */
    storj_download_state_t *state;
    struct json_object *response;
    int error_status;
    int status_code;
} json_request_replace_pointer_t;

/** @brief A structure for sharing data with worker threads for making JSON
 * requests with the bridge.
 */
typedef struct {
    storj_http_options_t *http_options;
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
    storj_http_options_t *http_options;
    storj_bridge_options_t *options;
    char *token;
    const char *bucket_id;
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
