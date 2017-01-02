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

static void queue_next_work(storj_download_state_t *state);

#endif /* STORJ_DOWNLOADER_H */
