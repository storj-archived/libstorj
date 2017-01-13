/**
 * @file http.h
 * @brief Storj HTTP utilities.
 *
 * Helper methods and utilities for http requests.
 */
#ifndef STORJ_HTTP_H
#define STORJ_HTTP_H

#include "storj.h"
#include <neon/ne_request.h>
#include <neon/ne_string.h>

#define SHARD_PROGRESS_INTERVAL NE_BUFSIZ * 150

/** @brief A structure for sharing progress state between threads.
 *
 * This structure is used to send async updates from a worker thread
 * back to the event loop thread, to report the bytes that have been
 * received for a shard.
 */
typedef struct {
    uint32_t pointer_index;
    uint64_t bytes;
    /* state should not be modified in worker threads */
    void *state;
} shard_download_progress_t;

/**
 * @brief Make a HTTP request for a shard
 *
 * @param[in] host The farmer host
 * @param[in] port The farmer port
 * @param[in] shard_hash The hash of the shard to retrieve
 * @param[out] out Target for shard data
 * @return A non-zero error value on failure and 0 on success.
 */
int fetch_shard(storj_http_options_t *http_options,
                char *farmer_id,
                char *proto,
                char *host,
                int port,
                char *shard_hash,
                ssize_t shard_total_bytes,
                char *shard_data,
                char *token,
                int *status_code,
                uv_async_t *progress_handle,
                bool *cancelled);

/**
 * @brief Make a JSON HTTP request
 *
 * @param[in] options The storj bridge options
 * @param[in] method The HTTP method
 * @param[in] path The path of the resource
 * @param[in] request_body A json object of the request body
 * @param[in] auth Boolean to include authentication
 * @param[out] status_code The resulting status code from the request
 * @return A non-zero error value on failure and 0 on success.
 */
struct json_object *fetch_json(storj_http_options_t *http_options,
                               storj_bridge_options_t *options,
                               char *method,
                               char *path,
                               struct json_object *request_body,
                               bool auth,
                               char *token,
                               int *status_code);


#endif /* STORJ_HTTP_H */
