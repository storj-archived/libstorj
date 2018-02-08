/**
 * @file storjapi_callback.h
 * @brief Storj callback library.
 *
 * Implements callback functionality that can be customised for 
 * end user's application
 */

#ifndef CLI_CALLBACK_H
#define CLI_CALLBACK_H

#ifdef __cplusplus
extern "C" {
#endif

#include "storj.h"

#define CLI_NO_SUCH_FILE_OR_DIR   0x00
#define CLI_VALID_REGULAR_FILE    0x01
#define CLI_VALID_DIR             0x02
#define CLI_UNKNOWN_FILE_ATTR     0x03
#define CLI_UPLOAD_FILE_LOG_ERR   0x04

/**
 * @brief Callback function listing bucket names & IDs 
 */
void get_buckets_callback(uv_work_t *work_req, int status);

/**
 * @brief Callback function returning the bucket id for a given
 *        bucket name
 */
void get_bucket_id_callback(uv_work_t *work_req, int status);

/**
 * @brief Storj api state machine function 
 */
void queue_next_cmd_req(storj_api_t *storj_api);

#ifdef __cplusplus
}
#endif

#endif /* CLI_CALLBACK_H */
