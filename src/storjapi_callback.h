/**
 * @file storjapi_callback.h
 * @brief Storj callback library.
 *
 * Implements callback functionality that can be customised for 
 * end user's application
 */

#ifndef STORJAPI_CALLBACK_H
#define STORJAPI_CALLBACK_H

#ifdef __cplusplus
extern "C" {
#endif

#include "storj.h"

/**
 * @brief Callback function returning the bucket id for a given
 *        bucket name
 */
void get_bucket_id_callback(uv_work_t *work_req, int status);

/**
 * @brief Callback function listing the files in a given bucket
 *
 */
void list_files_callback(uv_work_t *work_req, int status);

/**
 * @brief Storj api state machine function 
 */
void queue_next_cmd_req(storj_api_t *storj_api);




#ifdef __cplusplus
}
#endif

#endif /* STORJ_H */
