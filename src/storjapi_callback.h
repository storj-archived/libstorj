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
 * @brief Get bucket id by bucket name 
 *
 * @param[in] env The storj environment struct
 * @param[in] email the user's email
 * @param[in] password the user's password
 * @param[in] handle A pointer that will be available in the callback
 * @param[in] cb A function called with response when complete
 * @return A non-zero error value on failure and 0 on success.
 */
void get_bucket_id_callback(uv_work_t *work_req, int status);

/**
 * @brief Get bucket id by bucket name 
 *
 * @param[in] env The storj environment struct
 * @param[in] email the user's email
 * @param[in] password the user's password
 * @param[in] handle A pointer that will be available in the callback
 * @param[in] cb A function called with response when complete
 * @return A non-zero error value on failure and 0 on success.
 */
void list_files_callback(uv_work_t *work_req, int status);

/**
 * @brief Get bucket id by bucket name 
 *
 * @param[in] env The storj environment struct
 * @param[in] email the user's email
 * @param[in] password the user's password
 * @param[in] handle A pointer that will be available in the callback
 * @param[in] cb A function called with response when complete
 * @return A non-zero error value on failure and 0 on success.
 */
void queue_next_cmd_req(storj_api_t *storj_api);




#ifdef __cplusplus
}
#endif

#endif /* STORJ_H */
