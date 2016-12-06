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
struct json_object *fetch_json(storj_bridge_options_t *options,
                               char *method,
                               char *path,
                               struct json_object *request_body,
                               storj_boolean_t auth,
                               int **status_code);


#endif /* STORJ_HTTP_H */
