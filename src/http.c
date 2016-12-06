#include "http.h"

static void clean_up_neon(ne_session *s, ne_request *r)
{
    // Destroy the request
    ne_request_destroy(r);

    // Must not be called if there is a request active
    ne_close_connection(s);

    // Must not be called until all requests have been destroy
    ne_session_destroy(s);
}

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
struct json_object *fetch_json(storj_bridge_options_t *options,
                               char *method,
                               char *path,
                               struct json_object *request_body,
                               storj_boolean_t auth,
                               int **status_code)
{
    ne_session *sess = ne_session_create(options->proto, options->host,
                                         options->port);

    //
    // TODO: error check the ne calls in this function
    //

    if (0 == strcmp(options->proto, "https")) {
        ne_ssl_trust_default_ca(sess);
    }

    ne_request *req = ne_request_create(sess, method, path);

    // include authentication headers if info is provided
    if (auth && options->user && options->pass) {
        char *user_pass = ne_concat(options->user, ":", options->pass, NULL);
        char *user_pass_64 = ne_base64((unsigned char *)user_pass, strlen(user_pass));
        char *auth_value = ne_concat("Basic ", user_pass_64, NULL);

        ne_add_request_header(req, "Authorization", auth_value);
    }

    // include body if request body json is provided
    if (request_body) {
        const char *req_buf = json_object_to_json_string(request_body);

        ne_add_request_header(req, "Content-Type", "application/json");
        ne_set_request_body_buffer(req, req_buf, strlen(req_buf));
    }

    if (ne_begin_request(req) != NE_OK) {
        printf("Request failed: %s\n", ne_get_error(sess));
        // FIXME: we should standardize how we want to write out errors.
        // And do we want to return an object here or bail?
        clean_up_neon(sess, req);
        return NULL;
    }

    // set the status code
    *status_code = ne_get_status(req)->code;

    // Note: NE_BUFSIZ is from ne_defs.h. Should be okay to use.
    int body_sz = NE_BUFSIZ * 4;
    char *body  = calloc(NE_BUFSIZ * 4, sizeof(char));
    char *buf   = calloc(NE_BUFSIZ, sizeof(char));
    // TODO error check the calloc
    ssize_t bytes = 0;
    ssize_t total = 0;

    while (bytes = ne_read_response_block(req, buf, NE_BUFSIZ)) {
        if (bytes < 0) {
            // TODO: error. careful with cleanup
        }

        if (total + bytes + 1 > body_sz) {
            body_sz += bytes + 1;
            body = (char *) realloc(body, body_sz);
            // TODO error check realloc call
        }

        memcpy(body + total, buf, bytes);
        total += bytes;
    }

    clean_up_neon(sess, req);

    json_object *j = json_tokener_parse(body);
    // TODO: Error checking

    free(body);
    free(buf);

    return j;
}
