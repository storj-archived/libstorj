#include <nettle/sha.h>
#include <nettle/ripemd160.h>

#include "http.h"

// TODO error check the calloc and realloc calls

static void clean_up_neon(ne_session *s, ne_request *r)
{
    // Destroy the request
    ne_request_destroy(r);

    // Must not be called if there is a request active
    ne_close_connection(s);

    // Must not be called until all requests have been destroy
    ne_session_destroy(s);
}

int put_shard(storj_http_options_t *http_options,
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
              bool *canceled)
{

    ne_session *sess = ne_session_create(proto, host, port);

    if (http_options->user_agent) {
        ne_set_useragent(sess, http_options->user_agent);
    }

    if (http_options->proxy_version &&
        http_options->proxy_host &&
        http_options->proxy_port) {

        ne_session_socks_proxy(sess,
                               (enum ne_sock_sversion)http_options->proxy_version,
                               http_options->proxy_host,
                               http_options->proxy_port,
                               "",
                               "");
    }

    char query_args[80];
    ne_snprintf(query_args, 80, "?token=%s", token);

    char *path = ne_concat("/shards/", shard_hash, query_args, NULL);

    ne_request *req = ne_request_create(sess, "POST", path);

    ne_add_request_header(req, "x-storj-node-id", farmer_id);

    if (0 == strcmp(proto, "https")) {
        ne_ssl_trust_default_ca(sess);
    }

    if (shard_data && shard_total_bytes) {
        ne_add_request_header(req, "Content-Type", "application/octet-stream");
        ne_set_request_body_buffer(req, shard_data, shard_total_bytes);
    }

    signal(SIGPIPE, SIG_IGN);

    int request_status = ne_request_dispatch(req);

    if (request_status != NE_OK) {
        return request_status;
    }

    // set the status code
    *status_code = ne_get_status(req)->code;

    // clean up memory
    free(path);
    clean_up_neon(sess, req);

    return 0;
}

/* shard_data must be allocated for shard_total_bytes */
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
                bool *canceled)
{
    struct sha256_ctx ctx;
    sha256_init(&ctx);

    ne_session *sess = ne_session_create(proto, host, port);

    if (http_options->user_agent) {
        ne_set_useragent(sess, http_options->user_agent);
    }

    if (http_options->proxy_version &&
        http_options->proxy_host &&
        http_options->proxy_port) {

        ne_session_socks_proxy(sess,
                               (enum ne_sock_sversion)http_options->proxy_version,
                               http_options->proxy_host,
                               http_options->proxy_port,
                               "",
                               "");
    }

    char query_args[80];
    ne_snprintf(query_args, 80, "?token=%s", token);

    char *path = ne_concat("/shards/", shard_hash, query_args, NULL);

    ne_request *req = ne_request_create(sess, "GET", path);

    ne_add_request_header(req, "x-storj-node-id", farmer_id);

    if (0 == strcmp(proto, "https")) {
        ne_ssl_trust_default_ca(sess);
    }

    if (ne_begin_request(req) != NE_OK) {
        clean_up_neon(sess, req);
        return STORJ_FARMER_REQUEST_ERROR;
    }

    *status_code = ne_get_status(req)->code;

    char *buf = calloc(NE_BUFSIZ, sizeof(char));

    ssize_t bytes = 0;
    ssize_t total = 0;

    ssize_t bytes_since_progress = 0;

    int error_code = 0;

    while ((bytes = ne_read_response_block(req, buf, NE_BUFSIZ)) > 0) {
        if (total + bytes > shard_total_bytes) {
            error_code = STORJ_FARMER_INTEGRITY_ERROR;
            break;
        }

        sha256_update(&ctx, bytes, (uint8_t *)buf);

        memcpy(shard_data + total, buf, bytes);
        total += bytes;

        bytes_since_progress += bytes;

        // give progress updates at set interval
        if (progress_handle && bytes_since_progress > SHARD_PROGRESS_INTERVAL) {
            shard_download_progress_t *progress = progress_handle->data;
            progress->bytes = total;
            uv_async_send(progress_handle);
            bytes_since_progress = 0;
        }

        if (*canceled) {
            error_code = STORJ_TRANSFER_CANCELED;
            break;
        }

    }

    ne_end_request(req);
    clean_up_neon(sess, req);
    free(buf);
    free(path);

    if (!error_code && total != shard_total_bytes) {
        error_code = STORJ_FARMER_INTEGRITY_ERROR;
    }

    if (error_code) {
        return error_code;
    }

    uint8_t *hash_sha256 = calloc(SHA256_DIGEST_SIZE, sizeof(uint8_t));
    sha256_digest(&ctx, SHA256_DIGEST_SIZE, hash_sha256);

    struct ripemd160_ctx rctx;
    ripemd160_init(&rctx);
    ripemd160_update(&rctx, SHA256_DIGEST_SIZE, hash_sha256);

    free(hash_sha256);

    uint8_t *hash_rmd160 = calloc(RIPEMD160_DIGEST_SIZE + 1, sizeof(uint8_t));
    ripemd160_digest(&rctx, RIPEMD160_DIGEST_SIZE, hash_rmd160);

    char *hash = calloc(RIPEMD160_DIGEST_SIZE * 2 + 1, sizeof(char));
    for (unsigned i = 0; i < RIPEMD160_DIGEST_SIZE; i++) {
        sprintf(&hash[i*2], "%02x", hash_rmd160[i]);
    }

    free(hash_rmd160);

    if (strcmp(shard_hash, hash) != 0) {
        error_code = STORJ_FARMER_INTEGRITY_ERROR;
    }

    free(hash);

    if (error_code) {
        return error_code;
    }

    // final progress update
    if (progress_handle) {
        shard_download_progress_t *progress = progress_handle->data;
        progress->bytes = total;
        uv_async_send(progress_handle);
    }

    return 0;
}

struct json_object *fetch_json(storj_http_options_t *http_options,
                               storj_bridge_options_t *options,
                               char *method,
                               char *path,
                               struct json_object *request_body,
                               bool auth,
                               char *token,
                               int *status_code)
{
    // TODO: reuse an existing session and socket to the bridge

    ne_session *sess = ne_session_create(options->proto, options->host,
                                         options->port);

    if (http_options->user_agent) {
        ne_set_useragent(sess, http_options->user_agent);
    }

    if (http_options->proxy_version &&
        http_options->proxy_host &&
        http_options->proxy_port) {

        ne_session_socks_proxy(sess,
                               (enum ne_sock_sversion)http_options->proxy_version,
                               http_options->proxy_host,
                               http_options->proxy_port,
                               "",
                               "");
    }

    // TODO: error check the ne calls in this function

    if (0 == strcmp(options->proto, "https")) {
        ne_ssl_trust_default_ca(sess);
    }

    ne_request *req = ne_request_create(sess, method, path);

    // include authentication headers if info is provided
    if (auth && options->user && options->pass) {
        // Hash password
        uint8_t *pass_hash = calloc(SHA256_DIGEST_SIZE, sizeof(uint8_t));
        char *pass = calloc(SHA256_DIGEST_SIZE * 2 + 1, sizeof(char));
        struct sha256_ctx ctx;
        sha256_init(&ctx);
        sha256_update(&ctx, strlen(options->pass), (uint8_t *)options->pass);
        sha256_digest(&ctx, SHA256_DIGEST_SIZE, pass_hash);
        for (unsigned i = 0; i < SHA256_DIGEST_SIZE; i++) {
            sprintf(&pass[i*2], "%02x", pass_hash[i]);
        }

        free(pass_hash);

        char *user_pass = ne_concat(options->user, ":", pass, NULL);

        free(pass);

        char *user_pass_64 = ne_base64((uint8_t *)user_pass, strlen(user_pass));

        free(user_pass);

        int auth_value_len = strlen(user_pass_64) + 6;
        char auth_value[auth_value_len + 1];
        strcpy(auth_value, "Basic ");
        strcat(auth_value, user_pass_64);

        free(user_pass_64);

        auth_value[auth_value_len] = '\0';

        ne_add_request_header(req, "Authorization", auth_value);
    }

    if (token) {
        ne_add_request_header(req, "X-Token", token);
    }

    // include body if request body json is provided
    if (request_body) {
        const char *req_buf = json_object_to_json_string(request_body);

        ne_add_request_header(req, "Content-Type", "application/json");
        ne_set_request_body_buffer(req, req_buf, strlen(req_buf));
    }

    int request_status = 0;
    if ((request_status = ne_begin_request(req)) != NE_OK) {
        // TODO check request status
        // TODO get details if NE_ERROR(1) with ne_get_error(sess)
        clean_up_neon(sess, req);
        return NULL;
    }

    // set the status code
    *status_code = ne_get_status(req)->code;

    int body_sz = NE_BUFSIZ * 4;
    char *body = calloc(NE_BUFSIZ * 4, sizeof(char));
    char *buf = calloc(NE_BUFSIZ, sizeof(char));

    ssize_t bytes = 0;
    ssize_t total = 0;

    while ((bytes = ne_read_response_block(req, buf, NE_BUFSIZ))) {
        if (bytes < 0) {
            // TODO: error. careful with cleanup
        }

        if (total + bytes + 1 > body_sz) {
            body_sz += bytes + 1;
            body = (char *) realloc(body, body_sz);
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
