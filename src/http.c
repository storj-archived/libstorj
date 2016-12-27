#include <nettle/sha.h>

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

int fetch_shard(char *proto,
                char *host,
                int port,
                char *shard_hash,
                ssize_t shard_total_bytes,
                char *shard_data,
                char *token,
                int *status_code)
{
    // TODO make sure that shard_data has correct number of bytes allocated

    ne_session *sess = ne_session_create(proto, host, port);

    char query_args[80];
    ne_snprintf(query_args, 80, "?token=%s", token);

    char *path = ne_concat("/shards/", shard_hash, query_args, NULL);

    ne_request *req = ne_request_create(sess, "GET", path);

    if (0 == strcmp(proto, "https")) {
        ne_ssl_trust_default_ca(sess);
    }

    if (ne_begin_request(req) != NE_OK) {
        clean_up_neon(sess, req);
        // TODO enum error types: REQUEST_FAILURE
        return -1;
    }

    *status_code = ne_get_status(req)->code;

    char *buf = calloc(NE_BUFSIZ, sizeof(char));

    ssize_t bytes = 0;
    ssize_t total = 0;

    while ((bytes = ne_read_response_block(req, buf, NE_BUFSIZ)) > 0) {
        if (total + bytes > shard_total_bytes) {
            // TODO error enum types: SHARD_INTEGRITY
            return -1;
        }

        memcpy(shard_data + total, buf, bytes);
        total += bytes;
    }

    if (bytes == 0) {
        ne_end_request(req);
    }

    if (total != shard_total_bytes) {
        // TODO error enum types: SHARD_INTEGRITY
        return -1;
    }

    clean_up_neon(sess, req);
    free(buf);

    return 0;
}

struct json_object *fetch_json(storj_bridge_options_t *options,
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
        sha256_update(&ctx, strlen(options->pass), options->pass);
        sha256_digest(&ctx, SHA256_DIGEST_SIZE, pass_hash);
        for (unsigned i = 0; i < SHA256_DIGEST_SIZE; i++) {
            sprintf(&pass[i*2], "%02x", pass_hash[i]);
        }

        char *user_pass = ne_concat(options->user, ":", pass, NULL);
        char *user_pass_64 = ne_base64((uint8_t *)user_pass, strlen(user_pass));

        int auth_value_len = strlen(user_pass_64) + 6;
        char auth_value[auth_value_len + 1];
        strcpy(auth_value, "Basic ");
        strcat(auth_value, user_pass_64);
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

    if (ne_begin_request(req) != NE_OK) {
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

    while (bytes = ne_read_response_block(req, buf, NE_BUFSIZ)) {
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
