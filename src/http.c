#include <nettle/sha.h>
#include <nettle/ripemd160.h>

#include "http.h"

// TODO error check the calloc and realloc calls

static size_t body_shard_send(void *buffer, size_t size, size_t nmemb,
                              void *userp)
{
    shard_body_t *body = userp;

    if (*body->canceled) {
        return CURL_READFUNC_ABORT;
    }

    size_t buflen = size * nmemb;

    if (buflen > 0) {
        if (body->remain < buflen) {
            buflen = body->remain;
        }
        memcpy(buffer, body->pnt, buflen);

        body->pnt += buflen;
        body->total_sent += buflen;
        body->bytes_since_progress += buflen;

        body->remain -= buflen;
    }

    // give progress updates at set interval
    if (body->progress_handle && buflen &&
        (body->bytes_since_progress > SHARD_PROGRESS_INTERVAL ||
         body->remain == 0)) {

        shard_upload_progress_t *progress = body->progress_handle->data;
        progress->bytes = body->total_sent;
        uv_async_send(body->progress_handle);

        body->bytes_since_progress = 0;
    }

    return buflen;
}

int put_shard(storj_http_options_t *http_options,
              char *farmer_id,
              char *proto,
              char *host,
              int port,
              char *shard_hash,
              uint64_t shard_total_bytes,
              uint8_t *shard_data,
              char *token,
              int *status_code,
              uv_async_t *progress_handle,
              bool *canceled)
{

    CURL *curl = curl_easy_init();
    if (!curl) {
        return 1;
    }

    char query_args[80];
    snprintf(query_args, 80, "?token=%s", token);

    int url_len = strlen(proto) + 3 + strlen(host) + 1 + 10 + 8
        + strlen(shard_hash) + strlen(query_args);
    char *url = calloc(url_len + 1, sizeof(char));

    snprintf(url, url_len, "%s://%s:%i/shards/%s%s", proto, host, port,
             shard_hash, query_args);

    curl_easy_setopt(curl, CURLOPT_URL, url);

    if (http_options->user_agent) {
        curl_easy_setopt(curl, CURLOPT_USERAGENT, http_options->user_agent);
    }

    int proxy_len = strlen(http_options->proxy_version) + 3 +
        stlen(http_options->proxy_host) + 1 + 10;

    char *proxy = calloc(proxy_len + 1, sizeof(char));
    snprintf(proxy, proxy_len, "%s://");

    if (http_options->proxy_url) {
        curl_easy_setopt(curl, CURLOPT_PROXY, http_options->proxy_url);
    }

    //curl_easy_setopt(curl, CURLOPT_POST, 1);

    struct curl_slist *content_chunk = NULL;
    content_chunk = curl_slist_append(content_chunk, "Content-Type: application/octet-stream");
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, content_chunk);

    struct curl_slist *node_chunk = NULL;
    char *header = calloc(17 + 40 + 1, sizeof(char));
    strcat(header, "x-storj-node-id: ");
    strncat(header, farmer_id, 40);
    chunk = curl_slist_append(node_chunk, header);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, chunk);

    shard_body_t *shard_body = NULL;

    if (shard_data && shard_total_bytes) {

        shard_body = malloc(sizeof(shard_body_t));
        shard_body->shard_data = shard_data;
        shard_body->length = shard_total_bytes;
        shard_body->remain = shard_total_bytes;
        shard_body->pnt = shard_data;
        shard_body->total_sent = 0;
        shard_body->bytes_since_progress = 0;
        shard_body->progress_handle = progress_handle;
        shard_body->canceled = canceled;

        curl_easy_setopt(curl, CURLOPT_READFUNCTION, body_shard_send);
        curl_easy_setopt(curl, CURLOPT_READDATA, (void *)shard_body);
    }

#ifdef _WIN32
    signal(WSAECONNRESET, SIG_IGN);
#else
    signal(SIGPIPE, SIG_IGN);
#endif

    int req = curl_easy_perform(curl);

    if (*canceled) {
        goto clean_up;
    }

    if (req != CURLE_OK) {
        // TODO log using logger
        printf("Put shard request error: %s\n", curl_easy_strerror(req));
        return req;
    }

    // set the status code
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, *status_code);

clean_up:

    // clean up memory
    if (shard_body) {
        free(shard_body);
    }
    free(path);
    curl_easy_cleanup(curl);

    return 0;
}

/* shard_data must be allocated for shard_total_bytes */
int fetch_shard(storj_http_options_t *http_options,
                char *farmer_id,
                char *proto,
                char *host,
                int port,
                char *shard_hash,
                uint64_t shard_total_bytes,
                char *shard_data,
                char *token,
                int *status_code,
                uv_async_t *progress_handle,
                bool *canceled)
{
    struct sha256_ctx ctx;
    sha256_init(&ctx);

    CURL *curl = curl_easy_init();
    if (!curl) {
        return 1;
    }

    if (http_options->user_agent) {
        curl_easy_setopt(curl, CURLOPT_USERAGENT, http_options->user_agent);
    }

    if (http_options->proxy_url) {
        curl_easy_setopt(curl, CURLOPT_PROXY, http_options->proxy_url);
    }

    char query_args[80];
    snprintf(query_args, 80, "?token=%s", token);

    char *path = calloc(8 + strlen(shard_hash) + strlen(query_args) + 1);
    strcat(path, "/shards/");
    strcat(path, shard_hash);
    strcat(path, query_args);

    //ne_request *req = ne_request_create(sess, "GET", path);

    struct curl_slist *node_chunk = NULL;
    char *header = calloc(17 + 40 + 1, sizeof(char));
    strcat(header, "x-storj-node-id: ");
    strncat(header, farmer_id, 40);
    chunk = curl_slist_append(node_chunk, header);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, chunk);

    int req = curl_easy_perform(curl);

    if (req != CURLE_OK) {
        curl_easy_cleanup(curl);
        return STORJ_FARMER_REQUEST_ERROR;
    }

    // Set the status code
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, *status_code);


    // TODO XXX
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

static size_t body_memory_receive(void *buffer, size_t size, size_t nmemb,
                                  void *userp)
{
    size_t buflen = size * nmemb;
    http_body_t *body = (http_body_t *)userp;

    body->data = realloc(body->data, body->length + buflen + 1);
    if (body->data == NULL) {
        return 0;
    }

    memcpy(&(mem->data[mem->length]), buffer, buflen);

    body->length += buflen;
    body>data[mem->length] = 0;

    return buflen;
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

    CURL *curl = curl_easy_init();
    if (!curl) {
        return 1;
    }

    // Set the url
    int url_len = strlen(options->proto) + 3 + strlen(options->host) +
        1 + 10 + 1 + strlen(path);
    char *url = calloc(url_len + 1, sizeof(char));
    snprintf(url, url_len, "%s://%s:%i/%s", options->proto, options->host,
             options->port, path);
    curl_easy_setopt(curl, CURLOPT_URL, url);

    // Set the user agent
    if (http_options->user_agent) {
        curl_easy_setopt(curl, CURLOPT_USERAGENT, http_options->user_agent);
    }

    // Set the proxy
    if (http_options->proxy_url) {
        curl_easy_setopt(curl, CURLOPT_PROXY, http_options->proxy_url);
    }

    // Setup the body handler
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, body_memory_receive);
    http_body_t *body = malloc(sizeof(http_body_t));
    body->data = NULL;
    body->length = 0;
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)body);

    // Include authentication headers if info is provided
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

        int user_pass_len = strlen(options->user) + 1 + strlen(pass);
        char *user_pass = calloc(user_pass_len + 1, sizeof(char));
        strcat(user_pass, options->user);
        strcat(user_pass, ":");

        free(pass);

        // TODO fix this XXX
        char *user_pass_64 = curl_base64_encode((uint8_t *)user_pass, strlen(user_pass));

        free(user_pass);

        int auth_value_len = strlen(user_pass_64) + 6;
        char auth_value[auth_value_len + 1];
        strcpy(auth_value, "Authorization: Basic ");
        strcat(auth_value, user_pass_64);

        free(user_pass_64);

        auth_value[auth_value_len] = '\0';

        struct curl_slist *auth_chunk = NULL;
        auth_chunk = curl_slist_append(auth_chunk, auth_value);
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, auth_chunk);
    }

    if (token) {
        struct curl_slist *token_chunk = NULL;
        char *token_header = calloc(9 + strlen(token) + 1, sizeof(char));
        strcat(token_header, "X-Token: ");
        strcat(token_header, token);
        token_chunk = curl_slist_append(token_chunk, token_header);
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, token_chunk);
    }

    // Include body if request body json is provided
    if (request_body) {
        const char *req_buf = json_object_to_json_string(request_body);


        struct curl_slist *json_chunk = NULL;
        json_chunk = curl_slist_append(json_chunk,
                                       "Content-Type: application/json");
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, json_chunk);

        // TODO XXX
        ne_set_request_body_buffer(req, req_buf, strlen(req_buf));
    }

    int req = curl_easy_perform(curl);

    if (req != CURLE_OK) {
        // TODO check request status
        // TODO get details with curl_easy_strerror(req)
        curl_easy_cleanup(curl);
        return NULL;
    }

    // set the status code
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, *status_code);

    json_object *j = json_tokener_parse(body->data);

    curl_easy_cleanup(curl);
    free(body);

    return j;
}
