#include "http.h"

// TODO error check the calloc and realloc calls

static size_t body_shard_send(void *buffer, size_t size, size_t nmemb,
                              void *userp)
{
    shard_body_send_t *body = userp;

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

    if (http_options->proxy_url) {
        curl_easy_setopt(curl, CURLOPT_PROXY, http_options->proxy_url);
    }

    curl_easy_setopt(curl, CURLOPT_POST, 1);

    struct curl_slist *content_chunk = NULL;
    content_chunk = curl_slist_append(content_chunk, "Content-Type: application/octet-stream");
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, content_chunk);

    struct curl_slist *node_chunk = NULL;
    char *header = calloc(17 + 40 + 1, sizeof(char));
    strcat(header, "x-storj-node-id: ");
    strncat(header, farmer_id, 40);
    node_chunk = curl_slist_append(node_chunk, header);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, node_chunk);

    shard_body_send_t *shard_body = NULL;

    if (shard_data && shard_total_bytes) {

        shard_body = malloc(sizeof(shard_body_send_t));
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
        curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE_LARGE, shard_total_bytes);
    }

    // TODO is this still needed?
#ifdef _WIN32
    signal(WSAECONNRESET, SIG_IGN);
#else
    signal(SIGPIPE, SIG_IGN);
#endif

    int req = curl_easy_perform(curl);

    curl_slist_free_all(content_chunk);
    curl_slist_free_all(node_chunk);
    free(header);

    if (*canceled) {
        goto clean_up;
    }

    if (req != CURLE_OK) {
        // TODO log using logger
        printf("Put shard request error: %s\n", curl_easy_strerror(req));
        return req;
    }

    // set the status code
    long int _status_code;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &_status_code);
    *status_code = (int)_status_code;

clean_up:

    // clean up memory
    if (shard_body) {
        free(shard_body);
    }
    free(url);
    curl_easy_cleanup(curl);

    return 0;
}

static size_t body_shard_receive(void *buffer, size_t size, size_t nmemb,
                                  void *userp)
{
    size_t buflen = size * nmemb;
    shard_body_receive_t *body = (shard_body_receive_t *)userp;

    if (*body->canceled) {
        return CURL_READFUNC_ABORT;
    }

    if (body->length + buflen > body->shard_total_bytes) {
        return CURL_READFUNC_ABORT;
    }

    // Update the hash
    sha256_update(body->sha256_ctx, buflen, (uint8_t *)buffer);

    // Copy the data
    memcpy(body->data + body->length, buffer, buflen);

    body->length += buflen;
    body->bytes_since_progress += buflen;

    // Give progress updates at set interval
    if (body->progress_handle &&
        body->bytes_since_progress > SHARD_PROGRESS_INTERVAL) {
        shard_download_progress_t *progress = body->progress_handle->data;
        progress->bytes = body->length;
        uv_async_send(body->progress_handle);
        body->bytes_since_progress = 0;
    }

    return buflen;
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
    int url_len = strlen(proto) + 3 + strlen(host) + 1 + 10
        + 8 + strlen(shard_hash) + strlen(query_args);
    char *url = calloc(url_len + 1, sizeof(char));
    snprintf(url, url_len, "%s://%s:%i/shards/%s%s", proto, host, port,
             shard_hash, query_args);

    curl_easy_setopt(curl, CURLOPT_URL, url);

    curl_easy_setopt(curl, CURLOPT_HTTPGET, 1);

    // Set the node id header
    struct curl_slist *node_chunk = NULL;
    char *header = calloc(17 + 40 + 1, sizeof(char));
    strcat(header, "x-storj-node-id: ");
    strncat(header, farmer_id, 40);
    node_chunk = curl_slist_append(node_chunk, header);
    free(header);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, node_chunk);

    // Set the body handler
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, body_shard_receive);
    shard_body_receive_t *body = malloc(sizeof(shard_body_receive_t));
    body->data = shard_data;
    body->length = 0;
    body->progress_handle = progress_handle;
    body->shard_total_bytes = shard_total_bytes;
    body->bytes_since_progress = 0;
    body->canceled = canceled;
    body->sha256_ctx = malloc(sizeof(struct sha256_ctx));
    sha256_init(body->sha256_ctx);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)body);

    int req = curl_easy_perform(curl);

    curl_slist_free_all(node_chunk);

    int error_code = 0;

    if (req != CURLE_OK) {
        // TODO include the actual http error code
        error_code = STORJ_FARMER_REQUEST_ERROR;
    }

    // set the status code
    long int _status_code;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &_status_code);
    *status_code = (int)_status_code;

    curl_easy_cleanup(curl);

    free(url);

    if (error_code) {
        free(body->sha256_ctx);
        free(body);
        return error_code;
    }

    if (body->length != shard_total_bytes) {
        free(body->sha256_ctx);
        free(body);
        return STORJ_FARMER_INTEGRITY_ERROR;
    }

    uint8_t *hash_sha256 = calloc(SHA256_DIGEST_SIZE, sizeof(uint8_t));
    sha256_digest(body->sha256_ctx, SHA256_DIGEST_SIZE, hash_sha256);

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

    free(body->sha256_ctx);
    free(body);
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
        progress->bytes = shard_total_bytes;
        uv_async_send(progress_handle);
    }

    return 0;
}

static size_t body_json_send(void *buffer, size_t size, size_t nmemb,
                             void *userp)
{
    http_body_send_t *body = (http_body_send_t *)userp;

    size_t buflen = size * nmemb;

    if (buflen > 0) {
        if (body->remain < buflen) {
            buflen = body->remain;
        }
        memcpy(buffer, body->pnt, buflen);

        body->pnt += buflen;
        body->remain -= buflen;
    }

    return buflen;
}

static size_t body_json_receive(void *buffer, size_t size, size_t nmemb,
                                  void *userp)
{
    size_t buflen = size * nmemb;
    http_body_receive_t *body = (http_body_receive_t *)userp;

    body->data = realloc(body->data, body->length + buflen + 1);
    if (body->data == NULL) {
        return 0;
    }

    memcpy(&(body->data[body->length]), buffer, buflen);

    body->length += buflen;
    body->data[body->length] = 0;

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
        return NULL;
    }
    char *user_pass = NULL;

    // Set the url
    int url_len = strlen(options->proto) + 3 + strlen(options->host) +
        1 + 10 + strlen(path);
    char *url = calloc(url_len + 1, sizeof(char));

    snprintf(url, url_len, "%s://%s:%i%s", options->proto, options->host,
             options->port, path);
    curl_easy_setopt(curl, CURLOPT_URL, url);

    // Set the user agent
    if (http_options->user_agent) {
        curl_easy_setopt(curl, CURLOPT_USERAGENT, http_options->user_agent);
    }

    // Set the HTTP method
    if (0 == strcmp(method, "PUT")) {
        curl_easy_setopt(curl, CURLOPT_PUT, 1);
    } else if (0 == strcmp(method, "POST")) {
        curl_easy_setopt(curl, CURLOPT_POST, 1);
    } else if (0 == strcmp(method, "GET")) {
        curl_easy_setopt(curl, CURLOPT_HTTPGET, 1);
    } else if (0 == strcmp(method, "DELETE")) {
        curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "DELETE");
    } else {
        return NULL;
    }

    // Set the proxy
    if (http_options->proxy_url) {
        curl_easy_setopt(curl, CURLOPT_PROXY, http_options->proxy_url);
    }

    // Setup the body handler
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, body_json_receive);
    http_body_receive_t *body = malloc(sizeof(http_body_receive_t));
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
        user_pass = calloc(user_pass_len + 1, sizeof(char));
        strcat(user_pass, options->user);
        strcat(user_pass, ":");
        strcat(user_pass, pass);

        free(pass);

        curl_easy_setopt(curl, CURLOPT_USERPWD, user_pass);

    }

    struct curl_slist *token_chunk = NULL;
    if (token) {
        char *token_header = calloc(9 + strlen(token) + 1, sizeof(char));
        strcat(token_header, "X-Token: ");
        strcat(token_header, token);
        token_chunk = curl_slist_append(token_chunk, token_header);
        free(token_header);
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, token_chunk);
    }

    // Include body if request body json is provided
    struct curl_slist *json_chunk = NULL;
    http_body_send_t *post_body = NULL;
    if (request_body) {
        const char *req_buf = json_object_to_json_string(request_body);

        json_chunk = curl_slist_append(json_chunk,
                                       "Content-Type: application/json");
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, json_chunk);

        post_body = malloc(sizeof(http_body_send_t));
        post_body->pnt = (char *)req_buf;
        post_body->remain = strlen(req_buf);

        curl_easy_setopt(curl, CURLOPT_READFUNCTION, body_json_send);
        curl_easy_setopt(curl, CURLOPT_READDATA, (void *)post_body);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE_LARGE, strlen(req_buf));
    }

    int req = curl_easy_perform(curl);

    free(url);

    if (token_chunk) {
        curl_slist_free_all(token_chunk);
    }

    if (json_chunk) {
        curl_slist_free_all(json_chunk);
    }

    if (post_body) {
        free(post_body);
    }

    if (user_pass) {
        free(user_pass);
    }

    if (req != CURLE_OK) {
        // TODO check request status
        // TODO get details with curl_easy_strerror(req)
        curl_easy_cleanup(curl);
        return NULL;
    }

    // set the status code
    long int _status_code;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &_status_code);
    *status_code = (int)_status_code;

    json_object *j = json_tokener_parse(body->data);

    curl_easy_cleanup(curl);
    free(body->data);
    free(body);

    return j;
}
