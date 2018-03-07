#include "http.h"

static size_t body_ignore_receive(void *buffer, size_t size, size_t nmemb,
                                  void *userp)
{
    size_t buflen = size * nmemb;
    return buflen;
}

static size_t body_shard_send(void *buffer, size_t size, size_t nmemb,
                              void *userp)
{
    shard_body_send_t *body = userp;

    if (*body->canceled) {
        return CURL_READFUNC_ABORT;
    }

    size_t read_bytes = 0;
    size_t buflen = size * nmemb / AES_BLOCK_SIZE * AES_BLOCK_SIZE;
    uint8_t clr_txt[buflen];
    memset_zero(clr_txt, buflen);

    if (buflen > 0) {
        if (body->remain < buflen) {
            buflen = body->remain;
        }

        // Read shard data from file
        read_bytes = pread(fileno(body->fd), clr_txt, buflen, body->offset + body->total_sent);
        if (read_bytes == -1) {
            body->error_code = errno;
            return CURL_READFUNC_ABORT;
        }

        if (body->ctx != NULL) {
            ctr_crypt(body->ctx->ctx, (nettle_cipher_func *)aes256_encrypt,
                      AES_BLOCK_SIZE, body->ctx->encryption_ctr, read_bytes,
                      (uint8_t *)buffer, (uint8_t *)clr_txt);
        } else {
            memcpy(buffer, clr_txt, read_bytes);
        }

        if (ferror(body->fd)) {
            return CURL_READFUNC_ABORT;
        }

        body->total_sent += read_bytes;
        body->bytes_since_progress += read_bytes;

        body->remain -= read_bytes;

        memset_zero(clr_txt, buflen);
    }

    // give progress updates at set interval
    if (body->progress_handle && read_bytes > 0 &&
        (body->bytes_since_progress > SHARD_PROGRESS_INTERVAL ||
         body->remain == 0)) {

        shard_upload_progress_t *progress = body->progress_handle->data;
        progress->bytes = body->total_sent;
        uv_async_send(body->progress_handle);

        body->bytes_since_progress = 0;
    }

    return read_bytes;
}

int put_shard(storj_http_options_t *http_options,
              char *farmer_id,
              char *proto,
              char *host,
              int port,
              char *shard_hash,
              uint64_t shard_total_bytes,
              FILE *original_file,
              uint64_t file_position,
              storj_encryption_ctx_t *ctx,
              char *token,
              int *status_code,
              int *read_code,
              uv_async_t *progress_handle,
              bool *canceled)
{
    int return_code = 0;

    CURL *curl = curl_easy_init();
    if (!curl) {
        return 1;
    }

    char query_args[80];
    snprintf(query_args, 80, "?token=%s", token);

    int url_len = strlen(proto) + 3 + strlen(host) + 1 + 10 + 8
        + strlen(shard_hash) + strlen(query_args);
    char *url = calloc(url_len + 1, sizeof(char));
    if (!url) {
        return 1;
    }

    snprintf(url, url_len, "%s://%s:%i/shards/%s%s", proto, host, port,
             shard_hash, query_args);

    curl_easy_setopt(curl, CURLOPT_URL, url);

    curl_easy_setopt(curl, CURLOPT_LOW_SPEED_LIMIT,
                     http_options->low_speed_limit);

    curl_easy_setopt(curl, CURLOPT_LOW_SPEED_TIME,
                     http_options->low_speed_time);

    if (http_options->user_agent) {
        curl_easy_setopt(curl, CURLOPT_USERAGENT, http_options->user_agent);
    }

    if (http_options->proxy_url) {
        curl_easy_setopt(curl, CURLOPT_PROXY, http_options->proxy_url);
    }

    if (http_options->cainfo_path) {
        curl_easy_setopt(curl, CURLOPT_CAINFO, http_options->cainfo_path);
    }

    curl_easy_setopt(curl, CURLOPT_POST, 1);

    struct curl_slist *header_list = NULL;
    header_list = curl_slist_append(header_list, "Content-Type: application/octet-stream");

    char *header = calloc(17 + 40 + 1, sizeof(char));
    if (!header) {
        return 1;
    }
    strcat(header, "x-storj-node-id: ");
    strncat(header, farmer_id, 40);
    header_list = curl_slist_append(header_list, header);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, header_list);

    shard_body_send_t *shard_body = NULL;


    if (original_file && shard_total_bytes) {

        shard_body = malloc(sizeof(shard_body_send_t));
        if (!shard_body) {
            return 1;
        }

        shard_body->fd = original_file;
        shard_body->offset = file_position;
        shard_body->ctx = ctx;
        shard_body->length = shard_total_bytes;
        shard_body->remain = shard_total_bytes;
        shard_body->total_sent = 0;
        shard_body->bytes_since_progress = 0;
        shard_body->progress_handle = progress_handle;
        shard_body->canceled = canceled;
        shard_body->error_code = 0;

        curl_easy_setopt(curl, CURLOPT_READFUNCTION, body_shard_send);
        curl_easy_setopt(curl, CURLOPT_READDATA, (void *)shard_body);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE_LARGE, (uint64_t)shard_total_bytes);
    }

    // Ignore any data sent back, we only need to know the status code
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, body_ignore_receive);

    int req = curl_easy_perform(curl);

    curl_slist_free_all(header_list);
    free(header);

    if (*canceled) {
        return_code = 1;
        goto clean_up;
    }

    if (req != CURLE_OK) {
        return_code = req;
        goto clean_up;
    }

    // set the status code
    if (shard_body && shard_total_bytes) {
        *read_code = shard_body->error_code;
    }

    long int _status_code;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &_status_code);
    *status_code = (int)_status_code;

    // check that total bytes have been sent
    if (shard_body->total_sent != shard_total_bytes) {
        return_code = 1;
        goto clean_up;
    }

clean_up:

    // clean up memory
    if (shard_body) {
        free(shard_body);
    }
    free(url);
    curl_easy_cleanup(curl);

    return return_code;
}

static size_t body_shard_receive(void *buffer, size_t size, size_t nmemb,
                                  void *userp)
{
    size_t buflen = size * nmemb;
    shard_body_receive_t *body = (shard_body_receive_t *)userp;

    if (*body->canceled) {
        return CURL_READFUNC_ABORT;
    }

    if (body->length + body->tail_position + buflen > body->shard_total_bytes) {
        return CURL_READFUNC_ABORT;
    }

    // Resize the buffer if necessary
    if (body->tail_position + buflen > body->tail_length) {
        body->tail_length = (body->tail_position + buflen) * 2;
        body->tail = realloc(body->tail, body->tail_length);

        if (!body->tail) {
            return CURL_READFUNC_ABORT;
        }
    }

    // Copy buffer to tail
    memcpy(body->tail + body->tail_position, buffer, buflen);

    size_t writelen = body->tail_position + buflen;
    if (body->length + writelen != body->shard_total_bytes) {
        writelen = (writelen / AES_BLOCK_SIZE) * AES_BLOCK_SIZE;
    }

    // Update the hash
    sha256_update(body->sha256_ctx, writelen, (uint8_t *)body->tail);

    // Write directly to the file at the correct position
    if (writelen == pwrite(fileno(body->destination),
                           body->tail,
                           writelen,
                           body->file_position)) {

        if (writelen == -1) {
            body->error_code = errno;
            return CURL_READFUNC_ABORT;
        }

        body->file_position += writelen;
    } else {
        // TODO handle error
        return CURL_READFUNC_ABORT;
    }

    body->length += writelen;
    body->bytes_since_progress += writelen;

    // Move any remaining data to the beginning and mark position
    size_t tailing_size = body->tail_position + buflen - writelen;
    if (tailing_size > 0) {
        uint8_t tmp[tailing_size];
        memcpy(&tmp, body->tail + writelen, tailing_size);
        memcpy(body->tail, &tmp, tailing_size);
        body->tail_position = tailing_size;
    } else {
        body->tail_position = 0;
    }

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
                char *token,
                FILE *destination,
                uint64_t file_position,
                int *status_code,
                int *write_code,
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

    if (http_options->cainfo_path) {
        curl_easy_setopt(curl, CURLOPT_CAINFO, http_options->cainfo_path);
    }

    char query_args[80];
    snprintf(query_args, 80, "?token=%s", token);
    int url_len = strlen(proto) + 3 + strlen(host) + 1 + 10
        + 8 + strlen(shard_hash) + strlen(query_args);
    char *url = calloc(url_len + 1, sizeof(char));
    if (!url) {
        return 1;
    }
    snprintf(url, url_len, "%s://%s:%i/shards/%s%s", proto, host, port,
             shard_hash, query_args);

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_HTTPGET, 1);

    curl_easy_setopt(curl, CURLOPT_LOW_SPEED_LIMIT,
                     http_options->low_speed_limit);

    curl_easy_setopt(curl, CURLOPT_LOW_SPEED_TIME,
                     http_options->low_speed_time);

    // Set the node id header
    struct curl_slist *node_chunk = NULL;
    char *header = calloc(17 + 40 + 1, sizeof(char));
    if (!header) {
        return 1;
    }
    strcat(header, "x-storj-node-id: ");
    strncat(header, farmer_id, 40);
    node_chunk = curl_slist_append(node_chunk, header);
    free(header);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, node_chunk);

    // Set the body handler
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, body_shard_receive);
    shard_body_receive_t *body = malloc(sizeof(shard_body_receive_t));
    if (!body) {
        return 1;
    }

    body->tail = malloc(BUFSIZ);
    body->tail_length = BUFSIZ;
    body->tail_position = 0;
    body->length = 0;
    body->progress_handle = progress_handle;
    body->shard_total_bytes = shard_total_bytes;
    body->bytes_since_progress = 0;
    body->canceled = canceled;
    body->sha256_ctx = malloc(sizeof(struct sha256_ctx));
    body->error_code = 0;
    if (!body->sha256_ctx) {
        return 1;
    }
    sha256_init(body->sha256_ctx);

    body->destination = destination;
    body->file_position = file_position;
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)body);

    int req = curl_easy_perform(curl);

    curl_slist_free_all(node_chunk);
    free(body->tail);

    // set the status code
    if (body) {
        *write_code = body->error_code;
    }


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
    if (!hash_sha256) {
        return 1;
    }
    sha256_digest(body->sha256_ctx, SHA256_DIGEST_SIZE, hash_sha256);

    struct ripemd160_ctx rctx;
    ripemd160_init(&rctx);
    ripemd160_update(&rctx, SHA256_DIGEST_SIZE, hash_sha256);

    free(hash_sha256);

    uint8_t *hash_rmd160 = calloc(RIPEMD160_DIGEST_SIZE + 1, sizeof(uint8_t));
    if (!hash_rmd160) {
        return 1;
    }
    ripemd160_digest(&rctx, RIPEMD160_DIGEST_SIZE, hash_rmd160);

    char *hash = calloc(RIPEMD160_DIGEST_SIZE * 2 + 1, sizeof(char));
    if (!hash) {
        return 1;
    }
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

int fetch_json(storj_http_options_t *http_options,
               storj_bridge_options_t *options,
               char *method,
               char *path,
               struct json_object *request_body,
               bool auth,
               struct json_object **response,
               int *status_code)
{
    CURL *curl = curl_easy_init();
    if (!curl) {
        return 1;
    }

    // curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);

    char *user_pass = NULL;

    // Set the url
    int url_len = strlen(options->proto) + 3 + strlen(options->host) +
        1 + 10 + strlen(path);
    char *url = calloc(url_len + 1, sizeof(char));
    if (!url) {
        return 1;
    }

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
    } else if (0 == strcmp(method, "PATCH")) {
        curl_easy_setopt(curl, CURLOPT_POST, 1);
        curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "PATCH");
    } else {
        return 1;
    }

    // Set the proxy
    if (http_options->proxy_url) {
        curl_easy_setopt(curl, CURLOPT_PROXY, http_options->proxy_url);
    }

    // Set the path to the Certificate Authority (CA) bundle
    if (http_options->cainfo_path) {
        curl_easy_setopt(curl, CURLOPT_CAINFO, http_options->cainfo_path);
    }

    // Set the timeout
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, http_options->timeout);

    // Setup the body handler
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, body_json_receive);
    http_body_receive_t *body = malloc(sizeof(http_body_receive_t));
    if (!body) {
        return 1;
    }
    body->data = NULL;
    body->length = 0;
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)body);

    // Include authentication headers if info is provided
    if (auth && options->user && options->pass) {

        // Hash password
        uint8_t *pass_hash = calloc(SHA256_DIGEST_SIZE, sizeof(uint8_t));
        if (!pass_hash) {
            return 1;
        }
        char *pass = calloc(SHA256_DIGEST_SIZE * 2 + 1, sizeof(char));
        if (!pass) {
            return 1;
        }
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
        if (!user_pass) {
            return 1;
        }
        strcat(user_pass, options->user);
        strcat(user_pass, ":");
        strcat(user_pass, pass);

        free(pass);

        curl_easy_setopt(curl, CURLOPT_USERPWD, user_pass);

    }

    struct curl_slist *header_list = NULL;

    // Include body if request body json is provided
    http_body_send_t *post_body = NULL;
    const char *req_buf = NULL;
    if (request_body) {
        req_buf = json_object_to_json_string(request_body);

        header_list = curl_slist_append(header_list,
                                       "Content-Type: application/json");

        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, header_list);

        post_body = malloc(sizeof(http_body_send_t));
        if (!post_body) {
            return 1;
        }
        post_body->pnt = (char *)req_buf;
        post_body->remain = strlen(req_buf);

        curl_easy_setopt(curl, CURLOPT_READFUNCTION, body_json_send);
        curl_easy_setopt(curl, CURLOPT_READDATA, (void *)post_body);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE_LARGE, (uint64_t)strlen(req_buf));
    } else {
        header_list = curl_slist_append(header_list, "Content-Length: 0");
        header_list = curl_slist_append(header_list, "Content-Type: application/json");
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, header_list);
    }

    int ret = 0;
    int req = curl_easy_perform(curl);

    free(url);

    if (header_list) {
        curl_slist_free_all(header_list);
    }

    if (post_body) {
        free(post_body);
    }

    if (user_pass) {
        free(user_pass);
    }

    *response = NULL;

    if (req != CURLE_OK) {
        ret = req;
        goto cleanup;
    }

    // set the status code
    long int _status_code;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &_status_code);
    *status_code = (int)_status_code;

    if (body->data && body->length > 0) {
        *response = json_tokener_parse((char *)body->data);
    }

cleanup:
    curl_easy_cleanup(curl);
    if (body->data) {
        free(body->data);
    }
    if (body) {
        free(body);
    }

    return ret;
}
