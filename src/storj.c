#include "storj.h"
#include "http.h"
#include "utils.h"
#include "crypto.h"

static inline void noop() {};

static void json_request_worker(uv_work_t *work)
{
    json_request_t *req = work->data;
    int status_code = 0;
    req->response = fetch_json(req->http_options,
                               req->options, req->method, req->path, req->body,
                               req->auth, NULL, &status_code);

    req->status_code = status_code;
}

static uv_work_t *uv_work_new()
{
    uv_work_t *work = malloc(sizeof(uv_work_t));
    assert(work != NULL);
    return work;
}

static json_request_t *json_request_new(
    storj_http_options_t *http_options,
    storj_bridge_options_t *options,
    char *method,
    char *path,
    struct json_object *request_body,
    bool auth,
    void *handle)
{
    json_request_t *req = malloc(sizeof(json_request_t));
    assert(req != NULL);

    req->http_options = http_options;
    req->options = options;
    req->method = method;
    req->path = path;
    req->body = request_body;
    req->auth = auth;
    req->handle = handle;

    return req;
}

static uv_work_t *json_request_work_new(
    storj_env_t *env,
    char *method,
    char *path,
    struct json_object *request_body,
    bool auth,
    void *handle)
{
    uv_work_t *work = uv_work_new();
    work->data = json_request_new(env->http_options,
                                  env->bridge_options, method, path,
                                  request_body, auth, handle);

    return work;
}

struct storj_env *storj_init_env(storj_bridge_options_t *options,
                                 storj_encrypt_options_t *encrypt_options,
                                 storj_http_options_t *http_options,
                                 storj_log_options_t *log_options)
{
    uv_loop_t *loop = malloc(sizeof(uv_loop_t));
    if (uv_loop_init(loop)) {
        return NULL;
    }

    storj_env_t *env = malloc(sizeof(storj_env_t));

    // setup the uv event loop
    env->loop = loop;

    // deep copy bridge options
    storj_bridge_options_t *bo = malloc(sizeof(storj_bridge_options_t));
    bo->proto = strdup(options->proto);
    bo->host = strdup(options->host);
    bo->port = options->port;
    if (options->user) {
        bo->user = strdup(options->user);
    } else {
        bo->user = NULL;
    }

#ifdef _POSIX_MEMLOCK
    int page_size = sysconf(_SC_PAGESIZE);
#elif _WIN32
    SYSTEM_INFO si;
    GetSystemInfo (&si);
    uintptr_t page_size = si.dwPageSize;
#endif

    if (options->pass) {
        // prevent bridge password from being swapped unencrypted to disk
#ifdef _POSIX_MEMLOCK
        int pass_len = strlen(options->pass);
        if (pass_len >= page_size) {
            return NULL;
        }

#ifdef HAVE_ALIGNED_ALLOC
        bo->pass = aligned_alloc(page_size, page_size);
#elif HAVE_POSIX_MEMALIGN
        bo->pass = NULL;
        if (posix_memalign((void *)&bo->pass, page_size, page_size)) {
            return NULL;
        }
#else
        bo->pass = malloc(page_size);
#endif

        if (bo->pass == NULL) {
            return NULL;
        }
        memset((char *)bo->pass, 0, page_size);
        memcpy((char *)bo->pass, options->pass, pass_len);
        if (mlock(bo->pass, pass_len)) {
            return NULL;
        }
#elif _WIN32
        int pass_len = strlen(options->pass);
        bo->pass = _aligned_malloc(page_size, page_size);
        if (bo->pass == NULL) {
            return NULL;
        }
        memset((char *)bo->pass, 0, page_size);
        memcpy((char *)bo->pass, options->pass, pass_len);
        if (!VirtualLock((char *)bo->pass, pass_len)) {
            return NULL;
        }
#else
        bo->pass = strdup(options->pass);
#endif
    } else {
        bo->pass = NULL;
    }

    env->bridge_options = bo;

    // deep copy encryption options
    storj_encrypt_options_t *eo = malloc(sizeof(storj_encrypt_options_t));

    if (encrypt_options && encrypt_options->mnemonic) {

        // prevent file encryption mnemonic from being swapped unencrypted to disk
#ifdef _POSIX_MEMLOCK
        int mnemonic_len = strlen(encrypt_options->mnemonic);
        if (mnemonic_len >= page_size) {
            return NULL;
        }

#ifdef HAVE_ALIGNED_ALLOC
        eo->mnemonic = aligned_alloc(page_size, page_size);
#elif HAVE_POSIX_MEMALIGN
        eo->mnemonic = NULL;
        if (posix_memalign((void *)&eo->mnemonic, page_size, page_size)) {
            return NULL;
        }
#else
        eo->mnemonic = malloc(page_size);
#endif

        if (eo->mnemonic == NULL) {
            return NULL;
        }

        memset((char *)eo->mnemonic, 0, page_size);
        memcpy((char *)eo->mnemonic, encrypt_options->mnemonic, mnemonic_len);
        if (mlock(eo->mnemonic, mnemonic_len)) {
            return NULL;
        }
#elif _WIN32
        int mnemonic_len = strlen(encrypt_options->mnemonic);
        eo->mnemonic = _aligned_malloc(page_size, page_size);
        if (eo->mnemonic == NULL) {
            return NULL;
        }
        memset((char *)eo->mnemonic, 0, page_size);
        memcpy((char *)eo->mnemonic, encrypt_options->mnemonic, mnemonic_len);
        if (!VirtualLock((char *)eo->mnemonic, mnemonic_len)) {
            return NULL;
        }
#else
        eo->mnemonic = strdup(encrypt_options->mnemonic);
#endif
    } else {
        eo->mnemonic = NULL;
    }

    env->encrypt_options = eo;

    // deep copy the http options
    storj_http_options_t *ho = malloc(sizeof(storj_http_options_t));
    ho->user_agent = strdup(http_options->user_agent);
    ho->proxy_version = http_options->proxy_version;
    if (http_options->proxy_host) {
        ho->proxy_host = strdup(http_options->proxy_host);
    } else {
        ho->proxy_host = NULL;
    }
    ho->proxy_port = http_options->proxy_port;
    env->http_options = ho;

    // setup the log options
    env->log_options = log_options;

    storj_log_levels_t *log = malloc(sizeof(storj_log_levels_t));

    log->debug = (storj_logger_fn)noop;
    log->info = (storj_logger_fn)noop;
    log->warn = (storj_logger_fn)noop;
    log->error = (storj_logger_fn)noop;

    switch(log_options->level) {
        case 4:
            log->debug = log_options->logger;
        case 3:
            log->info = log_options->logger;
        case 2:
            log->warn = log_options->logger;
        case 1:
            log->error = log_options->logger;
        case 0:
            break;
    }

    env->log = log;

    return env;
}

int storj_destroy_env(storj_env_t *env)
{
    int status = 0;

    // free and destroy all bridge options
    free((char *)env->bridge_options->proto);
    free((char *)env->bridge_options->host);
    free((char *)env->bridge_options->user);

    // zero out password before freeing
    if (env->bridge_options->pass) {
        unsigned int pass_len = strlen(env->bridge_options->pass);
        if (pass_len > 0) {
            memset_zero((char *)env->bridge_options->pass, pass_len);
        }
#ifdef _POSIX_MEMLOCK
        status = munlock(env->bridge_options->pass, pass_len);
#elif _WIN32
        if (!VirtualUnlock((char *)env->bridge_options->pass, pass_len)) {
            status = 1;
        }
#endif
        free((char *)env->bridge_options->pass);
    }
    free(env->bridge_options);

    // free and destroy all encryption options
    if (env->encrypt_options && env->encrypt_options->mnemonic) {
        unsigned int mnemonic_len = strlen(env->encrypt_options->mnemonic);

        // zero out file encryption mnemonic before freeing
        if (mnemonic_len > 0) {
            memset_zero((char *)env->encrypt_options->mnemonic, mnemonic_len);
        }
#ifdef _POSIX_MEMLOCK
        status = munlock(env->encrypt_options->mnemonic, mnemonic_len);
#elif _WIN32
        if (!VirtualUnlock((char *)env->encrypt_options->mnemonic, mnemonic_len)) {
            status = 1;
        }
#endif
        free((char *)env->encrypt_options->mnemonic);
    }
    free(env->encrypt_options);

    // free all http options
    free((char *)env->http_options->user_agent);
    free((char *)env->http_options->proxy_host);
    free(env->http_options);

    // free the event loop
    free(env->loop);

    // free the log levels
    free(env->log);

    // free the environment
    free(env);

    return status;
}

int storj_write_auth(const char *filepath,
                     const char *passphrase,
                     const char *bridge_user,
                     const char *bridge_pass,
                     const char *mnemonic)
{
    FILE *fp;
    fp = fopen(filepath, "w");
    if (fp == NULL) {
        return 1;
    }

    char *pass_encrypted;
    int pass_length = strlen(bridge_pass);

    if (encrypt_data(passphrase, bridge_user, bridge_pass,
                     &pass_encrypted)) {
        fclose(fp);
        return 1;
    }

    char *mnemonic_encrypted;
    int mnemonic_length = strlen(mnemonic);

    if (encrypt_data(passphrase, bridge_user, mnemonic,
                     &mnemonic_encrypted)) {
        fclose(fp);
        return 1;
    }

    struct json_object *body = json_object_new_object();
    json_object *user_str = json_object_new_string(bridge_user);

    json_object *pass_str = json_object_new_string(pass_encrypted);
    json_object *mnemonic_str = json_object_new_string(mnemonic_encrypted);

    json_object_object_add(body, "user", user_str);
    json_object_object_add(body, "pass", pass_str);
    json_object_object_add(body, "mnemonic", mnemonic_str);

    const char *body_str = json_object_to_json_string(body);

    fwrite(body_str, strlen(body_str), sizeof(char), fp);
    fwrite("\n", 1, sizeof(char), fp);

    json_object_put(body);
    free(mnemonic_encrypted);
    free(pass_encrypted);

    fclose(fp);

    return 0;
}

int storj_read_auth(const char *filepath,
                    const char *passphrase,
                    char **bridge_user,
                    char **bridge_pass,
                    char **mnemonic)
{
    FILE *fp;
    fp = fopen(filepath, "r");
    if (fp == NULL) {
        return 1;
    }

    fseek(fp, 0, SEEK_END);
    int fsize = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    char *data = calloc(fsize + 1, sizeof(char));
    if (data == NULL) {
        return 1;
    }
    int read_blocks = fread(data, fsize, 1, fp);
    if (read_blocks != 1) {
        free(data);
        return 1;
    }
    fclose(fp);

    int status = 0;

    json_object *body = json_tokener_parse(data);

    struct json_object *user_value;
    if (!json_object_object_get_ex(body, "user", &user_value)) {
        status = 1;
        goto clean_up;
    }

    *bridge_user = strdup((char *)json_object_get_string(user_value));

    struct json_object *pass_value;
    if (!json_object_object_get_ex(body, "pass", &pass_value)) {
        status = 1;
        goto clean_up;
    }
    char *pass_enc = (char *)json_object_get_string(pass_value);

    struct json_object *mnemonic_value;
    if (!json_object_object_get_ex(body, "mnemonic", &mnemonic_value)) {
        status = 1;
        goto clean_up;
    }
    char *mnemonic_enc = (char *)json_object_get_string(mnemonic_value);

    if (decrypt_data(passphrase, *bridge_user, pass_enc, bridge_pass)) {
        status = 1;
        goto clean_up;
    }

    if (decrypt_data(passphrase, *bridge_user, mnemonic_enc, mnemonic)) {
        status = 1;
        goto clean_up;
    }

clean_up:
    json_object_put(body);
    free(data);

    return status;
}

int storj_mnemonic_generate(int strength, char **buffer)
{
    return mnemonic_generate(strength, buffer);
}

bool storj_mnemonic_check(const char *mnemonic)
{
    return mnemonic_check(mnemonic);
}

char *storj_strerror(int error_code)
{
    switch(error_code) {
        case STORJ_BRIDGE_REQUEST_ERROR:
            return "Bridge request error";
        case STORJ_BRIDGE_AUTH_ERROR:
            return "Bridge request authorization error";
        case STORJ_BRIDGE_TOKEN_ERROR:
            return "Bridge request token error";
        case STORJ_BRIDGE_POINTER_ERROR:
            return "Bridge request pointer error";
        case STORJ_BRIDGE_REPOINTER_ERROR:
            return "Bridge request replace pointer error";
        case STORJ_BRIDGE_TIMEOUT_ERROR:
            return "Bridge request timeout error";
        case STORJ_BRIDGE_INTERNAL_ERROR:
            return "Bridge request internal error";
        case STORJ_BRIDGE_RATE_ERROR:
            return "Bridge transfer rate limit error";
        case STORJ_BRIDGE_BUCKET_NOTFOUND_ERROR:
            return "Bucket is not found";
        case STORJ_BRIDGE_FILE_NOTFOUND_ERROR:
            return "File is not found";
        case STORJ_BRIDGE_JSON_ERROR:
            return "Unexpected JSON response";
        case STORJ_FARMER_REQUEST_ERROR:
            return "Farmer request error";
        case STORJ_FARMER_EXHAUSTED_ERROR:
            return "Farmer exhausted error";
        case STORJ_FARMER_TIMEOUT_ERROR:
            return "Farmer request timeout error";
        case STORJ_FARMER_AUTH_ERROR:
            return "Farmer request authorization error";
        case STORJ_FARMER_INTEGRITY_ERROR:
            return "Farmer request integrity error";
        case STORJ_FILE_INTEGRITY_ERROR:
            return "File integrity error";
        case STORJ_BRIDGE_FRAME_ERROR:
            return "Bridge frame request error";
        case STORJ_FILE_ENCRYPTION_ERROR:
            return "File Encryption error";
        case STORJ_TRANSFER_CANCELED:
            return "File transfer canceled";
        case STORJ_TRANSFER_OK:
            return "No errors";
        default:
            return "Unknown error";
    }
}

int storj_bridge_get_info(storj_env_t *env, void *handle, uv_after_work_cb cb)
{
    uv_work_t *work = json_request_work_new(env,"GET", "/", NULL,
                                            false, handle);

    return uv_queue_work(env->loop, (uv_work_t*) work, json_request_worker, cb);
}

int storj_bridge_get_buckets(storj_env_t *env, void *handle, uv_after_work_cb cb)
{
    uv_work_t *work = json_request_work_new(env, "GET", "/buckets", NULL,
                                            true, handle);

    return uv_queue_work(env->loop, (uv_work_t*) work, json_request_worker, cb);
}

int storj_bridge_create_bucket(storj_env_t *env,
                               char *name,
                               void *handle,
                               uv_after_work_cb cb)
{
    struct json_object *body = json_object_new_object();
    json_object *name_string = json_object_new_string(name);

    json_object_object_add(body, "name", name_string);

    uv_work_t *work = json_request_work_new(env, "POST", "/buckets", body,
                                            true, handle);

    return uv_queue_work(env->loop, (uv_work_t*) work, json_request_worker, cb);
}

int storj_bridge_delete_bucket(storj_env_t *env,
                               char *id,
                               void *handle,
                               uv_after_work_cb cb)
{
    char *path = ne_concat("/buckets/", id, NULL);
    uv_work_t *work = json_request_work_new(env, "DELETE", path,
                                            NULL, true, handle);

    return uv_queue_work(env->loop, (uv_work_t*) work, json_request_worker, cb);
}

int storj_bridge_list_files(storj_env_t *env,
                            char *id,
                            void *handle,
                            uv_after_work_cb cb)
{
    char *path = ne_concat("/buckets/", id, "/files", NULL);
    uv_work_t *work = json_request_work_new(env, "GET", path, NULL,
                                            true, handle);

    return uv_queue_work(env->loop, (uv_work_t*) work, json_request_worker, cb);
}

int storj_bridge_create_bucket_token(storj_env_t *env,
                                     char *bucket_id,
                                     storj_bucket_op_t operation,
                                     void *handle,
                                     uv_after_work_cb cb)
{
    struct json_object *body = json_object_new_object();
    json_object *op_string = json_object_new_string(BUCKET_OP[operation]);

    json_object_object_add(body, "operation", op_string);

    char *path = ne_concat("/buckets/", bucket_id, "/tokens", NULL);
    uv_work_t *work = json_request_work_new(env, "POST", path, body,
                                            true, handle);

    return uv_queue_work(env->loop, (uv_work_t*) work, json_request_worker, cb);
}

int storj_bridge_get_file_pointers(storj_env_t *env,
                                   char *bucket_id,
                                   char *file_id,
                                   void *handle,
                                   uv_after_work_cb cb)
{
    char *path = ne_concat("/buckets/", bucket_id, "/files/", file_id, NULL);
    uv_work_t *work = json_request_work_new(env, "GET", path, NULL,
                                            true, handle);

    return uv_queue_work(env->loop, (uv_work_t*) work, json_request_worker, cb);
}

int storj_bridge_delete_file(storj_env_t *env,
                             char *bucket_id,
                             char *file_id,
                             void *handle,
                             uv_after_work_cb cb)
{
    char *path = ne_concat("/buckets/", bucket_id, "/files/", file_id, NULL);
    uv_work_t *work = json_request_work_new(env, "DELETE", path, NULL,
                                            true, handle);

    return uv_queue_work(env->loop, (uv_work_t*) work, json_request_worker, cb);
}

int storj_bridge_create_frame(storj_env_t *env,
                              void *handle,
                              uv_after_work_cb cb)
{
    uv_work_t *work = json_request_work_new(env, "POST", "/frames", NULL,
                                            true, handle);

    return uv_queue_work(env->loop, (uv_work_t*) work, json_request_worker, cb);
}

int storj_bridge_get_frames(storj_env_t *env,
                            void *handle,
                            uv_after_work_cb cb)
{
    uv_work_t *work = json_request_work_new(env, "GET", "/frames", NULL,
                                            true, handle);

    return uv_queue_work(env->loop, (uv_work_t*) work, json_request_worker, cb);
}

int storj_bridge_get_frame(storj_env_t *env,
                           char *frame_id,
                           void *handle,
                           uv_after_work_cb cb)
{
    char *path = ne_concat("/frames/", frame_id, NULL);
    uv_work_t *work = json_request_work_new(env, "GET", path, NULL,
                                            true, handle);

    return uv_queue_work(env->loop, (uv_work_t*) work, json_request_worker, cb);

}

int storj_bridge_delete_frame(storj_env_t *env,
                              char *frame_id,
                              void *handle,
                              uv_after_work_cb cb)
{
    char *path = ne_concat("/frames/", frame_id, NULL);
    uv_work_t *work = json_request_work_new(env, "DELETE", path, NULL,
                                            true, handle);

    return uv_queue_work(env->loop, (uv_work_t*) work, json_request_worker, cb);
}

int storj_bridge_get_file_info(storj_env_t *env,
                               char *bucket_id,
                               char *file_id,
                               void *handle,
                               uv_after_work_cb cb)
{
    char *path = ne_concat("/buckets/", bucket_id, "/files/",
                           file_id, "/info", NULL);

    uv_work_t *work = json_request_work_new(env, "GET", path, NULL,
                                            true, handle);

    return uv_queue_work(env->loop, (uv_work_t*) work, json_request_worker, cb);
}

int storj_bridge_list_mirrors(storj_env_t *env,
                              char *bucket_id,
                              char *file_id,
                              void *handle,
                              uv_after_work_cb cb)
{
    char *path = ne_concat("/buckets/", bucket_id, "/files/", file_id,
                           "/mirrors", NULL);

    uv_work_t *work = json_request_work_new(env, "GET", path, NULL,
                                           true, handle);

    return uv_queue_work(env->loop, (uv_work_t*) work, json_request_worker, cb);
}

int storj_bridge_register(storj_env_t *env,
                              char *email,
                              char *password,
                              void *handle,
                              uv_after_work_cb cb)
{
    uint8_t sha256_digest[SHA256_DIGEST_SIZE];
    sha256_of_str((uint8_t *)password, strlen(password), sha256_digest);
    // TODO refactor hex2str, to make it more clear how much space needs
    // to be allocated for hex_str
    char *hex_str = calloc(2 * SHA256_DIGEST_SIZE + 2, sizeof(char));
    hex2str(SHA256_DIGEST_SIZE, sha256_digest, hex_str);
    hex_str[2 * SHA256_DIGEST_SIZE] = '\0';

    struct json_object *body = json_object_new_object();
    json_object *email_str = json_object_new_string(email);
    json_object *pass_str = json_object_new_string(hex_str);
    free(hex_str);
    json_object_object_add(body, "email", email_str);
    json_object_object_add(body, "password", pass_str);

    uv_work_t *work = json_request_work_new(env, "POST", "/users", body, true,
                                            handle);
    return uv_queue_work(env->loop, (uv_work_t*) work, json_request_worker, cb);
}
