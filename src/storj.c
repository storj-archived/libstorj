#include "storj.h"
#include "http.h"
#include "utils.h"
#include "crypto.h"

static inline void noop() {};

static void json_request_worker(uv_work_t *work)
{
    json_request_t *req = work->data;
    int status_code = 0;

    req->error_code = fetch_json(req->http_options,
                                 req->options, req->method, req->path, req->body,
                                 req->auth, NULL, &req->response, &status_code);

    req->status_code = status_code;
}

static uv_work_t *uv_work_new()
{
    uv_work_t *work = malloc(sizeof(uv_work_t));
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
    if (!req) {
        return NULL;
    }

    req->http_options = http_options;
    req->options = options;
    req->method = method;
    req->path = path;
    req->auth = auth;
    req->body = request_body;
    req->response = NULL;
    req->error_code = 0;
    req->status_code = 0;
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
    if (!work) {
        return NULL;
    }
    work->data = json_request_new(env->http_options,
                                  env->bridge_options, method, path,
                                  request_body, auth, handle);

    if (!work->data) {
        return NULL;
    }

    return work;
}

static void default_logger(const char *message,
                           int level,
                           void *handle)
{
    puts(message);
}

static void log_formatter(storj_log_options_t *options,
                          void *handle,
                          int level,
                          const char *format,
                          va_list args)
{
    va_list args_cpy;
    va_copy(args_cpy, args);
    int length = vsnprintf(0, 0, format, args_cpy);
    va_end(args_cpy);

    if (length > 0) {
        char message[length + 1];
        if (vsnprintf(message, length + 1, format, args)) {
            options->logger(message, level, handle);
        }
    }
}

static void log_formatter_debug(storj_log_options_t *options, void *handle,
                                const char *format, ...)
{
    va_list args;
    va_start(args, format);
    log_formatter(options, handle, 4, format, args);
    va_end(args);
}

static void log_formatter_info(storj_log_options_t *options, void *handle,
                               const char *format, ...)
{
    va_list args;
    va_start(args, format);
    log_formatter(options, handle, 3, format, args);
    va_end(args);
}

static void log_formatter_warn(storj_log_options_t *options, void *handle,
                               const char *format, ...)
{
    va_list args;
    va_start(args, format);
    log_formatter(options, handle, 2, format, args);
    va_end(args);
}

static void log_formatter_error(storj_log_options_t *options, void *handle,
                                const char *format, ...)
{
    va_list args;
    va_start(args, format);
    log_formatter(options, handle, 1, format, args);
    va_end(args);
}

struct storj_env *storj_init_env(storj_bridge_options_t *options,
                                 storj_encrypt_options_t *encrypt_options,
                                 storj_http_options_t *http_options,
                                 storj_log_options_t *log_options)
{
    curl_global_init(CURL_GLOBAL_ALL);

    uv_loop_t *loop = malloc(sizeof(uv_loop_t));
    if (!loop) {
        return NULL;
    }
    if (uv_loop_init(loop)) {
        return NULL;
    }

    storj_env_t *env = malloc(sizeof(storj_env_t));
    if (!env) {
        return NULL;
    }

    // setup the uv event loop
    env->loop = loop;

    // deep copy bridge options
    storj_bridge_options_t *bo = malloc(sizeof(storj_bridge_options_t));
    if (!bo) {
        return NULL;
    }

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
        bo->pass = VirtualAlloc(NULL, page_size,  MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
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
    if (!eo) {
        return NULL;
    }

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
        eo->mnemonic = VirtualAlloc(NULL, page_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
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

    // Set tmp_path
    struct stat sb;
    if (encrypt_options &&
        encrypt_options->tmp_path &&
        stat(encrypt_options->tmp_path, &sb) == 0 &&
        S_ISDIR(sb.st_mode)) {
        eo->tmp_path = strdup(encrypt_options->tmp_path);
    } else if (getenv("STORJ_TEMP") &&
               stat(getenv("STORJ_TEMP"), &sb) == 0 &&
               S_ISDIR(sb.st_mode)) {
        eo->tmp_path = strdup(getenv("STORJ_TEMP"));
#ifdef _WIN32
    } else if (getenv("TEMP") &&
               stat(getenv("TEMP"), &sb) == 0 &&
               S_ISDIR(sb.st_mode)) {
        eo->tmp_path = strdup(getenv("TEMP"));
#else
    } else if ("/tmp" && stat("/tmp", &sb) == 0 && S_ISDIR(sb.st_mode)) {
        eo->tmp_path = strdup("/tmp");
#endif
    } else {
        eo->tmp_path = NULL;
    }

    env->encrypt_options = eo;

    // deep copy the http options
    storj_http_options_t *ho = malloc(sizeof(storj_http_options_t));
    if (!ho) {
        return NULL;
    }
    ho->user_agent = strdup(http_options->user_agent);
    if (http_options->proxy_url) {
        ho->proxy_url = strdup(http_options->proxy_url);
    } else {
        ho->proxy_url = NULL;
    }
    env->http_options = ho;

    // setup the log options
    env->log_options = log_options;
    if (!env->log_options->logger) {
        env->log_options->logger = default_logger;
    }

    storj_log_levels_t *log = malloc(sizeof(storj_log_levels_t));
    if (!log) {
        return NULL;
    }

    log->debug = (storj_logger_format_fn)noop;
    log->info = (storj_logger_format_fn)noop;
    log->warn = (storj_logger_format_fn)noop;
    log->error = (storj_logger_format_fn)noop;

    switch(log_options->level) {
        case 4:
            log->debug = log_formatter_debug;
        case 3:
            log->info = log_formatter_info;
        case 2:
            log->warn = log_formatter_warn;
        case 1:
            log->error = log_formatter_error;
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

#ifdef _WIN32
        VirtualFree((char *)env->bridge_options, pass_len, MEM_RELEASE);
#else
        free((char *)env->bridge_options->pass);
#endif

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

#ifdef _WIN32
        VirtualFree((char *)env->bridge_options, mnemonic_len, MEM_RELEASE);
#else
        free((char *)env->encrypt_options->mnemonic);
#endif
    }

    if (env->encrypt_options->tmp_path) {
        free((char *)env->encrypt_options->tmp_path);
    }

    free(env->encrypt_options);

    // free all http options
    free((char *)env->http_options->user_agent);
    if (env->http_options->proxy_url) {
        free((char *)env->http_options->proxy_url);
    }
    free(env->http_options);

    // free the event loop
    free(env->loop);

    // free the log levels
    free(env->log);

    // free the environment
    free(env);

    curl_global_cleanup();

    return status;
}

int storj_encrypt_auth(const char *passphrase,
                       const char *bridge_user,
                       const char *bridge_pass,
                       const char *mnemonic,
                       char **buffer)
{
    char *pass_encrypted;
    int pass_length = strlen(bridge_pass);

    if (encrypt_data(passphrase, bridge_user, bridge_pass,
                     &pass_encrypted)) {
        return 1;
    }

    char *mnemonic_encrypted;
    int mnemonic_length = strlen(mnemonic);

    if (encrypt_data(passphrase, bridge_user, mnemonic,
                     &mnemonic_encrypted)) {
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

    *buffer = calloc(strlen(body_str) + 1, sizeof(char));
    memcpy(*buffer, body_str, strlen(body_str) + 1);

    json_object_put(body);
    free(mnemonic_encrypted);
    free(pass_encrypted);

    return 0;
}

int storj_encrypt_write_auth(const char *filepath,
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

    char *buffer = NULL;
    if (storj_encrypt_auth(passphrase, bridge_user,
                           bridge_pass, mnemonic, &buffer)) {
        fclose(fp);
        return 1;
    }

    fwrite(buffer, strlen(buffer), sizeof(char), fp);
    fwrite("\n", 1, sizeof(char), fp);

    free(buffer);
    fclose(fp);

    return 0;
}

int storj_decrypt_auth(const char *buffer,
                       const char *passphrase,
                       char **bridge_user,
                       char **bridge_pass,
                       char **mnemonic)
{
    int status = 0;

    json_object *body = json_tokener_parse(buffer);

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

    return status;
}

int storj_decrypt_read_auth(const char *filepath,
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

    char *buffer = calloc(fsize + 1, sizeof(char));
    if (buffer == NULL) {
        return 1;
    }

    int read_blocks = 0;
    while ((!feof(fp)) && (!ferror(fp))) {
        read_blocks = fread(buffer + read_blocks, 1, fsize, fp);
        if (read_blocks <= 0) {
            break;
        }
    }

    int error = ferror(fp);
    fclose(fp);

    if (error) {
        return error;
    }

    int status = storj_decrypt_auth(buffer, passphrase, bridge_user,
                                    bridge_pass, mnemonic);

    free(buffer);

    return status;

}

uint64_t storj_util_timestamp()
{
    return get_time_milliseconds();
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
        case STORJ_BRIDGE_FILEINFO_ERROR:
            return "Bridge file info error";
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
            return "File encryption error";
        case STORJ_FILE_SIZE_ERROR:
            return "File size error";
        case STORJ_FILE_DECRYPTION_ERROR:
            return "File decryption error";
        case STORJ_TRANSFER_CANCELED:
            return "File transfer canceled";
        case STORJ_MEMORY_ERROR:
            return "Memory error";
        case STORJ_QUEUE_ERROR:
            return "Queue error";
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
    if (!work) {
        return STORJ_MEMORY_ERROR;
    }

    return uv_queue_work(env->loop, (uv_work_t*) work, json_request_worker, cb);
}

int storj_bridge_get_buckets(storj_env_t *env, void *handle, uv_after_work_cb cb)
{
    uv_work_t *work = json_request_work_new(env, "GET", "/buckets", NULL,
                                            true, handle);
    if (!work) {
        return STORJ_MEMORY_ERROR;
    }

    return uv_queue_work(env->loop, (uv_work_t*) work, json_request_worker, cb);
}

int storj_bridge_create_bucket(storj_env_t *env,
                               const char *name,
                               void *handle,
                               uv_after_work_cb cb)
{
    struct json_object *body = json_object_new_object();
    json_object *name_string = json_object_new_string(name);

    json_object_object_add(body, "name", name_string);

    uv_work_t *work = json_request_work_new(env, "POST", "/buckets", body,
                                            true, handle);
    if (!work) {
        return STORJ_MEMORY_ERROR;
    }

    return uv_queue_work(env->loop, (uv_work_t*) work, json_request_worker, cb);
}

int storj_bridge_delete_bucket(storj_env_t *env,
                               const char *id,
                               void *handle,
                               uv_after_work_cb cb)
{
    char *path = str_concat_many(2, "/buckets/", id);
    if (!path) {
        return STORJ_MEMORY_ERROR;
    }

    uv_work_t *work = json_request_work_new(env, "DELETE", path,
                                            NULL, true, handle);
    if (!work) {
        return STORJ_MEMORY_ERROR;
    }

    return uv_queue_work(env->loop, (uv_work_t*) work, json_request_worker, cb);
}

int storj_bridge_list_files(storj_env_t *env,
                            const char *id,
                            void *handle,
                            uv_after_work_cb cb)
{
    char *path = str_concat_many(3, "/buckets/", id, "/files");
    if (!path) {
        return STORJ_MEMORY_ERROR;
    }

    uv_work_t *work = json_request_work_new(env, "GET", path, NULL,
                                            true, handle);
    if (!work) {
        return STORJ_MEMORY_ERROR;
    }

    return uv_queue_work(env->loop, (uv_work_t*) work, json_request_worker, cb);
}

int storj_bridge_create_bucket_token(storj_env_t *env,
                                     const char *bucket_id,
                                     storj_bucket_op_t operation,
                                     void *handle,
                                     uv_after_work_cb cb)
{
    struct json_object *body = json_object_new_object();
    json_object *op_string = json_object_new_string(BUCKET_OP[operation]);

    json_object_object_add(body, "operation", op_string);

    char *path = str_concat_many(3, "/buckets/", bucket_id, "/tokens");
    if (!path) {
        return STORJ_MEMORY_ERROR;
    }

    uv_work_t *work = json_request_work_new(env, "POST", path, body,
                                            true, handle);
    if (!work) {
        return STORJ_MEMORY_ERROR;
    }

    return uv_queue_work(env->loop, (uv_work_t*) work, json_request_worker, cb);
}

int storj_bridge_get_file_pointers(storj_env_t *env,
                                   const char *bucket_id,
                                   const char *file_id,
                                   void *handle,
                                   uv_after_work_cb cb)
{
    char *path = str_concat_many(4, "/buckets/", bucket_id, "/files/", file_id);
    if (!path) {
        return STORJ_MEMORY_ERROR;
    }

    uv_work_t *work = json_request_work_new(env, "GET", path, NULL,
                                            true, handle);
    if (!work) {
        return STORJ_MEMORY_ERROR;
    }

    return uv_queue_work(env->loop, (uv_work_t*) work, json_request_worker, cb);
}

int storj_bridge_delete_file(storj_env_t *env,
                             const char *bucket_id,
                             const char *file_id,
                             void *handle,
                             uv_after_work_cb cb)
{
    char *path = str_concat_many(4, "/buckets/", bucket_id, "/files/", file_id);
    if (!path) {
        return STORJ_MEMORY_ERROR;
    }

    uv_work_t *work = json_request_work_new(env, "DELETE", path, NULL,
                                            true, handle);
    if (!work) {
        return STORJ_MEMORY_ERROR;
    }

    return uv_queue_work(env->loop, (uv_work_t*) work, json_request_worker, cb);
}

int storj_bridge_create_frame(storj_env_t *env,
                              void *handle,
                              uv_after_work_cb cb)
{
    uv_work_t *work = json_request_work_new(env, "POST", "/frames", NULL,
                                            true, handle);
    if (!work) {
        return STORJ_MEMORY_ERROR;
    }

    return uv_queue_work(env->loop, (uv_work_t*) work, json_request_worker, cb);
}

int storj_bridge_get_frames(storj_env_t *env,
                            void *handle,
                            uv_after_work_cb cb)
{
    uv_work_t *work = json_request_work_new(env, "GET", "/frames", NULL,
                                            true, handle);
    if (!work) {
        return STORJ_MEMORY_ERROR;
    }

    return uv_queue_work(env->loop, (uv_work_t*) work, json_request_worker, cb);
}

int storj_bridge_get_frame(storj_env_t *env,
                           const char *frame_id,
                           void *handle,
                           uv_after_work_cb cb)
{
    char *path = str_concat_many(2, "/frames/", frame_id);
    if (!path) {
        return STORJ_MEMORY_ERROR;
    }

    uv_work_t *work = json_request_work_new(env, "GET", path, NULL,
                                            true, handle);
    if (!work) {
        return STORJ_MEMORY_ERROR;
    }

    return uv_queue_work(env->loop, (uv_work_t*) work, json_request_worker, cb);

}

int storj_bridge_delete_frame(storj_env_t *env,
                              const char *frame_id,
                              void *handle,
                              uv_after_work_cb cb)
{
    char *path = str_concat_many(2, "/frames/", frame_id);
    if (!path) {
        return STORJ_MEMORY_ERROR;
    }

    uv_work_t *work = json_request_work_new(env, "DELETE", path, NULL,
                                            true, handle);
    if (!work) {
        return STORJ_MEMORY_ERROR;
    }

    return uv_queue_work(env->loop, (uv_work_t*) work, json_request_worker, cb);
}

int storj_bridge_get_file_info(storj_env_t *env,
                               const char *bucket_id,
                               const char *file_id,
                               void *handle,
                               uv_after_work_cb cb)
{
    char *path = str_concat_many(5, "/buckets/", bucket_id, "/files/",
                                 file_id, "/info");
    if (!path) {
        return STORJ_MEMORY_ERROR;
    }

    uv_work_t *work = json_request_work_new(env, "GET", path, NULL,
                                            true, handle);
    if (!work) {
        return STORJ_MEMORY_ERROR;
    }

    return uv_queue_work(env->loop, (uv_work_t*) work, json_request_worker, cb);
}

int storj_bridge_list_mirrors(storj_env_t *env,
                              const char *bucket_id,
                              const char *file_id,
                              void *handle,
                              uv_after_work_cb cb)
{
    char *path = str_concat_many(5, "/buckets/", bucket_id, "/files/",
                                 file_id, "/mirrors");
    if (!path) {
        return STORJ_MEMORY_ERROR;
    }

    uv_work_t *work = json_request_work_new(env, "GET", path, NULL,
                                           true, handle);
    if (!work) {
        return STORJ_MEMORY_ERROR;
    }

    return uv_queue_work(env->loop, (uv_work_t*) work, json_request_worker, cb);
}

int storj_bridge_register(storj_env_t *env,
                          const char *email,
                          const char *password,
                          void *handle,
                          uv_after_work_cb cb)
{
    uint8_t sha256_digest[SHA256_DIGEST_SIZE];
    sha256_of_str((uint8_t *)password, strlen(password), sha256_digest);
    // TODO refactor hex2str, to make it more clear how much space needs
    // to be allocated for hex_str
    char *hex_str = calloc(2 * SHA256_DIGEST_SIZE + 2, sizeof(char));
    if (!hex_str) {
        return STORJ_MEMORY_ERROR;
    }
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
    if (!work) {
        return STORJ_MEMORY_ERROR;
    }
    return uv_queue_work(env->loop, (uv_work_t*) work, json_request_worker, cb);
}
