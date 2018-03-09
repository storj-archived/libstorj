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
                                 req->auth, &req->response, &status_code);

    req->status_code = status_code;
}

static void create_bucket_request_worker(uv_work_t *work)
{
    create_bucket_request_t *req = work->data;
    int status_code = 0;

    // Encrypt the bucket name
    if (encrypt_bucket_name(req->encrypt_options->mnemonic,
                            req->bucket_name,
                            (char **)&req->encrypted_bucket_name)) {
        req->error_code = STORJ_MEMORY_ERROR;
        return;
    }

    struct json_object *body = json_object_new_object();
    json_object *name = json_object_new_string(req->encrypted_bucket_name);
    json_object_object_add(body, "name", name);

    req->error_code = fetch_json(req->http_options,
                                 req->bridge_options, "POST", "/buckets", body,
                                 true, &req->response, &status_code);

    json_object_put(body);

    if (req->response != NULL) {
        req->bucket = malloc(sizeof(storj_bucket_meta_t));

        struct json_object *id;
        struct json_object *created;

        json_object_object_get_ex(req->response, "id", &id);
        json_object_object_get_ex(req->response, "created", &created);

        req->bucket->id = json_object_get_string(id);
        req->bucket->name = req->bucket_name;
        req->bucket->created = json_object_get_string(created);
        req->bucket->decrypted = true;
    }

    req->status_code = status_code;
}

static void get_buckets_request_worker(uv_work_t *work)
{
    get_buckets_request_t *req = work->data;
    int status_code = 0;

    req->error_code = fetch_json(req->http_options,
                                 req->options, req->method, req->path, req->body,
                                 req->auth, &req->response, &status_code);

    req->status_code = status_code;

    int num_buckets = 0;
    if (req->response != NULL &&
        json_object_is_type(req->response, json_type_array)) {
        num_buckets = json_object_array_length(req->response);
    }

    if (num_buckets > 0) {
        req->buckets = malloc(sizeof(storj_bucket_meta_t) * num_buckets);
        req->total_buckets = num_buckets;
    }

    struct json_object *bucket_item;
    struct json_object *name;
    struct json_object *created;
    struct json_object *id;

    for (int i = 0; i < num_buckets; i++) {
        bucket_item = json_object_array_get_idx(req->response, i);

        json_object_object_get_ex(bucket_item, "id", &id);
        json_object_object_get_ex(bucket_item, "name", &name);
        json_object_object_get_ex(bucket_item, "created", &created);

        storj_bucket_meta_t *bucket = &req->buckets[i];
        bucket->id = json_object_get_string(id);
        bucket->decrypted = false;
        bucket->created = json_object_get_string(created);
        bucket->name = NULL;

        // Attempt to decrypt the name, otherwise
        // we will default the name to the encrypted text.
        // The decrypted flag will be set to indicate the status
        // of decryption for alternative display.
        const char *encrypted_name = json_object_get_string(name);
        if (!encrypted_name) {
            continue;
        }
        char *decrypted_name;
        int error_status = decrypt_bucket_name(req->encrypt_options->mnemonic,
                                               encrypted_name,
                                               &decrypted_name);
        if (!error_status) {
            bucket->decrypted = true;
            bucket->name = decrypted_name;
        } else if (error_status == STORJ_META_DECRYPTION_ERROR){
            bucket->decrypted = false;
            bucket->name = strdup(encrypted_name);
        } else {
            req->error_code = STORJ_MEMORY_ERROR;
        }
    }
}

static void get_bucket_request_worker(uv_work_t *work)
{
    get_bucket_request_t *req = work->data;
    int status_code = 0;

    req->error_code = fetch_json(req->http_options,
                                 req->options, req->method, req->path, req->body,
                                 req->auth, &req->response, &status_code);

    req->status_code = status_code;

    if (!req->response) {
        req->bucket = NULL;
        return;
    }

    struct json_object *name;
    struct json_object *created;
    struct json_object *id;

    json_object_object_get_ex(req->response, "id", &id);
    json_object_object_get_ex(req->response, "name", &name);
    json_object_object_get_ex(req->response, "created", &created);

    req->bucket = malloc(sizeof(storj_bucket_meta_t));
    req->bucket->id = json_object_get_string(id);
    req->bucket->decrypted = false;
    req->bucket->created = json_object_get_string(created);
    req->bucket->name = NULL;

    // Attempt to decrypt the name, otherwise
    // we will default the name to the encrypted text.
    // The decrypted flag will be set to indicate the status
    // of decryption for alternative display.
    const char *encrypted_name = json_object_get_string(name);
    if (encrypted_name) {
        char *decrypted_name;
        int error_status = decrypt_bucket_name(req->encrypt_options->mnemonic,
                                               encrypted_name,
                                               &decrypted_name);
        if (!error_status) {
            req->bucket->decrypted = true;
            req->bucket->name = decrypted_name;
        } else if (error_status == STORJ_META_DECRYPTION_ERROR){
            req->bucket->decrypted = false;
            req->bucket->name = strdup(encrypted_name);
        } else {
            req->error_code = STORJ_MEMORY_ERROR;
        }
    }
}

static void get_bucket_id_request_worker(uv_work_t *work)
{
    get_bucket_id_request_t *req = work->data;
    int status_code = 0;

    // Encrypt the bucket name
    char *encrypted_bucket_name;
    if (encrypt_bucket_name(req->encrypt_options->mnemonic,
                            req->bucket_name,
                            &encrypted_bucket_name)) {
        req->error_code = STORJ_MEMORY_ERROR;
        goto cleanup;
    }

    char *escaped_encrypted_bucket_name = str_replace("/", "%2F", encrypted_bucket_name);
    if (!escaped_encrypted_bucket_name) {
        req->error_code = STORJ_MEMORY_ERROR;
        goto cleanup;
    }

    char *path = str_concat_many(2, "/bucket-ids/", escaped_encrypted_bucket_name);
    if (!path) {
        req->error_code = STORJ_MEMORY_ERROR;
        goto cleanup;
    }

    req->error_code = fetch_json(req->http_options,
                                 req->options, "GET", path, NULL,
                                 true, &req->response, &status_code);

    if (req->response != NULL) {
        struct json_object *id;
        json_object_object_get_ex(req->response, "id", &id);
        req->bucket_id = json_object_get_string(id);
    }

    req->status_code = status_code;

cleanup:

    free(encrypted_bucket_name);
    free(escaped_encrypted_bucket_name);
    free(path);
}

static void list_files_request_worker(uv_work_t *work)
{
    list_files_request_t *req = work->data;
    int status_code = 0;

    req->error_code = fetch_json(req->http_options,
                                 req->options, req->method, req->path, req->body,
                                 req->auth, &req->response, &status_code);

    req->status_code = status_code;

    int num_files = 0;
    if (req->response != NULL &&
        json_object_is_type(req->response, json_type_array)) {
        num_files = json_object_array_length(req->response);
    }

    if (num_files > 0) {
        req->files = malloc(sizeof(storj_file_meta_t) * num_files);
        req->total_files = num_files;
    }

    struct json_object *file;
    struct json_object *filename;
    struct json_object *mimetype;
    struct json_object *size;
    struct json_object *id;
    struct json_object *bucket_id;
    struct json_object *created;
    struct json_object *hmac;
    struct json_object *hmac_value;
    struct json_object *erasure;
    struct json_object *index;

    for (int i = 0; i < num_files; i++) {
        file = json_object_array_get_idx(req->response, i);

        json_object_object_get_ex(file, "filename", &filename);
        json_object_object_get_ex(file, "mimetype", &mimetype);
        json_object_object_get_ex(file, "size", &size);
        json_object_object_get_ex(file, "id", &id);
        json_object_object_get_ex(file, "bucket", &bucket_id);
        json_object_object_get_ex(file, "created", &created);
        json_object_object_get_ex(file, "hmac", &hmac);
        json_object_object_get_ex(hmac, "value", &hmac_value);
        json_object_object_get_ex(file, "erasure", &erasure);
        json_object_object_get_ex(file, "index", &index);

        storj_file_meta_t *file = &req->files[i];

        file->created = json_object_get_string(created);
        file->mimetype = json_object_get_string(mimetype);
        file->size = json_object_get_int64(size);
        file->erasure = json_object_get_string(erasure);
        file->index = json_object_get_string(index);
        file->hmac = json_object_get_string(hmac_value);
        file->id = json_object_get_string(id);
        file->bucket_id = json_object_get_string(bucket_id);
        file->decrypted = false;
        file->filename = NULL;

        // Attempt to decrypt the filename, otherwise
        // we will default the filename to the encrypted text.
        // The decrypted flag will be set to indicate the status
        // of decryption for alternative display.
        const char *encrypted_file_name = json_object_get_string(filename);
        if (!encrypted_file_name) {
            continue;
        }
        char *decrypted_file_name;
        int error_status = decrypt_file_name(req->encrypt_options->mnemonic,
                                             req->bucket_id,
                                             encrypted_file_name,
                                             &decrypted_file_name);
        if (!error_status) {
            file->decrypted = true;
            file->filename = decrypted_file_name;
        } else if (error_status == STORJ_META_DECRYPTION_ERROR) {
            file->decrypted = false;
            file->filename = strdup(encrypted_file_name);
        } else {
            req->error_code = STORJ_MEMORY_ERROR;
        }
    }
}

static void get_file_info_request_worker(uv_work_t *work)
{
    get_file_info_request_t *req = work->data;
    int status_code = 0;

    req->error_code = fetch_json(req->http_options,
                                 req->options, req->method, req->path, req->body,
                                 req->auth, &req->response, &status_code);

    req->status_code = status_code;

    struct json_object *filename;
    struct json_object *mimetype;
    struct json_object *size;
    struct json_object *id;
    struct json_object *bucket_id;
    struct json_object *created;
    struct json_object *hmac;
    struct json_object *hmac_value;
    struct json_object *erasure;
    struct json_object *index;

    json_object_object_get_ex(req->response, "filename", &filename);
    json_object_object_get_ex(req->response, "mimetype", &mimetype);
    json_object_object_get_ex(req->response, "size", &size);
    json_object_object_get_ex(req->response, "id", &id);
    json_object_object_get_ex(req->response, "bucket", &bucket_id);
    json_object_object_get_ex(req->response, "created", &created);
    json_object_object_get_ex(req->response, "hmac", &hmac);
    json_object_object_get_ex(hmac, "value", &hmac_value);
    json_object_object_get_ex(req->response, "erasure", &erasure);
    json_object_object_get_ex(req->response, "index", &index);

    req->file = malloc(sizeof(storj_file_meta_t));
    req->file->created = json_object_get_string(created);
    req->file->mimetype = json_object_get_string(mimetype);
    req->file->size = json_object_get_int64(size);
    req->file->erasure = json_object_get_string(erasure);
    req->file->index = json_object_get_string(index);
    req->file->hmac = json_object_get_string(hmac_value);
    req->file->id = json_object_get_string(id);
    req->file->bucket_id = json_object_get_string(bucket_id);
    req->file->decrypted = false;
    req->file->filename = NULL;

    // Attempt to decrypt the filename, otherwise
    // we will default the filename to the encrypted text.
    // The decrypted flag will be set to indicate the status
    // of decryption for alternative display.
    const char *encrypted_file_name = json_object_get_string(filename);
    if (encrypted_file_name) {
        char *decrypted_file_name;
        int error_status = decrypt_file_name(req->encrypt_options->mnemonic,
                                             req->bucket_id,
                                             encrypted_file_name,
                                             &decrypted_file_name);
        if (!error_status) {
            req->file->decrypted = true;
            req->file->filename = decrypted_file_name;
        } else if (error_status == STORJ_META_DECRYPTION_ERROR) {
        	req->file->decrypted = false;
        	req->file->filename = strdup(encrypted_file_name);
        } else {
            req->error_code = STORJ_MEMORY_ERROR;
        }
    }
}

static void get_file_id_request_worker(uv_work_t *work)
{
    get_file_id_request_t *req = work->data;
    int status_code = 0;

    char *encrypted_file_name;
    if (encrypt_file_name(req->encrypt_options->mnemonic,
                          req->bucket_id,
                          req->file_name,
                          &encrypted_file_name)) {
        req->error_code = STORJ_MEMORY_ERROR;
        goto cleanup;
    }

    char *escaped_encrypted_file_name = str_replace("/", "%2F", encrypted_file_name);
    if (!escaped_encrypted_file_name) {
        req->error_code = STORJ_MEMORY_ERROR;
        goto cleanup;
    }

    char *path = str_concat_many(4, "/buckets/", req->bucket_id,
                                    "/file-ids/", escaped_encrypted_file_name);
    if (!path) {
        req->error_code = STORJ_MEMORY_ERROR;
        goto cleanup;
    }

    req->error_code = fetch_json(req->http_options,
                                 req->options, "GET", path, NULL,
                                 true, &req->response, &status_code);

    if (req->response != NULL) {
        struct json_object *id;
        json_object_object_get_ex(req->response, "id", &id);
        req->file_id = json_object_get_string(id);
    }

    req->status_code = status_code;

cleanup:

    free(encrypted_file_name);
    free(escaped_encrypted_file_name);
    free(path);
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

static list_files_request_t *list_files_request_new(
    storj_http_options_t *http_options,
    storj_bridge_options_t *options,
    storj_encrypt_options_t *encrypt_options,
    const char *bucket_id,
    char *method,
    char *path,
    struct json_object *request_body,
    bool auth,
    void *handle)
{
    list_files_request_t *req = malloc(sizeof(list_files_request_t));
    if (!req) {
        return NULL;
    }

    req->http_options = http_options;
    req->options = options;
    req->encrypt_options = encrypt_options;
    req->bucket_id = bucket_id;
    req->method = method;
    req->path = path;
    req->auth = auth;
    req->body = request_body;
    req->response = NULL;
    req->files = NULL;
    req->total_files = 0;
    req->error_code = 0;
    req->status_code = 0;
    req->handle = handle;

    return req;
}

static get_file_info_request_t *get_file_info_request_new(
    storj_http_options_t *http_options,
    storj_bridge_options_t *options,
    storj_encrypt_options_t *encrypt_options,
    const char *bucket_id,
    char *method,
    char *path,
    struct json_object *request_body,
    bool auth,
    void *handle)
{
    get_file_info_request_t *req = malloc(sizeof(get_file_info_request_t));
    if (!req) {
        return NULL;
    }

    req->http_options = http_options;
    req->options = options;
    req->encrypt_options = encrypt_options;
    req->bucket_id = bucket_id;
    req->method = method;
    req->path = path;
    req->auth = auth;
    req->body = request_body;
    req->response = NULL;
    req->file = NULL;
    req->error_code = 0;
    req->status_code = 0;
    req->handle = handle;

    return req;
}

static create_bucket_request_t *create_bucket_request_new(
    storj_http_options_t *http_options,
    storj_bridge_options_t *bridge_options,
    storj_encrypt_options_t *encrypt_options,
    const char *bucket_name,
    void *handle)
{
    create_bucket_request_t *req = malloc(sizeof(create_bucket_request_t));
    if (!req) {
        return NULL;
    }

    req->http_options = http_options;
    req->encrypt_options = encrypt_options;
    req->bridge_options = bridge_options;
    req->bucket_name = bucket_name;
    req->encrypted_bucket_name = NULL;
    req->response = NULL;
    req->bucket = NULL;
    req->error_code = 0;
    req->status_code = 0;
    req->handle = handle;

    return req;
}

static get_buckets_request_t *get_buckets_request_new(
    storj_http_options_t *http_options,
    storj_bridge_options_t *options,
    storj_encrypt_options_t *encrypt_options,
    char *method,
    char *path,
    struct json_object *request_body,
    bool auth,
    void *handle)
{
    get_buckets_request_t *req = malloc(sizeof(get_buckets_request_t));
    if (!req) {
        return NULL;
    }

    req->http_options = http_options;
    req->options = options;
    req->encrypt_options = encrypt_options;
    req->method = method;
    req->path = path;
    req->auth = auth;
    req->body = request_body;
    req->response = NULL;
    req->buckets = NULL;
    req->total_buckets = 0;
    req->error_code = 0;
    req->status_code = 0;
    req->handle = handle;

    return req;
}

static get_bucket_request_t *get_bucket_request_new(
        storj_http_options_t *http_options,
        storj_bridge_options_t *options,
        storj_encrypt_options_t *encrypt_options,
        char *method,
        char *path,
        struct json_object *request_body,
        bool auth,
        void *handle)
{
    get_bucket_request_t *req = malloc(sizeof(get_bucket_request_t));
    if (!req) {
        return NULL;
    }

    req->http_options = http_options;
    req->options = options;
    req->encrypt_options = encrypt_options;
    req->method = method;
    req->path = path;
    req->auth = auth;
    req->body = request_body;
    req->response = NULL;
    req->bucket = NULL;
    req->error_code = 0;
    req->status_code = 0;
    req->handle = handle;

    return req;
}

static get_bucket_id_request_t *get_bucket_id_request_new(
        storj_http_options_t *http_options,
        storj_bridge_options_t *options,
        storj_encrypt_options_t *encrypt_options,
        const char *bucket_name,
        void *handle)
{
    get_bucket_id_request_t *req = malloc(sizeof(get_bucket_id_request_t));
    if (!req) {
        return NULL;
    }

    req->http_options = http_options;
    req->options = options;
    req->encrypt_options = encrypt_options;
    req->bucket_name = bucket_name;
    req->response = NULL;
    req->bucket_id = NULL;
    req->error_code = 0;
    req->status_code = 0;
    req->handle = handle;

    return req;
}

static get_file_id_request_t *get_file_id_request_new(
        storj_http_options_t *http_options,
        storj_bridge_options_t *options,
        storj_encrypt_options_t *encrypt_options,
        const char *bucket_id,
        const char *file_name,
        void *handle)
{
    get_file_id_request_t *req = malloc(sizeof(get_file_id_request_t));
    if (!req) {
        return NULL;
    }

    req->http_options = http_options;
    req->options = options;
    req->encrypt_options = encrypt_options;
    req->bucket_id = bucket_id;
    req->file_name = file_name;
    req->response = NULL;
    req->file_id = NULL;
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

static int get_filepath_from_filedescriptor(FILE *file_descriptor, char *file_path)
{
    #define MAXLEN 200
    char procpath[MAXLEN + 1] = {0x00};
    int fd = -1;

#ifdef __APPLE__
    if (fcntl(fileno(file_descriptor), F_GETPATH, file_path) != -1) {
        printf("\n *** IAM MacOS *** download destination file path = %s\n", file_path);
    } else {
        printf("[%s][%s][%d] Invalid file path \n", __FILE__, __FUNCTION__, __LINE__);
        return -1;
    }
#else
    /*
     * Get the low-level file descriptor of the open file
     */
    fd = fileno(file_descriptor);
    if (fd < 0) {
        printf("[%s][%s][%d] Invalid file descriptor \n", __FILE__, __FUNCTION__, __LINE__);
        return -1;
    }

    /*
     * Construct a string with the /proc path of the file
     * descriptor (which is a symbolic link to the real
     * file).
     */
    snprintf(procpath, MAXLEN, "/proc/self/fd/%d", fd);

    /*
     * Get the path the symlink is pointing to.
     */
    if (readlink(procpath, file_path, (size_t) MAXLEN) < 0) {
        printf("[%s][%s][%d] Invalid file path \n", __FILE__, __FUNCTION__, __LINE__);
        return -1;
    }
#endif

    printf("\n download destination file path = %s\n", file_path);
    return 0;
}

STORJ_API struct storj_env *storj_init_env(storj_bridge_options_t *options,
                                 storj_encrypt_options_t *encrypt_options,
                                 storj_http_options_t *http_options,
                                 storj_log_options_t *log_options)
{
    curl_global_init(CURL_GLOBAL_ALL);

    uv_loop_t *loop = uv_default_loop();
    if (!loop) {
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

    env->encrypt_options = eo;

    // Set tmp_path
    struct stat sb;
    env->tmp_path = NULL;
    if (env->tmp_path &&
        stat(env->tmp_path, &sb) == 0 &&
        S_ISDIR(sb.st_mode)) {
        env->tmp_path = strdup(env->tmp_path);
    } else if (getenv("STORJ_TEMP") &&
               stat(getenv("STORJ_TEMP"), &sb) == 0 &&
               S_ISDIR(sb.st_mode)) {
        env->tmp_path = strdup(getenv("STORJ_TEMP"));
#ifdef _WIN32
    } else if (getenv("TEMP") &&
               stat(getenv("TEMP"), &sb) == 0 &&
               S_ISDIR(sb.st_mode)) {
        env->tmp_path = strdup(getenv("TEMP"));
#else
    } else if ("/tmp" && stat("/tmp", &sb) == 0 && S_ISDIR(sb.st_mode)) {
        env->tmp_path = strdup("/tmp");
#endif
    } else {
        env->tmp_path = NULL;
    }

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
    if (http_options->cainfo_path) {
        ho->cainfo_path = strdup(http_options->cainfo_path);
    } else {
        ho->cainfo_path = NULL;
    }
    ho->low_speed_limit = http_options->low_speed_limit;
    ho->low_speed_time = http_options->low_speed_time;
    if (http_options->timeout == 0 ||
        http_options->timeout >= STORJ_HTTP_TIMEOUT) {
        ho->timeout = http_options->timeout;
    } else {
        ho->timeout = STORJ_HTTP_TIMEOUT;
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

STORJ_API int storj_destroy_env(storj_env_t *env)
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

    if (env->tmp_path) {
        free((char *)env->tmp_path);
    }

    free(env->encrypt_options);

    // free all http options
    free((char *)env->http_options->user_agent);
    if (env->http_options->proxy_url) {
        free((char *)env->http_options->proxy_url);
    }
    if (env->http_options->cainfo_path) {
        free((char *)env->http_options->cainfo_path);
    }
    free(env->http_options);

    // free the log levels
    free(env->log);

    // free the environment
    free(env);

    curl_global_cleanup();

    return status;
}

STORJ_API int storj_encrypt_auth(const char *passphrase,
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

STORJ_API int storj_encrypt_write_auth(const char *filepath,
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

STORJ_API int storj_decrypt_auth(const char *buffer,
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

STORJ_API int storj_decrypt_read_auth(const char *filepath,
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

STORJ_API uint64_t storj_util_timestamp()
{
    return get_time_milliseconds();
}

STORJ_API int storj_mnemonic_generate(int strength, char **buffer)
{
    return mnemonic_generate(strength, buffer);
}

STORJ_API bool storj_mnemonic_check(const char *mnemonic)
{
    return mnemonic_check(mnemonic);
}

STORJ_API char *storj_strerror(int error_code)
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
            return "Bridge rate limit error";
        case STORJ_BRIDGE_BUCKET_NOTFOUND_ERROR:
            return "Bucket is not found";
        case STORJ_BRIDGE_FILE_NOTFOUND_ERROR:
            return "File is not found";
        case STORJ_BRIDGE_BUCKET_FILE_EXISTS:
            return "File already exists";
        case STORJ_BRIDGE_OFFER_ERROR:
            return "Unable to receive storage offer";
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
        case STORJ_FILE_READ_ERROR:
            return "File read error";
        case STORJ_FILE_WRITE_ERROR:
            return "File write error";
        case STORJ_BRIDGE_FRAME_ERROR:
            return "Bridge frame request error";
        case STORJ_FILE_ENCRYPTION_ERROR:
            return "File encryption error";
        case STORJ_FILE_SIZE_ERROR:
            return "File size error";
        case STORJ_FILE_DECRYPTION_ERROR:
            return "File decryption error";
        case STORJ_FILE_GENERATE_HMAC_ERROR:
            return "File hmac generation error";
        case STORJ_FILE_SHARD_MISSING_ERROR:
            return "File missing shard error";
        case STORJ_FILE_RECOVER_ERROR:
            return "File recover error";
        case STORJ_FILE_RESIZE_ERROR:
            return "File resize error";
        case STORJ_FILE_UNSUPPORTED_ERASURE:
            return "File unsupported erasure code error";
        case STORJ_FILE_PARITY_ERROR:
            return "File create parity error";
        case STORJ_META_ENCRYPTION_ERROR:
            return "Meta encryption error";
        case STORJ_META_DECRYPTION_ERROR:
            return "Meta decryption error";
        case STORJ_TRANSFER_CANCELED:
            return "File transfer canceled";
        case STORJ_MEMORY_ERROR:
            return "Memory error";
        case STORJ_MAPPING_ERROR:
            return "Memory mapped file error";
        case STORJ_UNMAPPING_ERROR:
            return "Memory mapped file unmap error";
        case STORJ_QUEUE_ERROR:
            return "Queue error";
        case STORJ_HEX_DECODE_ERROR:
            return "Unable to decode hex string";
        case STORJ_TRANSFER_OK:
            return "No errors";
        default:
            return "Unknown error";
    }
}

STORJ_API int storj_bridge_get_info(storj_env_t *env, void *handle, uv_after_work_cb cb)
{
    uv_work_t *work = json_request_work_new(env,"GET", "/", NULL,
                                            false, handle);
    if (!work) {
        return STORJ_MEMORY_ERROR;
    }

    return uv_queue_work(env->loop, (uv_work_t*) work, json_request_worker, cb);
}

STORJ_API int storj_bridge_get_buckets(storj_env_t *env, void *handle, uv_after_work_cb cb)
{
    uv_work_t *work = uv_work_new();
    if (!work) {
        return STORJ_MEMORY_ERROR;
    }
    work->data = get_buckets_request_new(env->http_options,
                                         env->bridge_options,
                                         env->encrypt_options,
                                         "GET", "/buckets",
                                         NULL, true, handle);
    if (!work->data) {
        return STORJ_MEMORY_ERROR;
    }

    return uv_queue_work(env->loop, (uv_work_t*) work,
                         get_buckets_request_worker, cb);
}

STORJ_API void storj_free_get_buckets_request(get_buckets_request_t *req)
{
    if (req->response) {
        json_object_put(req->response);
    }
    if (req->buckets && req->total_buckets > 0) {
        for (int i = 0; i < req->total_buckets; i++) {
            free((char *)req->buckets[i].name);
        }
    }
    free(req->buckets);
    free(req);
}

STORJ_API int storj_bridge_create_bucket(storj_env_t *env,
                               const char *name,
                               void *handle,
                               uv_after_work_cb cb)
{
    uv_work_t *work = uv_work_new();
    if (!work) {
        return STORJ_MEMORY_ERROR;
    }

    work->data = create_bucket_request_new(env->http_options,
                                           env->bridge_options,
                                           env->encrypt_options,
                                           name,
                                           handle);
    if (!work->data) {
        return STORJ_MEMORY_ERROR;
    }

    return uv_queue_work(env->loop, (uv_work_t*) work,
                         create_bucket_request_worker, cb);
}

STORJ_API int storj_bridge_delete_bucket(storj_env_t *env,
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

STORJ_API int storj_bridge_get_bucket(storj_env_t *env,
                                      const char *id,
                                      void *handle,
                                      uv_after_work_cb cb)
{
    uv_work_t *work = uv_work_new();
    if (!work) {
        return STORJ_MEMORY_ERROR;
    }

    char *path = str_concat_many(2, "/buckets/", id);
    if (!path) {
        return STORJ_MEMORY_ERROR;
    }

    work->data = get_bucket_request_new(env->http_options,
                                        env->bridge_options,
                                        env->encrypt_options,
                                        "GET", path,
                                        NULL, true, handle);
    if (!work->data) {
        return STORJ_MEMORY_ERROR;
    }

    return uv_queue_work(env->loop, (uv_work_t*) work, get_bucket_request_worker, cb);
}

STORJ_API void storj_free_get_bucket_request(get_bucket_request_t *req)
{
    if (req->response) {
        json_object_put(req->response);
    }
    free(req->path);
    if (req->bucket) {
        free((char *)req->bucket->name);
    }
    free(req->bucket);
    free(req);
}

STORJ_API int storj_bridge_get_bucket_id(storj_env_t *env,
                                         const char *name,
                                         void *handle,
                                         uv_after_work_cb cb)
{
    uv_work_t *work = uv_work_new();
    if (!work) {
        return STORJ_MEMORY_ERROR;
    }

    work->data = get_bucket_id_request_new(env->http_options,
                                           env->bridge_options,
                                           env->encrypt_options,
                                           name, handle);
    if (!work->data) {
        return STORJ_MEMORY_ERROR;
    }

    return uv_queue_work(env->loop, (uv_work_t*) work, get_bucket_id_request_worker, cb);
}

STORJ_API int storj_bridge_list_files(storj_env_t *env,
                            const char *id,
                            void *handle,
                            uv_after_work_cb cb)
{
    char *path = str_concat_many(3, "/buckets/", id, "/files");
    if (!path) {
        return STORJ_MEMORY_ERROR;
    }

    uv_work_t *work = uv_work_new();
    if (!work) {
        return STORJ_MEMORY_ERROR;
    }
    work->data = list_files_request_new(env->http_options,
                                        env->bridge_options,
                                        env->encrypt_options,
                                        id, "GET", path,
                                        NULL, true, handle);

    if (!work->data) {
        return STORJ_MEMORY_ERROR;
    }

    return uv_queue_work(env->loop, (uv_work_t*) work,
                         list_files_request_worker, cb);
}

STORJ_API void storj_free_list_files_request(list_files_request_t *req)
{
    if (req->response) {
        json_object_put(req->response);
    }
    free(req->path);
    if (req->files && req->total_files > 0) {
        for (int i = 0; i < req->total_files; i++) {
            free((char *)req->files[i].filename);
        }
    }
    free(req->files);
    free(req);
}

STORJ_API int storj_bridge_create_bucket_token(storj_env_t *env,
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

STORJ_API int storj_bridge_get_file_pointers(storj_env_t *env,
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

STORJ_API int storj_bridge_delete_file(storj_env_t *env,
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

STORJ_API int storj_bridge_create_frame(storj_env_t *env,
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

STORJ_API int storj_bridge_get_frames(storj_env_t *env,
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

STORJ_API int storj_bridge_get_frame(storj_env_t *env,
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

STORJ_API int storj_bridge_delete_frame(storj_env_t *env,
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

STORJ_API int storj_bridge_get_file_info(storj_env_t *env,
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

    uv_work_t *work = uv_work_new();
    if (!work) {
        return STORJ_MEMORY_ERROR;
    }

    work->data = get_file_info_request_new(env->http_options,
                                           env->bridge_options,
                                           env->encrypt_options,
                                           bucket_id, "GET", path,
                                           NULL, true, handle);

    if (!work->data) {
        return STORJ_MEMORY_ERROR;
    }

    return uv_queue_work(env->loop, (uv_work_t*) work,
                         get_file_info_request_worker, cb);
}

STORJ_API int storj_bridge_get_file_id(storj_env_t *env,
                                       const char *bucket_id,
                                       const char *file_name,
                                       void *handle,
                                       uv_after_work_cb cb)
{
    uv_work_t *work = uv_work_new();
    if (!work) {
        return STORJ_MEMORY_ERROR;
    }

    work->data = get_file_id_request_new(env->http_options,
                                         env->bridge_options,
                                         env->encrypt_options,
                                         bucket_id, file_name, handle);
    if (!work->data) {
        return STORJ_MEMORY_ERROR;
    }

    return uv_queue_work(env->loop, (uv_work_t*) work, get_file_id_request_worker, cb);
}

STORJ_API void storj_free_get_file_info_request(get_file_info_request_t *req)
{
    if (req->response) {
        json_object_put(req->response);
    }
    free(req->path);
    if (req->file) {
        free((char *)req->file->filename);
    }
    free(req->file);
    free(req);
}

STORJ_API int storj_bridge_list_mirrors(storj_env_t *env,
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

STORJ_API int storj_bridge_register(storj_env_t *env,
                          const char *email,
                          const char *password,
                          void *handle,
                          uv_after_work_cb cb)
{
    uint8_t sha256_digest[SHA256_DIGEST_SIZE];
    sha256_of_str((uint8_t *)password, strlen(password), sha256_digest);

    char *hex_str = hex2str(SHA256_DIGEST_SIZE, sha256_digest);
    if (!hex_str) {
        return STORJ_MEMORY_ERROR;
    }

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

/** @brief Enumerable that defines that status of a pointer
 *
 * A pointer will begin as created, and move forward until an error
 * occurs, in which case it will start moving backwards from the error
 * state until it has been replaced and reset back to created. This process
 * can continue until success.
 */
typedef enum {
    POINTER_BEING_REPLACED = -3,
    POINTER_ERROR_REPORTED = -2,
    POINTER_ERROR = -1,
    POINTER_CREATED = 0,
    POINTER_BEING_DOWNLOADED = 1,
    POINTER_DOWNLOADED = 2,
    POINTER_MISSING = 3,
    POINTER_FINISHED = 4
} storj_pointer_status_t;

STORJ_API int storj_download_state_serialize(storj_download_state_t *state)
{
    char filePath[PATH_MAX] = {0x00};

    if (get_filepath_from_filedescriptor(state->destination, filePath) == 0x00)
    {
        strcat(filePath,".json");
        unlink(filePath);
    } else {
        return -1;
    }

    /* create a json object for the download_state struct */
    struct json_object *body = json_object_new_object();
    json_object_object_add(body, "total_bytes",
                           json_object_new_int64(state->total_bytes));

    /* add here storj_file_meta_t */
    struct json_object *jfile_info = json_object_new_object();
    if (state->info->created != NULL) {
        json_object_object_add(jfile_info, "created",
                               json_object_new_string(state->info->created));
    }
    if (state->info->filename != NULL) {
        json_object_object_add(jfile_info, "filename",
                               json_object_new_string(state->info->filename));
    }
    if (state->info->mimetype != NULL) {
        json_object_object_add(jfile_info, "mimetype",
                               json_object_new_string(state->info->mimetype));
    }
    if (state->info->erasure != NULL) {
        json_object_object_add(jfile_info, "erasure",
                               json_object_new_string(state->info->erasure));
    }
    json_object_object_add(jfile_info, "size",
                           json_object_new_int64(state->info->size));
    if (state->info->hmac != NULL) {
        json_object_object_add(jfile_info, "hmac",
                               json_object_new_string(state->info->hmac));
    }
    if (state->info->id != NULL) {
        json_object_object_add(jfile_info, "id",
                               json_object_new_string(state->info->id));
    }
    if (state->info->bucket_id != NULL) {
        json_object_object_add(jfile_info, "bucket_id",
                               json_object_new_string(state->info->bucket_id));
    }
    json_object_object_add(jfile_info, "decrypted",
                           json_object_new_boolean(state->info->decrypted));
    if (state->info->index != NULL) {
        json_object_object_add(jfile_info, "index",
                               json_object_new_string(state->info->index));
    }
    if (state->info->hmac != NULL) {
        json_object_object_add(jfile_info, "hmac",
                               json_object_new_string(state->info->hmac));
    }
    json_object_object_add(body, "storj_file_meta_t", jfile_info);

    json_object_object_add(body, "requesting_info",
                           json_object_new_boolean(state->requesting_info));
    json_object_object_add(body, "info_fail_count",
                           json_object_new_int(state->info_fail_count));
    if (state->file_id != NULL) {
        json_object_object_add(body, "file_id",
                               json_object_new_string(state->file_id));
    }
    if (state->bucket_id != NULL) {
        json_object_object_add(body, "bucket_id",
                               json_object_new_string(state->bucket_id));
    }
    json_object_object_add(body, "finished",
                           json_object_new_boolean(state->finished));
    json_object_object_add(body, "canceled",
                           json_object_new_boolean(state->canceled));
    json_object_object_add(body, "shard_size",
                           json_object_new_int64(state->shard_size));
    json_object_object_add(body, "total_shards",
                           json_object_new_int(state->total_shards));
    json_object_object_add(body, "download_max_concurrency",
                           json_object_new_int(state->download_max_concurrency));
    json_object_object_add(body, "completed_shards",
                           json_object_new_int(state->completed_shards));
    json_object_object_add(body, "resolving_shards",
                           json_object_new_int(state->recovering_shards));

    /* create json array of shard pointers */
    struct json_object *jptr_array = json_object_new_array();
    int i = 0x00;
    while (i < state->total_pointers) {

        struct json_object *jptr = json_object_new_object();
        struct json_object *jfarmer = json_object_new_object();
        storj_pointer_t *pointer = &state->pointers[i];

        json_object_object_add(jptr, "replace_count",
                               json_object_new_int(pointer->replace_count));
        if (pointer->token) {
            json_object_object_add(jptr, "token",
                                   json_object_new_string(pointer->token));
        }
        if (pointer->shard_hash) {
            json_object_object_add(jptr, "hash",
                                   json_object_new_string(pointer->shard_hash));
        }
        json_object_object_add(jptr, "index",
                               json_object_new_int(pointer->index));
        json_object_object_add(jptr, "status",
                               json_object_new_int(pointer->status));
        json_object_object_add(jptr, "size",
                               json_object_new_int64(pointer->size));
        json_object_object_add(jptr, "parity",
                               json_object_new_boolean(pointer->parity));
        json_object_object_add(jptr, "downloaded_size",
                               json_object_new_int64(pointer->downloaded_size));
        if (state->pointers->farmer_id) {
            json_object_object_add(jfarmer, "nodeID",
                                   json_object_new_string(pointer->farmer_id));
        }
        if (state->pointers->farmer_address) {
            json_object_object_add(jfarmer, "address",
                                   json_object_new_string(pointer->farmer_address));
        }
        json_object_object_add(jfarmer, "port",
                               json_object_new_int(pointer->farmer_port));
        json_object_object_add(jptr, "farmer", jfarmer);
        json_object_array_add(jptr_array, jptr);

        i++;
    }

    json_object_object_add(body, "storj_pointer_t", jptr_array);

    if (state->excluded_farmer_ids != NULL) {
        json_object_object_add(body, "excluded_farmer_ids",
                               json_object_new_string(state->excluded_farmer_ids));
    }
    json_object_object_add(body, "total_pointers",
                           json_object_new_int64(state->total_pointers));
    json_object_object_add(body, "rs",
                           json_object_new_boolean(state->rs));
    json_object_object_add(body, "recovering_shards",
                           json_object_new_boolean(state->recovering_shards));
    json_object_object_add(body, "truncated",
                           json_object_new_boolean(state->truncated));
    json_object_object_add(body, "pointers_completed",
                           json_object_new_boolean(state->pointers_completed));
    json_object_object_add(body, "pointer_fail_count",
                           json_object_new_int(state->pointer_fail_count));
    json_object_object_add(body, "requesting_pointers",
                           json_object_new_boolean(state->requesting_pointers));
    json_object_object_add(body, "error_status",
                           json_object_new_int(state->error_status));
    json_object_object_add(body, "writing",
                           json_object_new_boolean(state->writing));
    if (state->hmac != NULL) {
        json_object_object_add(body, "hmac",
                               json_object_new_string(state->hmac));
    }
    json_object_object_add(body, "pending_work_count",
                           json_object_new_int64(state->pending_work_count));

    json_object *jdwn = json_object_new_object();
    json_object_object_add(jdwn, "storj_download_state_t", body);

    FILE *fd = fopen(filePath, "w");
    fprintf(fd, "%s", json_object_get_string(jdwn));
    fclose(fd);

    json_object_put(jdwn);
    json_object_put(body);
    json_object_put(jfile_info);
    json_object_put(jptr_array);

    return 0;
}

static void set_pointer_from_json(storj_download_state_t *state,
                                  storj_pointer_t *p,
                                  struct json_object *json,
                                  bool is_replaced)
{
    if (!json_object_is_type(json, json_type_object)) {
        state->error_status = STORJ_BRIDGE_JSON_ERROR;
        return;
    }

    struct json_object *token_value;
    char *token = NULL;
    if (json_object_object_get_ex(json, "token", &token_value)) {
        token = (char *)json_object_get_string(token_value);
    }

    struct json_object *hash_value;
    if (!json_object_object_get_ex(json, "hash", &hash_value)) {
        state->error_status = STORJ_BRIDGE_JSON_ERROR;
        return;
    }
    char *hash = (char *)json_object_get_string(hash_value);

    struct json_object *status_value;
    if (!json_object_object_get_ex(json, "status", &status_value)) {
        state->error_status = STORJ_BRIDGE_JSON_ERROR;
        return;
    }
    int status = json_object_get_int(status_value);

    struct json_object *size_value;
    if (!json_object_object_get_ex(json, "size", &size_value)) {
        state->error_status = STORJ_BRIDGE_JSON_ERROR;
        return;
    }
    uint64_t size = json_object_get_int64(size_value);

    struct json_object *parity_value;
    bool parity = false;
    if (json_object_object_get_ex(json, "parity", &parity_value)) {
        parity = json_object_get_boolean(parity_value);
    }

    struct json_object *index_value;
    if (!json_object_object_get_ex(json, "index", &index_value)) {
        state->error_status = STORJ_BRIDGE_JSON_ERROR;
        return;
    }
    uint32_t index = json_object_get_int(index_value);


    struct json_object *farmer_value;
    char *address = NULL;
    uint32_t port = 0;
    char *farmer_id = NULL;

    if (json_object_object_get_ex(json, "farmer", &farmer_value) &&
        json_object_is_type(farmer_value, json_type_object)) {

        struct json_object *address_value;
        if (!json_object_object_get_ex(farmer_value, "address",
                                       &address_value)) {
            state->error_status = STORJ_BRIDGE_JSON_ERROR;
            return;
        }
        address = (char *)json_object_get_string(address_value);

        struct json_object *port_value;
        if (!json_object_object_get_ex(farmer_value, "port", &port_value)) {
            state->error_status = STORJ_BRIDGE_JSON_ERROR;
            return;
        }
        port = json_object_get_int(port_value);

        struct json_object *farmer_id_value;
        if (!json_object_object_get_ex(farmer_value, "nodeID",
                                       &farmer_id_value)) {
            state->error_status = STORJ_BRIDGE_JSON_ERROR;
            return;
        }
        farmer_id = (char *)json_object_get_string(farmer_id_value);
    }


    if (is_replaced) {
        p->replace_count += 1;
    } else {
        p->replace_count = 0;
    }

    // Check to see if we have a token for this shard, otherwise
    // we will immediately move this shard to POINTER_MISSING
    // so that it can be retried and possibly recovered.
    if (address && token) {
        // reset the status
        p->status = POINTER_CREATED;
    } else {
        state->log->warn(state->env->log_options,
                         state->handle,
                         "Missing shard %s at index %i",
                         hash,
                         index);
        p->status = POINTER_MISSING;
    }

    p->size = size;
    p->parity = parity;
    p->downloaded_size = 0;
    p->index = index;
    p->farmer_port = port;
    p->status = status;

    if (is_replaced) {
        free(p->token);
        free(p->shard_hash);
        free(p->farmer_address);
        free(p->farmer_id);
    }
    if (token) {
        p->token = strdup(token);
    } else {
        p->token = NULL;
    }
    p->shard_hash = strdup(hash);
    if (address) {
        p->farmer_address = strdup(address);
    } else {
        p->farmer_address = NULL;
    }
    if (farmer_id) {
        p->farmer_id = strdup(farmer_id);
    } else {
        p->farmer_id = NULL;
    }

    // setup exchange report values
    p->report = malloc(
            sizeof(storj_exchange_report_t));

    if (!p->report) {
        state->error_status = STORJ_MEMORY_ERROR;
        return;
    }


    const char *client_id = state->env->bridge_options->user;
    p->report->reporter_id = strdup(client_id);
    p->report->client_id = strdup(client_id);
    p->report->data_hash = strdup(hash);
    if (farmer_id) {
        p->report->farmer_id = strdup(farmer_id);
    } else {
        p->report->farmer_id = NULL;
    }
    p->report->send_status = 0; // not sent
    p->report->send_count = 0;

    // these values will be changed in after_request_shard
    p->report->start = 0;
    p->report->end = 0;
    p->report->code = STORJ_REPORT_FAILURE;
    p->report->message = STORJ_REPORT_DOWNLOAD_ERROR;

    p->work = NULL;

    if (!state->shard_size) {
        // TODO make sure all except last shard is the same size
        state->shard_size = size;
        state->log->debug(state->env->log_options,
                          state->handle,
                          "Shard size set to %" PRIu64,
                            state->shard_size);
    };
}

static void append_pointers_to_state(storj_download_state_t *state,
                                     struct json_object *res)
{
    int length = json_object_array_length(res);

    if (length == 0) {
        state->log->debug(state->env->log_options,
                          state->handle,
                          "Finished requesting pointers");
        state->pointers_completed = true;
    } else if (length > 0) {

        state->total_pointers = length;
        int total_pointers = state->total_pointers;

        if (state->total_pointers > 0) {
            state->pointers = realloc(state->pointers,
                                      total_pointers * sizeof(storj_pointer_t));
            printf("storj.c state->pointers = 0x%X\n", state->pointers);
        }
        if (!state->pointers) {
            state->error_status = STORJ_MEMORY_ERROR;
            return;
        }

        state->total_pointers = total_pointers;
        state->total_shards = total_pointers;

        for (int i = 0; i < length; i++) {
            struct json_object *json = json_object_array_get_idx(res, i);
            set_pointer_from_json(state, &state->pointers[i], json, false);

            // Keep track of the number of data and parity pointers
            storj_pointer_t *pointer = &state->pointers[i];
            if (pointer->parity) {
                state->total_parity_pointers += 1;
            }
        }
    }
}

STORJ_API int storj_download_state_deserialize(storj_download_state_t *state, char *file_path)
{
    //FILE *fd = fopen(file_path, "r");
    struct json_object *jdwnld_obj;
    jdwnld_obj = json_object_from_file(file_path);

    struct json_object *jstorj_download_state_t;
    if (json_object_object_get_ex(jdwnld_obj, "storj_download_state_t", &jstorj_download_state_t)) {
        /* setup download state */
        json_object_object_get_ex(jstorj_download_state_t, "file_id", &jdwnld_obj);
        state->file_id = json_object_get_string(jdwnld_obj);

        json_object_object_get_ex(jstorj_download_state_t, "bucket_id", &jdwnld_obj);
        state->bucket_id = json_object_get_string(jdwnld_obj);

        /* setup the storj_file_meta_t */
        struct json_object *jstorj_file_meta_t;
        if (json_object_object_get_ex(jstorj_download_state_t, "storj_file_meta_t", &jstorj_file_meta_t)) {
            storj_file_meta_t *file = malloc(sizeof(storj_file_meta_t));
            memset(file, 0x00, sizeof(storj_file_meta_t));
            state->info = file;

            /* get file hmac */
            json_object_object_get_ex(jstorj_file_meta_t, "hmac", &jdwnld_obj);
            state->info->hmac = strdup(json_object_get_string(jdwnld_obj));

            /* get file index */
            json_object_object_get_ex(jstorj_file_meta_t, "index", &jdwnld_obj);
            state->info->index = strdup(json_object_get_string(jdwnld_obj));
        } else {
            printf("hello hello groot inside deserilalize \n");
            return -1;
        }


        struct json_object *jstorj_pointer_t;
        json_object_object_get_ex(jstorj_download_state_t, "storj_pointer_t", &jstorj_pointer_t);

        append_pointers_to_state(state, jstorj_pointer_t);

        return 0;
    } else {
        return -1;
    }
}
