#include <time.h>
#include "storj.h"
#include "utils.h"
#include "crypto.h"

char *_storj_last_error = "";
char **STORJ_LAST_ERROR = &_storj_last_error;

static void create_bucket_request_worker(uv_work_t *work)
{
    create_bucket_request_t *req = work->data;

    BucketInfo *created_bucket = malloc(sizeof(BucketInfo));
    *created_bucket = create_bucket(req->project_ref,
                                    strdup(req->bucket_name),
                                    NULL, STORJ_LAST_ERROR);
    STORJ_RETURN_SET_REQ_ERROR_IF_LAST_ERROR;

    char created_str[32];
    time_t created_time = (time_t)created_bucket->created;
    strftime(created_str, 32, "%DT%T%Z", localtime(&created_time));

    req->bucket_name = strdup(created_bucket->name);
    req->bucket = malloc(sizeof(storj_bucket_meta_t));

    req->bucket->name = strdup(created_bucket->name);
    req->bucket->id = strdup(created_bucket->name);
    req->bucket->created = strdup(created_str);
    req->bucket->decrypted = true;
    // NB: this field is unused; it only exists for backwards compatibility as it is
    //  passed to `json_object_put` by api consumers.
    //  (see: https://svn.filezilla-project.org/svn/FileZilla3/trunk/src/storj/fzstorj.cpp)
    req->response = json_object_new_object();

    free_bucket_info((BucketInfo *)&created_bucket);
}

static void get_buckets_request_worker(uv_work_t *work)
{
    get_buckets_request_t *req = work->data;

    BucketList bucket_list = list_buckets(req->project_ref, NULL, STORJ_LAST_ERROR);
    STORJ_RETURN_SET_REQ_ERROR_IF_LAST_ERROR;

    req->total_buckets = bucket_list.length;

    if (bucket_list.length > 0) {
        req->buckets = malloc(sizeof(storj_bucket_meta_t) * bucket_list.length);

        BucketInfo bucket_item;
        for (int i = 0; i < bucket_list.length; i++) {
            bucket_item = bucket_list.items[i];
            storj_bucket_meta_t *bucket = &req->buckets[i];

            char created_str[32];
            time_t created_time = (time_t)bucket_item.created;
            strftime(created_str, 32, "%DT%T%Z", localtime(&created_time));

            bucket->name = strdup(bucket_item.name);
            bucket->id = strdup(bucket_item.name);
            bucket->created = strdup(created_str);
            bucket->decrypted = true;
        }
    }

    // NB: this field is unused; it only exists for backwards compatibility as it is
    //  passed to `json_object_put` by api consumers.
    //  (see: https://svn.filezilla-project.org/svn/FileZilla3/trunk/src/storj/fzstorj.cpp)
    req->response = json_object_new_object();

    free_bucket_list(&bucket_list);
}

static void get_bucket_request_worker(uv_work_t *work)
{
    get_bucket_request_t *req = work->data;

    BucketInfo bucket_info = get_bucket_info(req->project_ref,
                                             strdup(req->bucket_name),
                                             STORJ_LAST_ERROR);
    STORJ_RETURN_SET_REQ_ERROR_IF_LAST_ERROR

    req->bucket = malloc(sizeof(storj_bucket_meta_t));

    char created_str[32];
    time_t created_time = (time_t)bucket_info.created;
    strftime(created_str, 32, "%DT%T%Z", localtime(&created_time));

    req->bucket->name = strdup(bucket_info.name);
    req->bucket->id = strdup(bucket_info.name);
    req->bucket->created = strdup(created_str);
    req->bucket->decrypted = true;
    // NB: this field is unused; it only exists for backwards compatibility as it is
    //  passed to `json_object_put` by api consumers.
    //  (see: https://svn.filezilla-project.org/svn/FileZilla3/trunk/src/storj/fzstorj.cpp)
    req->response = json_object_new_object();

    free_bucket_info((BucketInfo *)&bucket_info);
}

static void delete_bucket_request_worker(uv_work_t *work)
{
    delete_bucket_request_t *req = work->data;

    delete_bucket(req->project_ref, strdup(req->bucket_name), STORJ_LAST_ERROR);
    STORJ_RETURN_SET_REQ_ERROR_IF_LAST_ERROR

    // NB: http "no content" success status code.
    req->status_code = 204;
}

static void list_files_request_worker(uv_work_t *work)
{
    list_files_request_t *req = work->data;

    BucketRef bucket_ref = open_bucket(req->project_ref, strdup(req->bucket_id),
                                       strdup(req->encryption_access),
                                       STORJ_LAST_ERROR);
    STORJ_RETURN_SET_REQ_ERROR_IF_LAST_ERROR;

    ObjectList object_list = list_objects(bucket_ref, NULL, STORJ_LAST_ERROR);

    req->total_files = object_list.length;

    if (object_list.length > 0) {
        req->files = malloc(sizeof(storj_file_meta_t) * object_list.length);

        ObjectInfo object_item;
        for (int i = 0; i < object_list.length; i++) {
            object_item = object_list.items[i];
            storj_file_meta_t *file = &req->files[i];

            char created_str[32];
            time_t created_time = (time_t)object_item.created;
            strftime(created_str, 32, "%DT%T%Z", localtime(&created_time));

            file->created = strdup(created_str);
            file->mimetype = strdup(object_item.content_type);
            file->id = strdup(object_item.path);
            file->bucket_id = strdup(object_item.bucket.name);
            file->filename = strdup(object_item.path);
            file->decrypted = true;

            // TODO: if we want to populate size we need to
            //  get object meta for each file.
//            file->size = ;
        }
    }
}

//static void get_file_info_request_worker(uv_work_t *work)
//{
//    get_file_info_request_t *req = work->data;
//    int status_code = 0;
//
//    req->error_code = fetch_json(req->http_options,
//                                 req->options, req->method, req->path, req->body,
//                                 req->auth, &req->response, &status_code);
//
//    req->status_code = status_code;
//
//    struct json_object *filename;
//    struct json_object *mimetype;
//    struct json_object *size;
//    struct json_object *id;
//    struct json_object *bucket_id;
//    struct json_object *created;
//    struct json_object *hmac;
//    struct json_object *hmac_value;
//    struct json_object *erasure;
//    struct json_object *erasure_type;
//    struct json_object *index;
//
//    json_object_object_get_ex(req->response, "filename", &filename);
//    json_object_object_get_ex(req->response, "mimetype", &mimetype);
//    json_object_object_get_ex(req->response, "size", &size);
//    json_object_object_get_ex(req->response, "id", &id);
//    json_object_object_get_ex(req->response, "bucket", &bucket_id);
//    json_object_object_get_ex(req->response, "created", &created);
//    json_object_object_get_ex(req->response, "hmac", &hmac);
//    json_object_object_get_ex(hmac, "value", &hmac_value);
//    json_object_object_get_ex(req->response, "erasure", &erasure);
//    json_object_object_get_ex(erasure, "type", &erasure_type);
//    json_object_object_get_ex(req->response, "index", &index);
//
//    req->file = malloc(sizeof(storj_file_meta_t));
//    req->file->created = json_object_get_string(created);
//    req->file->mimetype = json_object_get_string(mimetype);
//    req->file->size = json_object_get_int64(size);
//    req->file->erasure = json_object_get_string(erasure_type);
//    req->file->index = json_object_get_string(index);
//    req->file->hmac = json_object_get_string(hmac_value);
//    req->file->id = json_object_get_string(id);
//    req->file->bucket_id = json_object_get_string(bucket_id);
//    req->file->decrypted = false;
//    req->file->filename = NULL;
//
//    // Attempt to decrypt the filename, otherwise
//    // we will default the filename to the encrypted text.
//    // The decrypted flag will be set to indicate the status
//    // of decryption for alternative display.
//    const char *encrypted_file_name = json_object_get_string(filename);
//    if (encrypted_file_name) {
//        char *decrypted_file_name;
//        int error_status = decrypt_file_name(req->encrypt_options->mnemonic,
//                                             req->bucket_id,
//                                             encrypted_file_name,
//                                             &decrypted_file_name);
//        if (!error_status) {
//            req->file->decrypted = true;
//            req->file->filename = decrypted_file_name;
//        } else if (error_status == STORJ_META_DECRYPTION_ERROR) {
//        	req->file->decrypted = false;
//        	req->file->filename = strdup(encrypted_file_name);
//        } else {
//            req->error_code = STORJ_MEMORY_ERROR;
//        }
//    }
//}
//
//static void get_file_id_request_worker(uv_work_t *work)
//{
//    get_file_id_request_t *req = work->data;
//    int status_code = 0;
//
//    char *encrypted_file_name;
//    if (encrypt_file_name(req->encrypt_options->mnemonic,
//                          req->bucket_id,
//                          req->file_name,
//                          &encrypted_file_name)) {
//        req->error_code = STORJ_MEMORY_ERROR;
//        goto cleanup;
//    }
//
//    char *escaped_encrypted_file_name = str_replace("/", "%2F", encrypted_file_name);
//    if (!escaped_encrypted_file_name) {
//        req->error_code = STORJ_MEMORY_ERROR;
//        goto cleanup;
//    }
//
//    char *path = str_concat_many(4, "/buckets/", req->bucket_id,
//                                    "/file-ids/", escaped_encrypted_file_name);
//    if (!path) {
//        req->error_code = STORJ_MEMORY_ERROR;
//        goto cleanup;
//    }
//
//    req->error_code = fetch_json(req->http_options,
//                                 req->options, "GET", path, NULL,
//                                 true, &req->response, &status_code);
//
//    if (req->response != NULL) {
//        struct json_object *id;
//        json_object_object_get_ex(req->response, "id", &id);
//        req->file_id = json_object_get_string(id);
//    }
//
//    req->status_code = status_code;
//
//cleanup:
//
//    free(encrypted_file_name);
//    free(escaped_encrypted_file_name);
//    free(path);
//}

static uv_work_t *uv_work_new()
{
    uv_work_t *work = malloc(sizeof(uv_work_t));
    return work;
}

static list_files_request_t *list_files_request_new(
    ProjectRef project_ref,
    const char *encryption_access,
    const char *bucket_id,
    void *handle)
{
    list_files_request_t *req = malloc(sizeof(list_files_request_t));
    if (!req) {
        return NULL;
    }

    req->project_ref = project_ref;
    req->bucket_id = strdup(bucket_id);
    req->encryption_access = strdup(encryption_access);
    req->response = NULL;
    req->files = NULL;
    req->total_files = 0;
    req->error_code = 0;
    req->status_code = 0;
    req->handle = handle;

    return req;
}

//static get_file_info_request_t *get_file_info_request_new(
//    storj_http_options_t *http_options,
//    storj_bridge_options_t *options,
//    storj_encrypt_options_t *encrypt_options,
//    const char *bucket_id,
//    char *method,
//    char *path,
//    struct json_object *request_body,
//    bool auth,
//    void *handle)
//{
//    get_file_info_request_t *req = malloc(sizeof(get_file_info_request_t));
//    if (!req) {
//        return NULL;
//    }
//
//    req->http_options = http_options;
//    req->options = options;
//    req->encrypt_options = encrypt_options;
//    req->bucket_id = bucket_id;
//    req->method = method;
//    req->path = path;
//    req->auth = auth;
//    req->body = request_body;
//    req->response = NULL;
//    req->file = NULL;
//    req->error_code = 0;
//    req->status_code = 0;
//    req->handle = handle;
//
//    return req;
//}

static create_bucket_request_t *create_bucket_request_new(
    ProjectRef project_ref,
    const char *bucket_name,
    void *handle)
{
    create_bucket_request_t *req = malloc(sizeof(create_bucket_request_t));
    if (!req) {
        return NULL;
    }

    req->bucket_name = strdup(bucket_name);
    req->project_ref = project_ref;
    req->response = NULL;
    req->bucket = NULL;
    req->error_code = 0;
    req->status_code = 0;
    req->handle = handle;

    return req;
}

static get_buckets_request_t *get_buckets_request_new(
    ProjectRef project_ref,
    void *handle)
{
    get_buckets_request_t *req = malloc(sizeof(get_buckets_request_t));
    if (!req) {
        return NULL;
    }

    req->project_ref = project_ref;
    req->response = NULL;
    req->buckets = NULL;
    req->total_buckets = 0;
    req->error_code = 0;
    req->status_code = 0;
    req->handle = handle;

    return req;
}

static get_bucket_request_t *get_bucket_request_new(
        ProjectRef project_ref,
        char *bucket_name,
        void *handle)
{
    get_bucket_request_t *req = malloc(sizeof(get_bucket_request_t));
    if (!req) {
        return NULL;
    }

    req->project_ref = project_ref;
    req->bucket_name = strdup(bucket_name);
    req->response = NULL;
    req->bucket = NULL;
    req->error_code = 0;
    req->status_code = 0;
    req->handle = handle;

    return req;
}

static get_bucket_id_request_t *get_bucket_id_request_new(
        const char *bucket_name,
        void *handle)
{
    get_bucket_id_request_t *req = malloc(sizeof(get_bucket_id_request_t));
    if (!req) {
        return NULL;
    }

    req->bucket_name = strdup(bucket_name);
    req->bucket_id = strdup(bucket_name);
    req->response = NULL;
    req->error_code = 0;
    req->status_code = 0;
    req->handle = handle;

    return req;
}

static delete_bucket_request_t *delete_bucket_request_new(
        ProjectRef project_ref,
        const char *bucket_name,
        void *handle)
{
    delete_bucket_request_t *req = malloc(sizeof(delete_bucket_request_t));
    if (!req) {
        return NULL;
    }

    req->project_ref = project_ref;
    req->bucket_name = strdup(bucket_name);
    req->response = NULL;
    req->error_code = 0;
    req->status_code = 0;
    req->handle = handle;

    return req;
}

//static get_file_id_request_t *get_file_id_request_new(
//        storj_http_options_t *http_options,
//        storj_bridge_options_t *options,
//        storj_encrypt_options_t *encrypt_options,
//        const char *bucket_id,
//        const char *file_name,
//        void *handle)
//{
//    get_file_id_request_t *req = malloc(sizeof(get_file_id_request_t));
//    if (!req) {
//        return NULL;
//    }
//
//    req->http_options = http_options;
//    req->options = options;
//    req->encrypt_options = encrypt_options;
//    req->bucket_id = bucket_id;
//    req->file_name = file_name;
//    req->response = NULL;
//    req->file_id = NULL;
//    req->error_code = 0;
//    req->status_code = 0;
//    req->handle = handle;
//
//    return req;
//}

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


// TODO: use memlock for encryption and api keys
// (see: https://github.com/storj/libstorj/blob/master/src/storj.c#L853)
STORJ_API storj_env_t *storj_init_env(storj_bridge_options_t *bridge_options,
                                 storj_encrypt_options_t *encrypt_options,
                                 storj_http_options_t *http_options,
                                 storj_log_options_t *log_options)
{
    APIKeyRef apikey_ref = parse_api_key(bridge_options->apikey, STORJ_LAST_ERROR);
    STORJ_RETURN_IF_LAST_ERROR(NULL);

    UplinkConfig uplink_cfg = {{0}};
    uplink_cfg.Volatile.tls.skip_peer_ca_whitelist = true;

    UplinkRef uplink_ref = new_uplink(uplink_cfg, STORJ_LAST_ERROR);
    STORJ_RETURN_IF_LAST_ERROR(NULL);

    ProjectRef project_ref = open_project(uplink_ref, bridge_options->addr, apikey_ref, STORJ_LAST_ERROR);
    STORJ_RETURN_IF_LAST_ERROR(NULL);

    storj_env_t *env = malloc(sizeof(storj_env_t));
    env->bridge_options = bridge_options;
    env->encrypt_options = encrypt_options;
    env->http_options = http_options;
    env->log_options = log_options;
    env->uplink_ref = uplink_ref;
    env->project_ref = project_ref;

    uv_loop_t *loop = uv_default_loop();
    if (!loop) {
        return NULL;
    }

    // setup the uv event loop
    env->loop = loop;

    return env;
}

// TODO: use memlock for encryption and api keys
// (see: https://github.com/storj/libstorj/blob/master/src/storj.c#L999)
STORJ_API int storj_destroy_env(storj_env_t *env)
{
    close_project(env->project_ref, STORJ_LAST_ERROR);
    STORJ_RETURN_IF_LAST_ERROR(1);

    close_uplink(env->uplink_ref, STORJ_LAST_ERROR);
    STORJ_RETURN_IF_LAST_ERROR(1);

    return 0;
}

STORJ_API char *storj_strerror(int error_code)
{
    switch(error_code) {

        case STORJ_LIBUPLINK_ERROR:
            return *STORJ_LAST_ERROR;
        case STORJ_MEMORY_ERROR:
            return "Memory error";
        default:
            return "Unknown error";
    }
}

STORJ_API int storj_bridge_get_buckets(storj_env_t *env, void *handle, uv_after_work_cb cb)
{
    uv_work_t *work = uv_work_new();
    if (!work) {
        return STORJ_MEMORY_ERROR;
    }

    work->data = get_buckets_request_new(env->project_ref, handle);
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
            free((char *)req->buckets[i].id);
            free((char *)req->buckets[i].created);
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
    uv_work_t *work = uv_work_new(); if (!work) {
        return STORJ_MEMORY_ERROR;
    }


    work->data = create_bucket_request_new(env->project_ref,
                                           name,
                                           handle);
    if (!work->data) {
        return STORJ_MEMORY_ERROR;
    }

    return uv_queue_work(env->loop, (uv_work_t*) work,
                         create_bucket_request_worker, cb);
}

STORJ_API int storj_bridge_delete_bucket(storj_env_t *env,
                               const char *bucket_name,
                               void *handle,
                               uv_after_work_cb cb)
{
    uv_work_t *work = uv_work_new(); if (!work) {
        return STORJ_MEMORY_ERROR;
    }

    work->data = delete_bucket_request_new(env->project_ref, bucket_name, handle);
    if (!work->data) {
        return STORJ_MEMORY_ERROR;
    }

    return uv_queue_work(env->loop, (uv_work_t*) work, delete_bucket_request_worker, cb);
}

STORJ_API int storj_bridge_get_bucket(storj_env_t *env,
                                      const char *name,
                                      void *handle,
                                      uv_after_work_cb cb)
{
    uv_work_t *work = uv_work_new();
    if (!work) {
        return STORJ_MEMORY_ERROR;
    }

    char *bucket_name = strdup(name);
    work->data = get_bucket_request_new(env->project_ref, bucket_name, handle);
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
    if (req->bucket) {
        free((char *)req->bucket->name);
        free((char *)req->bucket->id);
        free((char *)req->bucket->created);
    }

    free(req->bucket);
    free((char *)req->bucket_name);
    free(req);
}

STORJ_API void storj_free_create_bucket_request(create_bucket_request_t *req)
{
    if (req->response) {
        json_object_put(req->response);
    }
    if (req->bucket) {
        free((char *)req->bucket->name);
        free((char *)req->bucket->id);
        free((char *)req->bucket->created);
    }

    free(req->bucket);
    free((char *)req->bucket_name);
    free(req);
}

STORJ_API int storj_bridge_get_bucket_id(storj_env_t *env,
                                         const char *name,
                                         void *handle,
                                         uv_after_work_cb cb)
{
    int status_code = 0;

    uv_work_t *work = uv_work_new();
    if (!work) {
        return STORJ_MEMORY_ERROR;
    }

    work->data = get_bucket_id_request_new(name, handle);
    if (!work->data) {
        return STORJ_MEMORY_ERROR;
    }

    cb(work, status_code);
    return status_code;
}

STORJ_API int storj_bridge_list_files(storj_env_t *env,
                            const char *id,
                            const char *encryption_access,
                            void *handle,
                            uv_after_work_cb cb)
{
    uv_work_t *work = uv_work_new();
    if (!work) {
        return STORJ_MEMORY_ERROR;
    }
    work->data = list_files_request_new(env->project_ref,
                                        encryption_access,
                                        id, handle);

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
    // TODO: either add locking or at lease zero memory out.
    free((char *)req->encryption_access);
    free((char *)req->bucket_id);
    if (req->files && req->total_files > 0) {
        for (int i = 0; i < req->total_files; i++) {
            storj_free_file_meta(&req->files[i]);
        }
    }
    free(req->files);
    free(req);
}

STORJ_API void storj_free_file_meta(storj_file_meta_t *file_meta)
{
    free((char *)file_meta->filename);
    free((char *)file_meta->bucket_id);
    free((char *)file_meta->mimetype);
    free((char *)file_meta->created);
    free((char *)file_meta->id);
    free(file_meta);
}

//STORJ_API int storj_bridge_delete_file(storj_env_t *env,
//                             const char *bucket_id,
//                             const char *file_id,
//                             void *handle,
//                             uv_after_work_cb cb)
//{
//    char *path = str_concat_many(4, "/buckets/", bucket_id, "/files/", file_id);
//    if (!path) {
//        return STORJ_MEMORY_ERROR;
//    }
//
//    uv_work_t *work = json_request_work_new(env, "DELETE", path, NULL,
//                                            true, handle);
//    if (!work) {
//        return STORJ_MEMORY_ERROR;
//    }
//
//    return uv_queue_work(env->loop, (uv_work_t*) work, json_request_worker, cb);
//}
//
//STORJ_API int storj_bridge_get_file_info(storj_env_t *env,
//                                         const char *bucket_id,
//                                         const char *file_id,
//                                         void *handle,
//                                         uv_after_work_cb cb)
//{
//    char *path = str_concat_many(5, "/buckets/", bucket_id, "/files/",
//                                 file_id, "/info");
//    if (!path) {
//        return STORJ_MEMORY_ERROR;
//    }
//
//    uv_work_t *work = uv_work_new();
//    if (!work) {
//        return STORJ_MEMORY_ERROR;
//    }
//
//    work->data = get_file_info_request_new(env->http_options,
//                                           env->bridge_options,
//                                           env->encrypt_options,
//                                           bucket_id, "GET", path,
//                                           NULL, true, handle);
//
//    if (!work->data) {
//        return STORJ_MEMORY_ERROR;
//    }
//
//    return uv_queue_work(env->loop, (uv_work_t*) work,
//                         get_file_info_request_worker, cb);
//}
//
//STORJ_API int storj_bridge_get_file_id(storj_env_t *env,
//                                       const char *bucket_id,
//                                       const char *file_name,
//                                       void *handle,
//                                       uv_after_work_cb cb)
//{
//    uv_work_t *work = uv_work_new();
//    if (!work) {
//        return STORJ_MEMORY_ERROR;
//    }
//
//    work->data = get_file_id_request_new(env->http_options,
//                                         env->bridge_options,
//                                         env->encrypt_options,
//                                         bucket_id, file_name, handle);
//    if (!work->data) {
//        return STORJ_MEMORY_ERROR;
//    }
//
//    return uv_queue_work(env->loop, (uv_work_t*) work, get_file_id_request_worker, cb);
//}

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
