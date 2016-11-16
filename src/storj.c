#include "storj.h"

static void clean_up_neon(ne_session *s, ne_request *r)
{
    // Do this first...
    ne_request_destroy(r);

    // Do this anywa: ``Use of this function is entirely optional, but it must
    // not be called if there is a request active using the session.''
    ne_close_connection(s);

    // Do this last: ``The session object must not be destroyed until after all
    // associated request objects have been destroyed.''
    ne_session_destroy(s);
}

static struct json_object *fetch_json(storj_bridge_options_t *options,
                                      char *method,
                                      char *path,
                                      boolean_t auth)
{
    ne_session *sess = ne_session_create(options->proto,
                                         options->host,
                                         options->port);

    //
    // TODO: error check the ne calls in this function
    //

    if (0 == strcmp(options->proto, "https")) {
        ne_ssl_trust_default_ca(sess);
    }

    ne_request *req = ne_request_create(sess, method, path);

    if (auth && options->user && options->pass) {

        char *user_pass = ne_concat(options->user, ":", options->pass, NULL);

        char *user_pass_64 = ne_base64((unsigned char *)user_pass,
                                       strlen(user_pass));

        char *auth_value = ne_concat("Basic ", user_pass_64, NULL);

        ne_add_request_header(req, "Authorization", auth_value);
    }
    // FIXME: what if the above if-check fails?

    if (ne_begin_request(req) != NE_OK) {
        printf("Request failed: %s\n", ne_get_error(sess));
        // FIXME: we should standardize how we want to write out errors.
        // And do we want to return an object here or bail?
        clean_up_neon(sess, req);
        return NULL;
    }

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

static void json_request_worker(uv_work_t *work)
{
    json_request_t *req = work->data;
    req->response = fetch_json(req->options, req->method, req->path, req->auth);
}

struct storj_env *storj_init_env(storj_bridge_options_t *options)
{
    uv_loop_t *loop = malloc(sizeof(uv_loop_t));
    if (uv_loop_init(loop)) {
        return NULL;
    }

    storj_env_t *env = malloc(sizeof(storj_env_t));
    env->bridge_options = options;
    env->loop = loop;

    return env;
}

int storj_close_env(storj_env_t *env)
{
    int status = uv_loop_close(env->loop);
    if (status == UV_EBUSY) {
        return status;
    }

    return 0;
}

int storj_bridge_get_info(storj_env_t *env, uv_after_work_cb cb)
{
    uv_work_t *work = malloc(sizeof(uv_work_t));
    assert(work != NULL);

    json_request_t *req = malloc(sizeof(json_request_t));
    assert(work != NULL);

    req->options = env->bridge_options;
    req->method = "GET";
    req->path = "/";
    req->auth = false;

    work->data = req;

    uv_queue_work(env->loop, (uv_work_t*) work, json_request_worker, cb);

    return 0;
}

int storj_bridge_get_buckets(storj_env_t *env, uv_after_work_cb cb)
{
    uv_work_t *work = malloc(sizeof(uv_work_t));
    assert(work != NULL);

    json_request_t *req = malloc(sizeof(json_request_t));
    assert(work != NULL);

    req->options = env->bridge_options;
    req->method = "GET";
    req->path = "/buckets";
    req->auth = true;

    work->data = req;

    uv_queue_work(env->loop, (uv_work_t*) work, json_request_worker, cb);

    return 0;
}

int storj_bridge_create_bucket(storj_env_t *env, char *name,
                               uv_after_work_cb cb)
{
    struct json_object *body = json_object_new_object();
    json_object *name_string = json_object_new_string(name);
    json_object_object_add(body, "name", name_string);

    uv_work_t *work = malloc(sizeof(uv_work_t));
    assert(work != NULL);

    json_request_t *req = malloc(sizeof(json_request_t));
    assert(work != NULL);

    req->body = body;
    req->options = env->bridge_options;
    req->method = "POST";
    req->path = "/buckets";
    req->auth = true;

    work->data = req;

    uv_queue_work(env->loop, (uv_work_t*) work, json_request_worker, cb);

    return 0;
}

int storj_bridge_delete_bucket(storj_env_t *env, uv_after_work_cb cb)
{

}

int storj_bridge_list_files(storj_env_t *env, uv_after_work_cb cb)
{

}

int storj_bridge_create_bucket_token(storj_env_t *env, uv_after_work_cb cb)
{

}

int storj_bridge_delete_file(storj_env_t *env, uv_after_work_cb cb)
{

}

int storj_bridge_create_frame(storj_env_t *env, uv_after_work_cb cb)
{

}

int storj_bridge_get_frames(storj_env_t *env, uv_after_work_cb cb)
{

}

int storj_bridge_get_file_info(storj_env_t *env, uv_after_work_cb cb)
{

}

int storj_bridge_get_frame(storj_env_t *env, uv_after_work_cb cb)
{

}

int storj_bridge_delete_frame(storj_env_t *env, uv_after_work_cb cb)
{

}

int storj_bridge_add_shard_to_frame(storj_env_t *env, uv_after_work_cb cb)
{

}

int storj_bridge_replicate_file(storj_env_t *env, uv_after_work_cb cb)
{

}

int storj_bridge_store_file(storj_env_t *env, uv_after_work_cb cb)
{

}

int storj_bridge_get_file_pointers(storj_env_t *env, uv_after_work_cb cb)
{

}

int storj_bridge_resolve_file(storj_env_t *env, uv_after_work_cb cb)
{

}
