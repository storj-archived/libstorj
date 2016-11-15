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
                                      boolean auth)
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

struct json_object *storj_bridge_get_info(storj_bridge_options_t *options)
{
    return fetch_json(options, "GET", "/", false);
}

struct json_object *storj_bridge_get_buckets(storj_bridge_options_t *options)
{
    return fetch_json(options, "GET", "/buckets", true);
}

struct json_object *storj_bridge_create_bucket()
{

}

struct json_object *storj_bridge_delete_bucket()
{

}

struct json_object *storj_bridge_list_files()
{

}

struct json_object *storj_bridge_create_bucket_token()
{

}

struct json_object *storj_bridge_delete_file()
{

}

struct json_object *storj_bridge_create_frame()
{

}

struct json_object *storj_bridge_get_frames()
{

}

struct json_object *storj_bridge_get_file_info()
{

}

struct json_object *storj_bridge_get_frame()
{

}

struct json_object *storj_bridge_delete_frame()
{

}

struct json_object *storj_bridge_add_shard_to_frame()
{

}

struct json_object *storj_bridge_replicate_file()
{

}

struct json_object *storj_bridge_store_file()
{

}

struct json_object *storj_bridge_get_file_pointers()
{

}

struct json_object *storj_bridge_resolve_file()
{

}
