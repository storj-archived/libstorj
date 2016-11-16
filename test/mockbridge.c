#include "storjtests.h"

char *get_response_string(json_object *obj, const char *key)
{
    struct json_object* value;
    if (json_object_object_get_ex(obj, key, &value)) {
        return (char *)json_object_get_string(value);
    } else {
        printf("Could not get string for key %s", key);
        exit(1);
    }
}

struct json_object *get_response_json(char *path)
{
    FILE *f = fopen(path, "r");
    if (f == NULL) {
        printf("Error reading %s", path);
        exit(1);
    }

    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    fseek(f, 0, SEEK_SET);

    char *json_string = malloc(fsize + 1);

    size_t len = fread(json_string, fsize, 1, f);
    if (len == 0) {
        printf("Error reading %s", path);
        exit(1);
    }

    fclose(f);

    json_string[fsize] = 0;
    return json_tokener_parse(json_string);
}

int mock_bridge_server(void *cls,
                       struct MHD_Connection *connection,
                       const char *url,
                       const char *method,
                       const char *version,
                       const char *upload_data,
                       size_t *upload_data_size,
                       void **ptr)
{

    struct MHD_Response *response;

    json_object *responses = get_response_json("test/mockbridge.json");

    char *page = "Not Found";
    int status_code = MHD_HTTP_NOT_FOUND;

    int ret;

    char *pass;
    char *user = MHD_basic_auth_get_username_password(connection, &pass);

    if (0 == strcmp(method, "GET")) {
        if (0 == strcmp(url, "/")) {
            page = get_response_string(responses, "info");
            status_code = MHD_HTTP_OK;
        }

        if (0 == strcmp(url, "/buckets")) {
            if (user &&
                0 == strcmp(user, USER) &&
                0 == strcmp(pass, PASS)) {
                page = get_response_string(responses, "getbuckets");
                status_code = MHD_HTTP_OK;
            } else {
                status_code = MHD_HTTP_UNAUTHORIZED;
                page = "Unauthorized";
            }
        }
    } else if (0 == strcmp(method, "POST")) {

        if (0 == strcmp(url, "/buckets")) {
            if (user &&
                0 == strcmp(user, USER) &&
                0 == strcmp(pass, PASS)) {

                // TODO check post body

                page = get_response_string(responses, "putbuckets");
                status_code = MHD_HTTP_OK;
            } else {
                status_code = MHD_HTTP_UNAUTHORIZED;
                page = "Unauthorized";
            }
        }
    }

    response = MHD_create_response_from_buffer(strlen(page),
                                               (void *) page,
                                               MHD_RESPMEM_PERSISTENT);

    *ptr = NULL;

    ret = MHD_queue_response(connection, status_code, response);
    if (ret == MHD_NO) {
        fprintf(stderr, "MHD_queue_response ERROR: Bad args were passed " \
                        "(e.g. null value), or another error occurred" \
                        "(e.g. reply was already sent)\n");
    }

    MHD_destroy_response(response);

    return ret;
}
