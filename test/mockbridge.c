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

    struct json_object *j = json_tokener_parse(json_string);

    free(json_string);

    return j;
}

storj_boolean_t check_auth(char *user, char *pass, int *status_code, char *page)
{
    if (user && 0 == strcmp(user, USER) && 0 == strcmp(pass, PASSHASH)) {
        return true;
    }

    *status_code = MHD_HTTP_UNAUTHORIZED;
    page = "Unauthorized";

    return false;
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
        } else if (0 == strcmp(url, "/buckets")) {
            if (check_auth(user, pass, &status_code, page)) {
                page = get_response_string(responses, "getbuckets");
                status_code = MHD_HTTP_OK;
            }
        } else if (0 == strcmp(url, "/buckets/368be0816766b28fd5f43af5/files")) {
            if (check_auth(user, pass, &status_code, page)) {
                page = get_response_string(responses, "listfiles");
                status_code = MHD_HTTP_OK;
            }
        } else if (0 == strcmp(url, "/buckets/368be0816766b28fd5f43af5/files/998960317b6725a3f8080c2b/info")) {
            if (check_auth(user, pass, &status_code, page)) {
                page = get_response_string(responses, "getfileinfo");
                status_code = MHD_HTTP_OK;
            }
        } else if (0 == strcmp(url, "/buckets/368be0816766b28fd5f43af5/files/998960317b6725a3f8080c2b")) {
            if (check_auth(user, pass, &status_code, page)) {

                const char* skip = MHD_lookup_connection_value(connection,
                                                               MHD_GET_ARGUMENT_KIND,
                                                               "skip");
                if (!skip || 0 == strcmp(skip, "0")) {
                    page = get_response_string(responses, "getfilepointers-0");
                    status_code = MHD_HTTP_OK;
                } else if (0 == strcmp(skip, "6")) {
                    page = get_response_string(responses, "getfilepointers-1");
                    status_code = MHD_HTTP_OK;
                } else if (0 == strcmp(skip, "12")) {
                    page = get_response_string(responses, "getfilepointers-2");
                    status_code = MHD_HTTP_OK;
                } else {
                    page = "[]";
                    status_code = MHD_HTTP_OK;
                }
            }
        } else if (0 == strcmp(url, "/frames")) {
            if (check_auth(user, pass, &status_code, page)) {
                page = get_response_string(responses, "getframes");
                status_code = MHD_HTTP_OK;
            }
        } else if (0 == strcmp(url, "/frames/d4af71ab00e15b0c1a7b6ab2")) {
            if (check_auth(user, pass, &status_code, page)) {
                page = get_response_string(responses, "getframe");
                status_code = MHD_HTTP_OK;
            }
        }

    } else if (0 == strcmp(method, "POST")) {

        if (0 == strcmp(url, "/buckets")) {
            if (check_auth(user, pass, &status_code, page)) {
                // TODO check post body
                page = get_response_string(responses, "putbuckets");
                status_code = MHD_HTTP_OK;
            }
        } else if (0 == strcmp(url, "/frames")) {
            if (check_auth(user, pass, &status_code, page)) {
                // TODO check post body
                page = get_response_string(responses, "createframe");
                status_code = MHD_HTTP_OK;
            }
        } else if (0 == strcmp(url, "/buckets/368be0816766b28fd5f43af5/tokens")) {
            if (check_auth(user, pass, &status_code, page)) {
                // TODO check post body
                page = get_response_string(responses, "createbuckettoken");
                status_code = 201;
            }
        }
    } else if (0 == strcmp(method, "DELETE")) {
        if (0 == strcmp(url, "/buckets/368be0816766b28fd5f43af5")) {
            if (check_auth(user, pass, &status_code, page)) {
                // TODO check post body
                // there is no response body
                status_code = MHD_HTTP_OK;
            }
        } else if (0 == strcmp(url, "/buckets/368be0816766b28fd5f43af5/files/998960317b6725a3f8080c2b")) {
            if (check_auth(user, pass, &status_code, page)) {
                // TODO check post body
                // there is no response body
                status_code = MHD_HTTP_OK;
            }
        } else if (0 == strcmp(url, "/frames/d4af71ab00e15b0c1a7b6ab2")) {
            if (check_auth(user, pass, &status_code, page)) {
                // TODO check post body
                status_code = MHD_HTTP_OK;
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

    // Free the json_object
    // json_object_put(responses);

    return ret;
}
