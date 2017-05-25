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

bool check_auth(char *user, char *pass, int *status_code, char *page)
{
    if (user && 0 == strcmp(user, USER) && 0 == strcmp(pass, PASSHASH)) {
        return true;
    }

    *status_code = MHD_HTTP_UNAUTHORIZED;
    page = "Unauthorized";

    return false;
}

int parse_json(const char *json, json_object **responses)
{
    json_tokener *tok = json_tokener_new();

    int stringlen = 0;
    enum json_tokener_error jerr;
    do {
        stringlen = strlen(json);
        *responses = json_tokener_parse_ex(tok, json, stringlen);
    } while ((jerr = json_tokener_get_error(tok)) == json_tokener_continue);

    if (jerr != json_tokener_success) {
        fprintf(stderr, "JSON Error: %s\n", json_tokener_error_desc(jerr));
        return 1;
    }

    json_tokener_free(tok);

    return 0;
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

    json_object *responses = NULL;
    if (parse_json(mockbridge_json, &responses)) {
        printf("Failed to parse JSON responses.\n");
        exit(1);
    }

    json_object *responses_info = NULL;
    if (parse_json(mockbridgeinfo_json, &responses_info)) {
        printf("Failed to parse JSON info response.\n");
        exit(1);
    }

    char *page = "Not Found";
    int status_code = MHD_HTTP_NOT_FOUND;

    int ret;

    char *pass = NULL;
    char *user = MHD_basic_auth_get_username_password(connection, &pass);

    if (0 == strcmp(method, "GET")) {
        if (0 == strcmp(url, "/")) {
            page = get_response_string(responses_info, "info");
            status_code = MHD_HTTP_OK;
        } else if (0 == strcmp(url, "/buckets")) {
            if (check_auth(user, pass, &status_code, page)) {
                page = get_response_string(responses, "getbuckets");
                status_code = MHD_HTTP_OK;
            }
        } else if (0 == strcmp(url, "/buckets/368be0816766b28fd5f43af5")) {
          if (check_auth(user, pass, &status_code, page)) {
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
        } else if (0 == strcmp(url, "/buckets/368be0816766b28fd5f43af5/file-ids/hTY5wsqYyLJQppCMiFQI7v2n/IZZiKb0ES1RCrUqK7Fe5m0/+fYwh+E/vp8M3FCEECle63BhlWlHi/Hj/Yg5y/bIjy8SxQ==")) {
            if (check_auth(user, pass, &status_code, page)) {
                status_code = MHD_HTTP_NOT_FOUND;
            }
        } else if (0 == strcmp(url, "/buckets/368be0816766b28fd5f43af5/files/998960317b6725a3f8080c2b")) {
            // TODO check token auth

            const char* skip = MHD_lookup_connection_value(connection,
                                                           MHD_GET_ARGUMENT_KIND,
                                                           "skip");
            if (!skip || 0 == strcmp(skip, "0")) {
                page = get_response_string(responses, "getfilepointers-0");
                status_code = MHD_HTTP_OK;
            } else if (0 == strcmp(skip, "3")) {
                page = get_response_string(responses, "getfilepointers-1");
                status_code = MHD_HTTP_OK;
            } else if (0 == strcmp(skip, "6")) {
                page = get_response_string(responses, "getfilepointers-2");
                status_code = MHD_HTTP_OK;
            } else if (0 == strcmp(skip, "9")) {
                page = get_response_string(responses, "getfilepointers-3");
                status_code = MHD_HTTP_OK;
            } else if (0 == strcmp(skip, "12")) {
                page = get_response_string(responses, "getfilepointers-4");
                status_code = MHD_HTTP_OK;
            } else if (0 == strcmp(skip, "15")) {
                page = get_response_string(responses, "getfilepointers-5");
                status_code = MHD_HTTP_OK;
            } else if (0 == strcmp(skip, "4")) {
                // TODO check exclude and limit query
                page = get_response_string(responses, "getfilepointers-r");
                status_code = MHD_HTTP_OK;
            } else if (0 == strcmp(skip, "14")) {
                // parity-shard
                page = get_response_string(responses, "getfilepointers-missing");
                status_code = MHD_HTTP_OK;
            } else {
                page = "[]";
                status_code = MHD_HTTP_OK;
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
        } else if (0 == strcmp(url, "/buckets/368be0816766b28fd5f43af5/files/998960317b6725a3f8080c2b/mirrors")) {
            if (check_auth(user, pass, &status_code, page)) {
                page = get_response_string(responses, "listmirrors");
                status_code = MHD_HTTP_OK;
            }
        } else {
            printf("url: %s\n", url);
        }

    } else if (0 == strcmp(method, "POST")) {

        if (0 == strcmp(url, "/reports/exchanges")) {
            // TODO check post body
            page = "{}";
            status_code = 201;
        } else if (0 == strcmp(url, "/buckets")) {
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
        } else if (0 == strcmp(url, "/buckets/368be0816766b28fd5f43af5/files")) {
            // For test upload
            if (check_auth(user, pass, &status_code, page)) {
                page = get_response_string(responses, "createfile");
                status_code = 201;
            }
        } else if (0 == strcmp(url, "/users")) {
            page = get_response_string(responses, "createuser");
            status_code = 201;
        }
    } else if (0 == strcmp(method, "PUT")) {
        if (0 == strcmp(url, "/frames/d6367831f7f1b117ffdd0015")) {
            if (check_auth(user, pass, &status_code, page)) {
                // TODO check post body
                page = get_response_string(responses, "putframe");
                status_code = MHD_HTTP_OK;
            }
        }
    } else if (0 == strcmp(method, "DELETE")) {
        if (0 == strcmp(url, "/buckets/368be0816766b28fd5f43af5")) {
            if (check_auth(user, pass, &status_code, page)) {
                // TODO check post body
                // there is no response body
                page = NULL;
                status_code = 204;
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

    if (page) {
        int page_len = strlen(page);
        char *page_cpy = calloc(page_len + 1, sizeof(char));
        memcpy(page_cpy, page, page_len);

        response = MHD_create_response_from_buffer(page_len,
                                                   (void *) page_cpy,
                                                   MHD_RESPMEM_MUST_FREE);
    } else {
        response = MHD_create_response_from_buffer(0,
                                                   NULL,
                                                   MHD_RESPMEM_MUST_FREE);
    }

    *ptr = NULL;

    ret = MHD_queue_response(connection, status_code, response);
    if (ret == MHD_NO) {
        fprintf(stderr, "MHD_queue_response ERROR: Bad args were passed " \
                        "(e.g. null value), or another error occurred" \
                        "(e.g. reply was already sent)\n");
    }

    MHD_destroy_response(response);

    if (pass) {
        free(pass);
    }
    free(user);
    json_object_put(responses);
    json_object_put(responses_info);

    return ret;
}
