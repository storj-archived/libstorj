#include "storjtests.h"

int mock_bridge_server(void *cls,
                       struct MHD_Connection *connection,
                       const char *url,
                       const char *method,
                       const char *version,
                       const char *upload_data,
                       size_t *upload_data_size,
                       void **ptr) {

    static int dummy;
    struct MHD_Response *response;


    char *page = "Not Found";
    int status_code = MHD_HTTP_NOT_FOUND;

    int ret;

    char *pass;
    char *user = MHD_basic_auth_get_username_password(connection, &pass);

    if (0 != strcmp(method, "GET")) {
        return MHD_NO;
    }

    if (0 == strcmp(url, "/")) {
        page = INFO;
        status_code = MHD_HTTP_OK;
    }

    if (0 == strcmp(url, "/buckets")) {
        if (user &&
            0 == strcmp(user, USER) &&
            0 == strcmp(pass, PASS)) {
            page = BUCKETS;
            status_code = MHD_HTTP_OK;
        } else {
            status_code = MHD_HTTP_UNAUTHORIZED;
            page = "Unauthorized";
        }
    }

    response = MHD_create_response_from_buffer(strlen(page),
                                               (void*) page,
                                               MHD_RESPMEM_PERSISTENT);

    *ptr = NULL;

    ret = MHD_queue_response(connection, status_code, response);

    MHD_destroy_response(response);

    return ret;
}
