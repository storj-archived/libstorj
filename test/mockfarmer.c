#include "storjtests.h"

int mock_farmer_shard_server(void *cls,
                             struct MHD_Connection *connection,
                             const char *url,
                             const char *method,
                             const char *version,
                             const char *upload_data,
                             size_t *upload_data_size,
                             void **ptr)
{

    struct MHD_Response *response;

    char *page = "Not Found";
    int status_code = MHD_HTTP_NOT_FOUND;

    int ret;

    if (0 == strcmp(method, "GET")) {
        if (0 == strcmp(url, "/shards/49ce4429f4cf35b3e7ddc05e233bf70fcb9eaced")) {
            page = "info";
            status_code = MHD_HTTP_OK;
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
