#include <nettle/aes.h>
#include <nettle/ctr.h>
#include <nettle/ctr.h>

#include "storjtests.h"

static int e_count = 0;

static void farmer_request_completed(void *cls,
                                     struct MHD_Connection *connection,
                                     void **con_cls,
                                     enum MHD_RequestTerminationCode toe)
{
    *con_cls = NULL;
}

int mock_farmer_shard_server(void *cls,
                             struct MHD_Connection *connection,
                             const char *url,
                             const char *method,
                             const char *version,
                             const char *upload_data,
                             size_t *upload_data_size,
                             void **con_cls)
{
    const char *encoding = MHD_lookup_connection_value(connection,
                                                       MHD_HEADER_KIND,
                                                       MHD_HTTP_HEADER_CONTENT_TYPE);

    if (NULL == *con_cls) {

        *con_cls = (void *)connection;

        return MHD_YES;
    }

    if (0 == strcmp(method, "POST")) {

        if (*upload_data_size != 0) {
            // TODO check upload_data
            *upload_data_size = 0;
            return MHD_YES;
        }

        int ret;
        struct MHD_Response *response;
        int status_code = MHD_HTTP_NOT_FOUND;

        if (0 == strcmp(url, "/")) {
            status_code = MHD_HTTP_OK;
        } else if (0 == strcmp(url, "/shards/07c64874633458d9325282a326ca443445febcd3")) {
            status_code = MHD_HTTP_OK;
        } else if (0 == strcmp(url, "/shards/1996efb94776710ac93fc02fef9ca9d26e7fe317")) {
            status_code = MHD_HTTP_OK;
        } else if (0 == strcmp(url, "/shards/23eedc7a8d08eba0355d8577d9f534d03bac8b34")) {
            status_code = MHD_HTTP_OK;
        } else if (0 == strcmp(url, "/shards/23eedc7a8d08eba0355d8577d9f534d03bac8b34")) {
            status_code = MHD_HTTP_OK;
        } else if (0 == strcmp(url, "/shards/3b07a2590060c4aec25fac88519de9df237e6227")) {
            status_code = MHD_HTTP_OK;
        } else if (0 == strcmp(url, "/shards/652fb8b01d017320a5d609346b3e3cf4ef77f50d")) {
            status_code = MHD_HTTP_OK;
        } else if (0 == strcmp(url, "/shards/69d49e7b7355cfaa00d4e42cd97ceb8d31ff4ce7")) {
            status_code = MHD_HTTP_OK;
        } else if (0 == strcmp(url, "/shards/85a942537a6b998c6338a438cd283e9bf531e261")) {
            status_code = MHD_HTTP_OK;
        } else if (0 == strcmp(url, "/shards/88ee3a1a14771c4a9ceb81357a5889cc3d8ad8e7")) {
            status_code = MHD_HTTP_OK;
        } else if (0 == strcmp(url, "/shards/9273982d7e7785b50fc56943ec9ef394c0c2c4d6")) {
            status_code = MHD_HTTP_OK;
        } else if (0 == strcmp(url, "/shards/a310d427a5cd21df2fa58bccf36954de147a830e")) {
            status_code = MHD_HTTP_OK;
        } else if (0 == strcmp(url, "/shards/a750106b958b36ac6f064fb929d1587548098425")) {
            status_code = MHD_HTTP_OK;
        } else if (0 == strcmp(url, "/shards/b41b389b63ba3efa422904a1eacf1a827d220655")) {
            status_code = MHD_HTTP_OK;
        } else if (0 == strcmp(url, "/shards/cac5d3e6630fb0640017c03991745b1e945b04e4")) {
            status_code = MHD_HTTP_OK;
        } else if (0 == strcmp(url, "/shards/cf76108f1d1c152647542c1e0d90504add64349b")) {
            status_code = MHD_HTTP_OK;
        } else {
            printf("url: %s\n", url);
        }

        char *page = "";
        response = MHD_create_response_from_buffer(strlen(page),
                                                   (void *) page,
                                                   MHD_RESPMEM_PERSISTENT);
        if (!response) {
            return MHD_NO;
        }

        ret = MHD_queue_response(connection, status_code, response);
        MHD_destroy_response(response);

        return ret;
    }

    if (0 == strcmp(method, "GET")) {

        struct MHD_Response *response;

        int status_code = MHD_HTTP_NOT_FOUND;

        int ret;

        int total_bytes = 16777216;
        int total_bytes_sent = 16777216;
        char *page = NULL;

        struct aes256_ctx *ctx = malloc(sizeof(struct aes256_ctx));

        // mnemonic: abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about
        // bucket_id: 368be0816766b28fd5f43af5
        // file_id: 998960317b6725a3f8080c2b
        uint8_t encrypt_key[32] = {215,99,0,133,172,219,64,35,54,53,171,23,146,160,
                                   81,126,137,21,253,171,48,217,184,188,8,137,3,
                                   4,83,50,30,251};
        uint8_t ctr[16] = {70,219,247,135,162,7,93,193,44,123,188,234,203,115,129,82};
        aes256_set_encrypt_key(ctx, encrypt_key);

        if (0 == strcmp(url, "/shards/269e72f24703be80bbb10499c91dc9b2022c4dc3")) {
            page = calloc(total_bytes + 1, sizeof(char));
            memset(page, 'a', total_bytes);
            increment_ctr_aes_iv(ctr, total_bytes * 0);
            status_code = MHD_HTTP_OK;
        } else if (0 == strcmp(url, "/shards/17416a592487d7b1b74c100448c8296122d8aff8")) {
            page = calloc(total_bytes + 1, sizeof(char));
            memset(page, 'b', total_bytes);
            increment_ctr_aes_iv(ctr, total_bytes * 1);
            status_code = MHD_HTTP_OK;
        } else if (0 == strcmp(url, "/shards/83cf5eaf2311a1ae9699772d9bafbb3e369a41cc")) {
            page = calloc(total_bytes + 1, sizeof(char));
            memset(page, 'c', total_bytes);
            increment_ctr_aes_iv(ctr, total_bytes * 2);
            status_code = MHD_HTTP_OK;
        } else if (0 == strcmp(url, "/shards/214ed86cb1287fe0fd18c174eecbf84341bf2655")) {
            page = calloc(total_bytes + 1, sizeof(char));
            memset(page, 'd', total_bytes);
            increment_ctr_aes_iv(ctr, total_bytes * 3);
            status_code = MHD_HTTP_OK;
        } else if (0 == strcmp(url, "/shards/1ea408fad0213a16f53421e9b72aeb0e12b93a4a")) {
            if (e_count == 0) {
                // mock a flaky farmer w/ truncated bytes
                total_bytes_sent = total_bytes_sent / 2;
                page = calloc(total_bytes_sent + 1, sizeof(char));
                memset(page, 'e', total_bytes_sent);
            } else {
                page = calloc(total_bytes + 1, sizeof(char));
                memset(page, 'e', total_bytes);
            }
            increment_ctr_aes_iv(ctr, total_bytes * 4);
            status_code = MHD_HTTP_OK;
            e_count += 1;
        } else if (0 == strcmp(url, "/shards/0219bb523832c09c77069c74804e5b0476cea7cf")) {
            page = calloc(total_bytes + 1, sizeof(char));
            memset(page, 'f', total_bytes);
            increment_ctr_aes_iv(ctr, total_bytes * 5);
            status_code = MHD_HTTP_OK;
        } else if (0 == strcmp(url, "/shards/ebcbe78dd209a03d3ce29f2e5460304de2060031")) {
            page = calloc(total_bytes + 1, sizeof(char));
            memset(page, 'g', total_bytes);
            increment_ctr_aes_iv(ctr, total_bytes * 6);
            status_code = MHD_HTTP_OK;
        } else if (0 == strcmp(url, "/shards/5ecd6cc2964a344b42406d3688e13927a51937aa")) {
            page = calloc(total_bytes + 1, sizeof(char));
            memset(page, 'h', total_bytes);
            increment_ctr_aes_iv(ctr, total_bytes * 7);
            status_code = MHD_HTTP_OK;
        } else if (0 == strcmp(url, "/shards/88c5e8885160c449b1dbb00ccf317067200b39a0")) {
            page = calloc(total_bytes + 1, sizeof(char));
            memset(page, 'i', total_bytes);
            increment_ctr_aes_iv(ctr, total_bytes * 8);
            status_code = MHD_HTTP_OK;
        } else if (0 == strcmp(url, "/shards/76b1a97498e026c47c924374b5b1148543d5c0ab")) {
            page = calloc(total_bytes + 1, sizeof(char));
            memset(page, 'j', total_bytes);
            increment_ctr_aes_iv(ctr, total_bytes * 9);
            status_code = MHD_HTTP_OK;
        } else if (0 == strcmp(url, "/shards/48e02627e37433c89fa034d3ee2df644ac7ac7a0")) {
            page = calloc(total_bytes + 1, sizeof(char));
            memset(page, 'k', total_bytes);
            increment_ctr_aes_iv(ctr, total_bytes * 10);
            status_code = MHD_HTTP_OK;
        } else if (0 == strcmp(url, "/shards/e4617532be728d48a8155ecfb200d50f00a01a23")) {
            page = calloc(total_bytes + 1, sizeof(char));
            memset(page, 'l', total_bytes);
            increment_ctr_aes_iv(ctr, total_bytes * 11);
            status_code = MHD_HTTP_OK;
        } else if (0 == strcmp(url, "/shards/973701b43290e3bef7007db0cb75744f9556ae3b")) {
            page = calloc(total_bytes + 1, sizeof(char));
            memset(page, 'm', total_bytes);
            increment_ctr_aes_iv(ctr, total_bytes * 12);
            status_code = MHD_HTTP_OK;
        } else if (0 == strcmp(url, "/shards/a0ec63ad4069fa51a53871c7a282e184371b842b")) {
            page = calloc(total_bytes + 1, sizeof(char));
            memset(page, 'n', total_bytes);
            increment_ctr_aes_iv(ctr, total_bytes * 13);
            status_code = MHD_HTTP_OK;
        } else {
            printf("url: %s\n", url);
        }

        char *crypt_page = NULL;

        if (page) {

            crypt_page = malloc(total_bytes_sent + 1);

            ctr_crypt(ctx, (nettle_cipher_func *)aes256_encrypt,
                      AES_BLOCK_SIZE, ctr,
                      total_bytes_sent, (uint8_t *)crypt_page, (uint8_t *)page);
        } else {
            total_bytes_sent = 9;
            crypt_page = calloc(total_bytes_sent + 1, sizeof(char));
            strcat(crypt_page, "Not Found");
        }

        free(page);
        free(ctx);

        response = MHD_create_response_from_buffer(total_bytes_sent,
                                                   (void *) crypt_page,
                                                   MHD_RESPMEM_MUST_FREE);

        ret = MHD_queue_response(connection, status_code, response);
        if (ret == MHD_NO) {
            fprintf(stderr, "MHD_queue_response ERROR: Bad args were passed " \
                    "(e.g. null value), or another error occurred" \
                    "(e.g. reply was already sent)\n");
        }

        MHD_destroy_response(response);

        return ret;
    }

    return MHD_NO;
}

struct MHD_Daemon *start_farmer_server()
{
    return MHD_start_daemon(MHD_USE_SELECT_INTERNALLY,
                            8092,
                            NULL,
                            NULL,
                            &mock_farmer_shard_server,
                            NULL,
                            MHD_OPTION_NOTIFY_COMPLETED,
                            &farmer_request_completed,
                            NULL,
                            MHD_OPTION_END);
}
