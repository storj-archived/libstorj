#include <nettle/aes.h>
#include <nettle/ctr.h>
#include <nettle/ctr.h>

#include "storjtests.h"

static int e_count = 0;
static int i_count = 0;

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
        } else if (0 == strcmp(url, "/shards/1807dfe06c4507d2e0efce6636bf83a90877f501")) {
            status_code = MHD_HTTP_OK;
        } else if (0 == strcmp(url, "/shards/23d264bcb8b014fbfcb5eabcbf29b62abb715a05")) {
            status_code = MHD_HTTP_OK;
        } else if (0 == strcmp(url, "/shards/27c85db367ad53668a37f23e2d42683f5d33ed4f")) {
            status_code = MHD_HTTP_OK;
        } else if (0 == strcmp(url, "/shards/4c35600c8929aabd34aaf9920fa776c1771f05f4")) {
            status_code = MHD_HTTP_OK;
        } else if (0 == strcmp(url, "/shards/4fd785171d477f7755d5814d73bb844cf476ffb5")) {
            status_code = MHD_HTTP_OK;
        } else if (0 == strcmp(url, "/shards/677506f70dc0d7ca77fdf19be5ab946cfdd303ab")) {
            status_code = MHD_HTTP_OK;
        } else if (0 == strcmp(url, "/shards/6e82ccdfe28275c69ca5d97d9a345ba3d4df9105")) {
            if (i_count == 0) {
                i_count += 1;
            } else {
                status_code = MHD_HTTP_OK;
            }
        } else if (0 == strcmp(url, "/shards/7cf8773b53bd8afd1a7db8d52ac1c282dec27e79")) {
            status_code = MHD_HTTP_OK;
        } else if (0 == strcmp(url, "/shards/c000c0e05a0bf3858f6ec49ab1d126a99aab1657")) {
            status_code = MHD_HTTP_OK;
        } else if (0 == strcmp(url, "/shards/c11ad9e7d02fffeda0a557f003db35c3b58a7df5")) {
            status_code = MHD_HTTP_OK;
        } else if (0 == strcmp(url, "/shards/c2dac1efe228e733f6e15a10ea3ed8258e9bd9b5")) {
            status_code = MHD_HTTP_OK;
        } else if (0 == strcmp(url, "/shards/d328b40d9acc5a728f25168808ff8a4e8a055560")) {
            status_code = MHD_HTTP_OK;
        } else if (0 == strcmp(url, "/shards/e14d9c962ba90ad80d0ce7d71a3fd67919ace018")) {
            status_code = MHD_HTTP_OK;
        } else if (0 == strcmp(url, "/shards/e9a75f154ace98eea5792f2c539e200a38bf8662")) {
            status_code = MHD_HTTP_OK;
        } else if (0 == strcmp(url, "/shards/dc5cb536f6feb255e7ac1233d825f0af2025ba5b")) {
            status_code = MHD_HTTP_OK;
        } else if (0 == strcmp(url, "/shards/7faa0b87f0b997af928bc2dcabd80ebe0f772056")) {
            status_code = MHD_HTTP_OK;
        } else if (0 == strcmp(url, "/shards/4c4795ed9de6a646a79cfbb2ecf1b13a14b21860")) {
            status_code = MHD_HTTP_OK;
        } else if (0 == strcmp(url, "/shards/211bd84bec4a3e0b47f3d4a9735666e28f78badd")) {
            status_code = MHD_HTTP_OK;
        } else if (0 == strcmp(url, "/shards/8f40380768a2a32ddf533df88ca923716cae3b06")) {
            status_code = MHD_HTTP_OK;
        } else if (0 == strcmp(url, "/shards/3a75a42a36ecbb600aee24ce63a2ee6bcf7c6b89")) {
            status_code = MHD_HTTP_OK;
        } else if (0 == strcmp(url, "/shards/a4f40c20cffd8df5f0e39a6ca7181c2455e0b842")) {
            status_code = MHD_HTTP_OK;
        } else if (0 == strcmp(url, "/shards/c300f3f14b25ec3d4743198a28a23118a97f03e5")) {
            status_code = MHD_HTTP_OK;
        } else if (0 == strcmp(url, "/shards/abdb05b8fa4979fdb521823e0cb371b978d4b2ee")) {
            status_code = MHD_HTTP_OK;
        } else if (0 == strcmp(url, "/shards/7b82e787fe1f2c0ec80e3186ee4e3255a9400e22")) {
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

        int shard_bytes = 16777216;
        int shard_bytes_sent = 16777216;
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

        int total_data_shards = 14;
        int total_parity_shards = 7;
        int total_shards = total_data_shards + total_parity_shards;

        char *data = calloc(shard_bytes * total_shards, sizeof(char));
        char *bytes = "abcdefghijklmn";
        for (int i = 0; i < strlen(bytes); i++) {
            memset(data + (i * shard_bytes), bytes[i], shard_bytes);
        }

        if (0 == strcmp(url, "/shards/269e72f24703be80bbb10499c91dc9b2022c4dc3")) {
            page = calloc(shard_bytes + 1, sizeof(char));
            memcpy(page, data + shard_bytes * 0, shard_bytes);
            increment_ctr_aes_iv(ctr, shard_bytes * 0);
            status_code = MHD_HTTP_OK;
        } else if (0 == strcmp(url, "/shards/17416a592487d7b1b74c100448c8296122d8aff8")) {
            page = calloc(shard_bytes + 1, sizeof(char));
            memcpy(page, data + shard_bytes * 1, shard_bytes);
            increment_ctr_aes_iv(ctr, shard_bytes * 1);
            status_code = MHD_HTTP_OK;
        } else if (0 == strcmp(url, "/shards/83cf5eaf2311a1ae9699772d9bafbb3e369a41cc")) {
            page = calloc(shard_bytes + 1, sizeof(char));
            memcpy(page, data + shard_bytes * 2, shard_bytes);
            increment_ctr_aes_iv(ctr, shard_bytes * 2);
            status_code = MHD_HTTP_OK;
        } else if (0 == strcmp(url, "/shards/214ed86cb1287fe0fd18c174eecbf84341bf2655")) {
            page = calloc(shard_bytes + 1, sizeof(char));
            memcpy(page, data + shard_bytes * 3, shard_bytes);
            increment_ctr_aes_iv(ctr, shard_bytes * 3);
            status_code = MHD_HTTP_OK;
        } else if (0 == strcmp(url, "/shards/1ea408fad0213a16f53421e9b72aeb0e12b93a4a")) {
            if (e_count == 0) {
                // mock a flaky farmer w/ truncated bytes
                shard_bytes_sent = shard_bytes_sent / 2;
                page = calloc(shard_bytes_sent + 1, sizeof(char));
                memset(page, 'e', shard_bytes_sent);
            } else {
                page = calloc(shard_bytes + 1, sizeof(char));
                memcpy(page, data + shard_bytes * 4, shard_bytes);
            }
            increment_ctr_aes_iv(ctr, shard_bytes * 4);
            status_code = MHD_HTTP_OK;
            e_count += 1;
        } else if (0 == strcmp(url, "/shards/0219bb523832c09c77069c74804e5b0476cea7cf")) {
            page = calloc(shard_bytes + 1, sizeof(char));
            memcpy(page, data + shard_bytes * 5, shard_bytes);
            increment_ctr_aes_iv(ctr, shard_bytes * 5);
            status_code = MHD_HTTP_OK;
        } else if (0 == strcmp(url, "/shards/ebcbe78dd209a03d3ce29f2e5460304de2060031")) {
            page = calloc(shard_bytes + 1, sizeof(char));
            memcpy(page, data + shard_bytes * 6, shard_bytes);
            increment_ctr_aes_iv(ctr, shard_bytes * 6);
            status_code = MHD_HTTP_OK;
        } else if (0 == strcmp(url, "/shards/5ecd6cc2964a344b42406d3688e13927a51937aa")) {
            page = calloc(shard_bytes + 1, sizeof(char));
            memcpy(page, data + shard_bytes * 7, shard_bytes);
            increment_ctr_aes_iv(ctr, shard_bytes * 7);
            status_code = MHD_HTTP_OK;
        } else if (0 == strcmp(url, "/shards/88c5e8885160c449b1dbb00ccf317067200b39a0")) {
            page = calloc(shard_bytes + 1, sizeof(char));
            memcpy(page, data + shard_bytes * 8, shard_bytes);
            increment_ctr_aes_iv(ctr, shard_bytes * 8);
            status_code = MHD_HTTP_OK;
        } else if (0 == strcmp(url, "/shards/76b1a97498e026c47c924374b5b1148543d5c0ab")) {
            page = calloc(shard_bytes + 1, sizeof(char));
            memcpy(page, data + shard_bytes * 9, shard_bytes);
            increment_ctr_aes_iv(ctr, shard_bytes * 9);
            status_code = MHD_HTTP_OK;
        } else if (0 == strcmp(url, "/shards/48e02627e37433c89fa034d3ee2df644ac7ac7a0")) {
            page = calloc(shard_bytes + 1, sizeof(char));
            memcpy(page, data + shard_bytes * 10, shard_bytes);
            increment_ctr_aes_iv(ctr, shard_bytes * 10);
            status_code = MHD_HTTP_OK;
        } else if (0 == strcmp(url, "/shards/e4617532be728d48a8155ecfb200d50f00a01a23")) {
            page = calloc(shard_bytes + 1, sizeof(char));
            memcpy(page, data + shard_bytes * 11, shard_bytes);
            increment_ctr_aes_iv(ctr, shard_bytes * 11);
            status_code = MHD_HTTP_OK;
        } else if (0 == strcmp(url, "/shards/973701b43290e3bef7007db0cb75744f9556ae3b")) {
            page = calloc(shard_bytes + 1, sizeof(char));
            memcpy(page, data + shard_bytes * 12, shard_bytes);
            increment_ctr_aes_iv(ctr, shard_bytes * 12);
            status_code = MHD_HTTP_OK;
        } else if (0 == strcmp(url, "/shards/a0ec63ad4069fa51a53871c7a282e184371b842b")) {
            page = calloc(shard_bytes + 1, sizeof(char));
            memcpy(page, data + shard_bytes * 13, shard_bytes);
            increment_ctr_aes_iv(ctr, shard_bytes * 13);
            status_code = MHD_HTTP_OK;
        } else {
            printf("url: %s\n", url);
        }

        char *crypt_page = NULL;

        if (page) {

            crypt_page = malloc(shard_bytes_sent + 1);

            ctr_crypt(ctx, (nettle_cipher_func *)aes256_encrypt,
                      AES_BLOCK_SIZE, ctr,
                      shard_bytes_sent, (uint8_t *)crypt_page, (uint8_t *)page);
        } else {
            shard_bytes_sent = 9;
            crypt_page = calloc(shard_bytes_sent + 1, sizeof(char));
            strcat(crypt_page, "Not Found");
        }

        free(data);
        free(page);
        free(ctx);

        response = MHD_create_response_from_buffer(shard_bytes_sent,
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
