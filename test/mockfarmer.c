#include <nettle/aes.h>
#include <nettle/ctr.h>
#include <nettle/ctr.h>

#include "storjtests.h"
#include "../src/rs.h"

static int e_count = 0;
static int i_count = 0;
static char* data = NULL;

static void setup_test_farmer_data(int shard_bytes, int shard_bytes_sent)
{
    // check if data already setu
    if (data) {
        return;
    }

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
    int total_parity_shards = 4;
    int total_shards = total_data_shards + total_parity_shards;
    int total_size = shard_bytes * total_shards;

    data = calloc(total_size, sizeof(char));
    char *bytes = "abcdefghijklmn";
    for (int i = 0; i < strlen(bytes); i++) {
        memset(data + (i * shard_bytes), bytes[i], shard_bytes);
    }

    ctr_crypt(ctx, (nettle_cipher_func *)aes256_encrypt,
              AES_BLOCK_SIZE, ctr,
              total_size, (uint8_t *)data, (uint8_t *)data);

    reed_solomon* rs = NULL;
    uint8_t **data_blocks = NULL;
    uint8_t **fec_blocks = NULL;
    fec_init();

    data_blocks = (uint8_t**)malloc(total_data_shards * sizeof(uint8_t *));
    if (!data_blocks) {
        fprintf(stderr, "memory error: unable to malloc");
        exit(1);
    }

    for (int i = 0; i < total_data_shards; i++) {
        data_blocks[i] = data + i * shard_bytes;
    }

    fec_blocks = (uint8_t**)malloc(total_parity_shards * sizeof(uint8_t *));
    if (!fec_blocks) {
        fprintf(stderr, "memory error: unable to malloc");
        exit(1);
    }

    for (int i = 0; i < total_parity_shards; i++) {
        fec_blocks[i] = data + (total_data_shards + i) * shard_bytes;
    }

    rs = reed_solomon_new(total_data_shards, total_parity_shards);
    reed_solomon_encode2(rs, data_blocks, fec_blocks, total_shards, shard_bytes, total_size);
    reed_solomon_release(rs);

    free(data_blocks);
    free(fec_blocks);
    free(ctx);
}

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
        } else if (0 == strcmp(url, "/shards/179723620bfce52a6efaa6d311811cd9a31c51dc")) {
            status_code = MHD_HTTP_OK;
        } else if (0 == strcmp(url, "/shards/3920fcb1acf8d773bdff94edd293b57e1506073d")) {
            status_code = MHD_HTTP_OK;
        } else if (0 == strcmp(url, "/shards/76ec05cdfa1bc0810c5a555350d1e4cb81b01524")) {
            status_code = MHD_HTTP_OK;
        } else if (0 == strcmp(url, "/shards/4a9986ed3ec84a8a1b62b8ce9770002cf9aff02a")) {
            status_code = MHD_HTTP_OK;
        } else if (0 == strcmp(url, "/shards/76d9efb59a35a3c3862bbfb489ab1ed916f3f0d3")) {
            status_code = MHD_HTTP_OK;
        } else if (0 == strcmp(url, "/shards/a590ff71ca93662d63942fc2dcc2125cd592a4d4")) {
            status_code = MHD_HTTP_OK;
        } else if (0 == strcmp(url, "/shards/1391bf1eb215941e84bd8c52201511041580918e")) {
            if (i_count == 0) {
                i_count += 1;
            } else {
                status_code = MHD_HTTP_OK;
            }
        } else if (0 == strcmp(url, "/shards/b6a676b696751baa9c04d82096a35107ca7f46b6")) {
            status_code = MHD_HTTP_OK;
        } else if (0 == strcmp(url, "/shards/b88b80d9f0942b90a86274b53e5ab3c8fae614de")) {
            status_code = MHD_HTTP_OK;
        } else if (0 == strcmp(url, "/shards/7afaf8bf5bbc6e0f69a4369db38d66c34caa47b5")) {
            status_code = MHD_HTTP_OK;
        } else if (0 == strcmp(url, "/shards/a51df80009ca689b9b05c84ec6511a1bfcbd53af")) {
            status_code = MHD_HTTP_OK;
        } else if (0 == strcmp(url, "/shards/a8f3fb43cc3a2ebbace4e435a49c4ddbc4c2e624")) {
            status_code = MHD_HTTP_OK;
        } else if (0 == strcmp(url, "/shards/04e21b32ffefb39c93023006148a6fcdd4fed66a")) {
            status_code = MHD_HTTP_OK;
        } else if (0 == strcmp(url, "/shards/0eb2a9961b3fd7752925af681784fbcb3483e211")) {
            status_code = MHD_HTTP_OK;
        } else if (0 == strcmp(url, "/shards/e3fabe31ef120978b8d95a1d6cc705f25086da52")) {
            status_code = MHD_HTTP_OK;
        } else if (0 == strcmp(url, "/shards/817de8fcdd64fb2adcb5f86bbdc2993879bf7c14")) {
            status_code = MHD_HTTP_OK;
        } else if (0 == strcmp(url, "/shards/9d5e980402a69e711b6176c268bbc059d7b5fb1f")) {
            status_code = MHD_HTTP_OK;
        } else if (0 == strcmp(url, "/shards/ec4a0f16ab581872ead75f6c6a681eb3c7861355")) {
            status_code = MHD_HTTP_OK;
        } else if (0 == strcmp(url, "/shards/7114c67d5d18884c51e5f2efd97803f95f7ddc18")) {
            status_code = MHD_HTTP_OK;
        } else if (0 == strcmp(url, "/shards/9354285b6750e5dff3fb6024f12826e8ab60007c")) {
            status_code = MHD_HTTP_OK;
        } else if (0 == strcmp(url, "/shards/eb342afde185b4f14477e9df81f85830cdd2cf12")) {
            status_code = MHD_HTTP_OK;
        } else if (0 == strcmp(url, "/shards/5dc5687381a7a09cdc98fe97cfcb1402ce8a1157")) {
            status_code = MHD_HTTP_OK;
        } else if (0 == strcmp(url, "/shards/a16fdcfe8b8acd2d2ba8a6889aaf74f1b13004bb")) {
            status_code = MHD_HTTP_OK;
        } else if (0 == strcmp(url, "/shards/db4af3d07dc90b0125cf465de4be1a10a478f9e4")) {
            status_code = MHD_HTTP_OK;
        } else if (0 == strcmp(url, "/shards/bf1e4713257129d525f1381d4104c217c13cb42f")) {
            status_code = MHD_HTTP_OK;

        // PARITY SHARDS
        } else if (0 == strcmp(url, "/shards/a058c13bf955d1d6134ab37ad6210de9cf539668")) {
            status_code = MHD_HTTP_OK;
        } else if (0 == strcmp(url, "/shards/f08c086703e511d38b0529afe6cc64f35b40bf1f")) {
            status_code = MHD_HTTP_OK;
        } else if (0 == strcmp(url, "/shards/a549cec8729de18e021c72b6a17009e0381b7bc6")) {
            status_code = MHD_HTTP_OK;
        } else if (0 == strcmp(url, "/shards/e0a3e7539912f15c83893f368cfe55e7a0909fbb")) {
            status_code = MHD_HTTP_OK;
        } else if (0 == strcmp(url, "/shards/0ec6fe684d01530ed2311c9c13a77d63b1d668c5")) {
            status_code = MHD_HTTP_OK;
        } else if (0 == strcmp(url, "/shards/c012be824494db131425a765d9d0bb390cd7c3d0")) {
            status_code = MHD_HTTP_OK;
        } else if (0 == strcmp(url, "/shards/76d463057e1631644b7b4c89170496b6a5879965")) {
            status_code = MHD_HTTP_OK;
        } else if (0 == strcmp(url, "/shards/e2b4704e8a308c115e989781f33f8c29b931961b")) {
            status_code = MHD_HTTP_OK;
        } else if (0 == strcmp(url, "/shards/251dc66f81cc78c70afbd139042df66eb0d9336e")) {
            status_code = MHD_HTTP_OK;
        } else if (0 == strcmp(url, "/shards/d1e0c5f9f08ab1f293a4559273a8a119f791647a")) {
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

        int shard_bytes = 16777216;
        int shard_bytes_sent = 16777216;
        setup_test_farmer_data(shard_bytes, shard_bytes_sent);

        struct MHD_Response *response;

        int status_code = MHD_HTTP_NOT_FOUND;
        char *page = NULL;

        int ret;

        if (0 == strcmp(url, "/shards/269e72f24703be80bbb10499c91dc9b2022c4dc3")) {
            page = calloc(shard_bytes + 1, sizeof(char));
            memcpy(page, data + shard_bytes * 0, shard_bytes);
            status_code = MHD_HTTP_OK;
        } else if (0 == strcmp(url, "/shards/17416a592487d7b1b74c100448c8296122d8aff8")) {
            page = calloc(shard_bytes + 1, sizeof(char));
            memcpy(page, data + shard_bytes * 1, shard_bytes);
            status_code = MHD_HTTP_OK;
        } else if (0 == strcmp(url, "/shards/83cf5eaf2311a1ae9699772d9bafbb3e369a41cc")) {
            page = calloc(shard_bytes + 1, sizeof(char));
            memcpy(page, data + shard_bytes * 2, shard_bytes);
            status_code = MHD_HTTP_OK;
        } else if (0 == strcmp(url, "/shards/214ed86cb1287fe0fd18c174eecbf84341bf2655")) {
            page = calloc(shard_bytes + 1, sizeof(char));
            memcpy(page, data + shard_bytes * 3, shard_bytes);
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
            status_code = MHD_HTTP_OK;
            e_count += 1;
        } else if (0 == strcmp(url, "/shards/0219bb523832c09c77069c74804e5b0476cea7cf")) {
            page = calloc(shard_bytes + 1, sizeof(char));
            memcpy(page, data + shard_bytes * 5, shard_bytes);
            status_code = MHD_HTTP_OK;
        } else if (0 == strcmp(url, "/shards/ebcbe78dd209a03d3ce29f2e5460304de2060031")) {
            page = calloc(shard_bytes + 1, sizeof(char));
            memcpy(page, data + shard_bytes * 6, shard_bytes);
            status_code = MHD_HTTP_OK;
        } else if (0 == strcmp(url, "/shards/5ecd6cc2964a344b42406d3688e13927a51937aa")) {
            page = calloc(shard_bytes + 1, sizeof(char));
            memcpy(page, data + shard_bytes * 7, shard_bytes);
            status_code = MHD_HTTP_OK;
        } else if (0 == strcmp(url, "/shards/88c5e8885160c449b1dbb00ccf317067200b39a0")) {
            page = calloc(shard_bytes + 1, sizeof(char));
            memcpy(page, data + shard_bytes * 8, shard_bytes);
            status_code = MHD_HTTP_OK;
        } else if (0 == strcmp(url, "/shards/76b1a97498e026c47c924374b5b1148543d5c0ab")) {
            page = calloc(shard_bytes + 1, sizeof(char));
            memcpy(page, data + shard_bytes * 9, shard_bytes);
            status_code = MHD_HTTP_OK;
        } else if (0 == strcmp(url, "/shards/48e02627e37433c89fa034d3ee2df644ac7ac7a0")) {
            page = calloc(shard_bytes + 1, sizeof(char));
            memcpy(page, data + shard_bytes * 10, shard_bytes);
            status_code = MHD_HTTP_OK;
        } else if (0 == strcmp(url, "/shards/e4617532be728d48a8155ecfb200d50f00a01a23")) {
            page = calloc(shard_bytes + 1, sizeof(char));
            memcpy(page, data + shard_bytes * 11, shard_bytes);
            status_code = MHD_HTTP_OK;
        } else if (0 == strcmp(url, "/shards/973701b43290e3bef7007db0cb75744f9556ae3b")) {
            page = calloc(shard_bytes + 1, sizeof(char));
            memcpy(page, data + shard_bytes * 12, shard_bytes);
            status_code = MHD_HTTP_OK;
        } else if (0 == strcmp(url, "/shards/a0ec63ad4069fa51a53871c7a282e184371b842b")) {
            page = calloc(shard_bytes + 1, sizeof(char));
            memcpy(page, data + shard_bytes * 13, shard_bytes);
            status_code = MHD_HTTP_OK;
        } else if (0 == strcmp(url, "/shards/424cdf090604317570da38ef7d5b41abea0952df")) {
            // this is parity shard #2, parity shard #1 is missing
            page = calloc(shard_bytes + 1, sizeof(char));
            memcpy(page, data + shard_bytes * 15, shard_bytes);
            status_code = MHD_HTTP_OK;
        } else if (0 == strcmp(url, "/shards/a292c0de26b2a9086473905abb938c7a1c45a9e9")) {
            page = calloc(shard_bytes + 1, sizeof(char));
            memcpy(page, data + shard_bytes * 16, shard_bytes);
            status_code = MHD_HTTP_OK;
        } else if (0 == strcmp(url, "/shards/aca155b4deeac64f2be748e3c434e1f5e9719ef3")) {
            page = calloc(shard_bytes + 1, sizeof(char));
            memcpy(page, data + shard_bytes * 17, shard_bytes);
            status_code = MHD_HTTP_OK;
        } else {
            printf("url: %s\n", url);
        }

        char *sent_page = NULL;

        if (page) {
            sent_page = malloc(shard_bytes_sent + 1);
            memcpy(sent_page, page, shard_bytes_sent);
        } else {
            shard_bytes_sent = 9;
            sent_page = calloc(shard_bytes_sent + 1, sizeof(char));
            strcat(sent_page, "Not Found");
        }

        free(page);

        response = MHD_create_response_from_buffer(shard_bytes_sent,
                                                   (void *) sent_page,
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

void free_farmer_data()
{
    free(data);
}
