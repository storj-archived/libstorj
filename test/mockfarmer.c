#include <nettle/aes.h>
#include <nettle/ctr.h>

#include "storjtests.h"

static int e_count = 0;

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

    if (0 == strcmp(method, "GET")) {
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
        }
    }

    if (0 == strcmp(method, "POST")) {
        // TODO verify upload data

        if (0 == strcmp(url, "/")) {
            status_code = MHD_HTTP_OK;
        } else if (0 == strcmp(url, "/shards/10f5c5300bd82edf4f779596f2abfc0e73850bb4")) {
            status_code = MHD_HTTP_OK;
        } else if (0 == strcmp(url, "/shards/1aa592ff1658b62f3e46e3a0523bb3e475192231")) {
            status_code = MHD_HTTP_OK;
        } else if (0 == strcmp(url, "/shards/2782b8a1e2ca93d4c2ecba7c5f8d14534a4da136")) {
            status_code = MHD_HTTP_OK;
        } else if (0 == strcmp(url, "/shards/2b612a8b9119ddfb5086ff9531fd5982f37f4235")) {
            status_code = MHD_HTTP_OK;
        } else if (0 == strcmp(url, "/shards/38e6c43cc958daa999de968b87ea45dbb0715a36")) {
            status_code = MHD_HTTP_OK;
        } else if (0 == strcmp(url, "/shards/5d8ad8720a3123969ef157032fd9d43f0767f859")) {
            status_code = MHD_HTTP_OK;
        } else if (0 == strcmp(url, "/shards/5e6004890307b74d84f560d5b77ca90803ebbb80")) {
            status_code = MHD_HTTP_OK;
        } else if (0 == strcmp(url, "/shards/5f56ef65b4efa94e76c5e370fe3cec045f78d6ee")) {
            status_code = MHD_HTTP_OK;
        } else if (0 == strcmp(url, "/shards/612d7f13db894124b077ae9c5ab4a2ddfca770e3")) {
            status_code = MHD_HTTP_OK;
        } else if (0 == strcmp(url, "/shards/64024717efb0d64e8c3305628828d5bd47592f2a")) {
            status_code = MHD_HTTP_OK;
        } else if (0 == strcmp(url, "/shards/64d5cd6b463fdb2da5a0b30b1aecf2325d87a703")) {
            status_code = MHD_HTTP_OK;
        } else if (0 == strcmp(url, "/shards/6674b562fff319bf1d604d3be0741d0610c20b7b")) {
            status_code = MHD_HTTP_OK;
        } else if (0 == strcmp(url, "/shards/673bcea20dce8b05ee7e854f45ccd87086035c3c")) {
            status_code = MHD_HTTP_OK;
        } else if (0 == strcmp(url, "/shards/6e22510c1ea87e4b6aa68b781651e5d91f021a9d")) {
            status_code = MHD_HTTP_OK;
        } else if (0 == strcmp(url, "/shards/720856fcc241c05f9fd28d33981d8a417206f468")) {
            status_code = MHD_HTTP_OK;
        } else if (0 == strcmp(url, "/shards/72dda673fe94d9a019bc0ffe51f0bfbdef2b52d0")) {
            status_code = MHD_HTTP_OK;
        } else if (0 == strcmp(url, "/shards/78f448e3e4828b9799431976b91f3ee5c4a1023a")) {
            status_code = MHD_HTTP_OK;
        } else if (0 == strcmp(url, "/shards/7af774d76021178e104a57dc9e5a014f871c5d96")) {
            status_code = MHD_HTTP_OK;
        } else if (0 == strcmp(url, "/shards/8d1f89a5139fd0959a47e7ffcde3c228fb5dacff")) {
            status_code = MHD_HTTP_OK;
        } else if (0 == strcmp(url, "/shards/9c670c19b3830a5c7d362aabeeffe3e14d9a1c83")) {
            status_code = MHD_HTTP_OK;
        } else if (0 == strcmp(url, "/shards/a4547c124afb1b6459bdfdebf1cc2da411cbccbb")) {
            status_code = MHD_HTTP_OK;
        } else if (0 == strcmp(url, "/shards/b44976cba53ec814caa460d8aa6f0ba7668082b2")) {
            status_code = MHD_HTTP_OK;
        } else if (0 == strcmp(url, "/shards/c1a21245a6786ae9ca55fefcd3b8f27721a9d561")) {
            status_code = MHD_HTTP_OK;
        } else if (0 == strcmp(url, "/shards/cdc18b4ef951e8d1468b1c9c0b8b15f187b7609c")) {
            status_code = MHD_HTTP_OK;
        } else if (0 == strcmp(url, "/shards/cdc7246ba4c9766a148447eab431ede0f3f5343c")) {
            status_code = MHD_HTTP_OK;
        } else if (0 == strcmp(url, "/shards/f1e392a29ce661967c6aa7a2e57e9e1447c1e6ee")) {
            status_code = MHD_HTTP_OK;
        } else if (0 == strcmp(url, "/shards/febcc72c25b3b693484d54c0393a50168b055309")) {
            status_code = MHD_HTTP_OK;
        } else if (0 == strcmp(url, "/shards/ff481fc3fa7ab4d74ad631b54c76f81602b9b0f2")) {
            status_code = MHD_HTTP_OK;
        } else if (0 == strcmp(url, "/shards/ff481fc3fa7ab4d74ad631b54c76f81602b9b0f2")) {
            status_code = MHD_HTTP_OK;
        } else {
            printf("url: %s\n", url);
        }
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
