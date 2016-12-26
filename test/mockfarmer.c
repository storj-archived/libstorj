#include <nettle/aes.h>
#include <nettle/ctr.h>

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


    int status_code = MHD_HTTP_NOT_FOUND;

    int ret;

    int total_bytes = 16777216;
    char *page = "Not Found";

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
        if (0 == strcmp(url, "/shards/576fc7f60ff5819b824d868f07cb1c2dde5712af")) {
            page = calloc(total_bytes + 1, sizeof(char));
            memset(page, 'a', total_bytes);
            increment_ctr_aes_iv(ctr, total_bytes * 0);
            status_code = MHD_HTTP_OK;
        } else if (0 == strcmp(url, "/shards/03d8d76f0a473bb9b4823365649d21cdede9ed06")) {
            page = calloc(total_bytes + 1, sizeof(char));
            memset(page, 'b', total_bytes);
            increment_ctr_aes_iv(ctr, total_bytes * 1);
            status_code = MHD_HTTP_OK;
        } else if (0 == strcmp(url, "/shards/f02ec907952b3d9307018d25d8977a86da7ac628")) {
            page = calloc(total_bytes + 1, sizeof(char));
            memset(page, 'c', total_bytes);
            increment_ctr_aes_iv(ctr, total_bytes * 2);
            status_code = MHD_HTTP_OK;
        } else if (0 == strcmp(url, "/shards/810b2960020caca44796dc42c7bb226987f00b40")) {
            page = calloc(total_bytes + 1, sizeof(char));
            memset(page, 'd', total_bytes);
            increment_ctr_aes_iv(ctr, total_bytes * 3);
            status_code = MHD_HTTP_OK;
        } else if (0 == strcmp(url, "/shards/b3262bf52f0ce496a0f66f3a04006a275c03bc7e")) {
            page = calloc(total_bytes + 1, sizeof(char));
            memset(page, 'e', total_bytes);
            increment_ctr_aes_iv(ctr, total_bytes * 4);
            status_code = MHD_HTTP_OK;
        } else if (0 == strcmp(url, "/shards/0233f478fd335f8923a8a1f95b728864c71462f5")) {
            page = calloc(total_bytes + 1, sizeof(char));
            memset(page, 'f', total_bytes);
            increment_ctr_aes_iv(ctr, total_bytes * 5);
            status_code = MHD_HTTP_OK;
        } else if (0 == strcmp(url, "/shards/4dde6d2b4103073c16908d1acda0f197d11ddc5a")) {
            page = calloc(total_bytes + 1, sizeof(char));
            memset(page, 'g', total_bytes);
            increment_ctr_aes_iv(ctr, total_bytes * 6);
            status_code = MHD_HTTP_OK;
        } else if (0 == strcmp(url, "/shards/a328f649d6d0459f9f9582ce0e346980aa125dcb")) {
            page = calloc(total_bytes + 1, sizeof(char));
            memset(page, 'h', total_bytes);
            increment_ctr_aes_iv(ctr, total_bytes * 7);
            status_code = MHD_HTTP_OK;
        } else if (0 == strcmp(url, "/shards/097cc86ce558935ddfa3f2eae5fa7e8b73d4bf89")) {
            page = calloc(total_bytes + 1, sizeof(char));
            memset(page, 'i', total_bytes);
            increment_ctr_aes_iv(ctr, total_bytes * 8);
            status_code = MHD_HTTP_OK;
        } else if (0 == strcmp(url, "/shards/e88e335ea487a0bfc4391cca1520652ca77a4820")) {
            page = calloc(total_bytes + 1, sizeof(char));
            memset(page, 'j', total_bytes);
            increment_ctr_aes_iv(ctr, total_bytes * 9);
            status_code = MHD_HTTP_OK;
        } else if (0 == strcmp(url, "/shards/7c81204e3e4eed609b16752bb8f7957327c5537e")) {
            page = calloc(total_bytes + 1, sizeof(char));
            memset(page, 'k', total_bytes);
            increment_ctr_aes_iv(ctr, total_bytes * 10);
            status_code = MHD_HTTP_OK;
        } else if (0 == strcmp(url, "/shards/a7644c8cb2bd40114a0c628673f020ec8cb94b50")) {
            page = calloc(total_bytes + 1, sizeof(char));
            memset(page, 'l', total_bytes);
            increment_ctr_aes_iv(ctr, total_bytes * 11);
            status_code = MHD_HTTP_OK;
        } else if (0 == strcmp(url, "/shards/ae559e7747086905ba4704ed80836417861cd6a0")) {
            page = calloc(total_bytes + 1, sizeof(char));
            memset(page, 'm', total_bytes);
            increment_ctr_aes_iv(ctr, total_bytes * 12);
            status_code = MHD_HTTP_OK;
        } else if (0 == strcmp(url, "/shards/f90f8cc815f341c575d06d4029620076c2072cf4")) {
            page = calloc(total_bytes + 1, sizeof(char));
            memset(page, 'n', total_bytes);
            increment_ctr_aes_iv(ctr, total_bytes * 13);
            status_code = MHD_HTTP_OK;
        }
    }

    char *crypt_page = malloc(total_bytes + 1);

    ctr_crypt(ctx, (nettle_cipher_func *)aes256_encrypt,
              AES_BLOCK_SIZE, ctr,
              total_bytes, crypt_page, page);

    free(page);

    response = MHD_create_response_from_buffer(total_bytes,
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
