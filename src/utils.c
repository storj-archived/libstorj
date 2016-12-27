#include "utils.h"

// TODO possibly use ccan/str/hex/hex.c code for decode and encoding hex

int hex2str(unsigned length, uint8_t *data, char *buffer)
{
    unsigned i;

    memset(buffer, '\0', length*2 + 1);

    for (i = 0; i<length; i++) {
        sprintf(&buffer[i*2], "%02x ", data[i]);
    }

    return OK;
}

void print_int_array(uint8_t *array, unsigned length)
{
    printf("{");
    for (int i = 0; i < length; i++) {
        printf("%i", array[i]);
        if (i != length - 1) {
            printf(",");
        }
    }
    printf("}\n");
}

int str2hex(unsigned length, char *data, uint8_t *buffer)
{
    unsigned i;

    memset(buffer, '\0', length/2 + 1);

    unsigned int *tmp = calloc(length/2, sizeof(unsigned int));

    for (i = 0; i<(length/2); i++) {
        sscanf(data + (i*2), "%2x", tmp + i);
        buffer[i] = (uint8_t)tmp[i];
    }

    free(tmp);

    return OK;
}

void random_buffer(uint8_t *buf, size_t len)
{
    static FILE *frand = NULL;
#ifdef _WIN32
    srand((unsigned)time(NULL));
    size_t i;
    for (i = 0; i < len; i++) {
        buf[i] = rand() % 0xFF;
    }
#else
    if (!frand) {
        frand = fopen("/dev/urandom", "r");
    }
    size_t len_read = fread(buf, 1, len, frand);
    (void)len_read;
    assert(len_read == len);
#endif
}

uint64_t shard_size(int hops)
{
    return (8  * (1024 * 1024)) * pow(2, hops);
};
