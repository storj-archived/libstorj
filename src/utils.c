#include "utils.h"

char *hex2str(size_t length, uint8_t *data)
{
    size_t encode_len = BASE16_ENCODE_LENGTH(length);
    uint8_t *result = calloc(encode_len + 1, sizeof(uint8_t));
    if (!result) {
        return NULL;
    }

    base16_encode_update(result, length, data);

    return (char *)result;
}

void print_int_array(uint8_t *array, unsigned length)
{
    printf("{");
    int i;
    for (i = 0; i < length; i++) {
        printf("%i", array[i]);
        if (i != length - 1) {
            printf(",");
        }
    }
    printf("}\n");
}

uint8_t *str2hex(size_t length, char *data)
{
    char *result = calloc(BASE16_DECODE_LENGTH(length) + 1, sizeof(char));
    if (!result) {
        return NULL;
    }

    struct base16_decode_ctx *ctx = malloc(sizeof(struct base16_decode_ctx));
    base16_decode_init(ctx);

    size_t decode_len = 0;
    if (!base16_decode_update(ctx, &decode_len, (uint8_t *)result,
                              length, (uint8_t *)data)) {
        free(result);
        free(ctx);
        return NULL;
    }

    if (!base16_decode_final(ctx)) {
        free(result);
        free(ctx);
        return NULL;
    }

    free(ctx);
    return (uint8_t *)result;
}

char *str_concat_many(int count, ...)
{
    int length = 1;

    va_list args;
    va_start(args, count);
    int i;
    for (i = 0; i < count; i++) {
        char *item = va_arg(args, char *);
        length += strlen(item);
    }
    va_end(args);

    char *combined = calloc(length, sizeof(char));
    if (!combined) {
        return NULL;
    }

    va_start(args, count);
    for (i = 0; i < count; i++) {
        char *item = va_arg(args, char *);
        strcat(combined, item);
    }
    va_end(args);

    return combined;
}

void random_buffer(uint8_t *buf, size_t len)
{
    static FILE *frand = NULL;
#ifdef _WIN32
    HCRYPTPROV hProvider;
    int ret = CryptAcquireContextW(&hProvider, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT);
    assert(ret);
    ret = CryptGenRandom(hProvider, len, buf);
    assert(ret);
    CryptReleaseContext(hProvider, 0);
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

uint64_t get_time_milliseconds() {
#ifdef _WIN32

    // Time between windows epoch and standard epoch
    const int64_t time_to_epoch = 116444736000000000LL;

    FILETIME ft;

    GetSystemTimePreciseAsFileTime(&ft);

    LARGE_INTEGER li;
    li.LowPart = ft.dwLowDateTime;
    li.HighPart = ft.dwHighDateTime;
    li.QuadPart -= time_to_epoch;
    li.QuadPart /= 10000;

    uint64_t milliseconds = li.QuadPart;
#else
    struct timeval t;
    gettimeofday(&t, NULL);
    uint64_t milliseconds = t.tv_sec * 1000LL + t.tv_usec / 1000;
#endif

    return milliseconds;
}

void memset_zero(void *v, size_t n)
{
#ifdef _WIN32
    SecureZeroMemory(v, n);
#else
    volatile unsigned char *p = v;
    while (n--) {
        *p++ = 0;
    }
#endif
}

#ifdef _WIN32
ssize_t pread(int fd, void *buf, size_t count, uint64_t offset)
{
    long unsigned int read_bytes = 0;

    OVERLAPPED overlapped;
    memset(&overlapped, 0, sizeof(OVERLAPPED));

    HANDLE hEvent;
    hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    if (hEvent) {
        overlapped.hEvent = hEvent;
    } else {
        printf("\nCreate event failed with error:%d",GetLastError());
        return 0;
    }

    overlapped.Offset = offset;

    HANDLE file = (HANDLE)_get_osfhandle(fd);
    SetLastError(0);
    bool RF = ReadFile(file, buf, count, &read_bytes, &overlapped);
    if ((RF==0) && GetLastError() == ERROR_IO_PENDING) {
        // Asynch readfile started. I can do other operations now
        while( !GetOverlappedResult(file, &overlapped, &read_bytes, TRUE)) {
            if (GetLastError() == ERROR_IO_INCOMPLETE) {
                // printf("I/O pending: %d .\n",GetLastError());
            } else if  (GetLastError() == ERROR_HANDLE_EOF) {
                // printf("End of file reached.\n");
                return 0;
            } else {
                // printf("GetOverlappedResult failed with error:%d\n",GetLastError());
                return 0;
            }
        }
    } else if ((RF == 0) && GetLastError() != ERROR_IO_PENDING) {
        // printf ("Error reading file :%d\n",GetLastError());
        return 0;
    }

    return read_bytes;
}

ssize_t pwrite(int fd, const void *buf, size_t count, uint64_t offset)
{
    long unsigned int written_bytes = 0;

    OVERLAPPED overlapped;
    memset(&overlapped, 0, sizeof(OVERLAPPED));

    HANDLE hEvent;
    hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    if (hEvent) {
        overlapped.hEvent = hEvent;
    } else {
        printf("\nCreate event failed with error:%d",GetLastError());
        return 0;
    }

    overlapped.Offset = offset;

    HANDLE file = (HANDLE)_get_osfhandle(fd);
    SetLastError(0);
    bool RF = WriteFile(file, buf, count, &written_bytes, &overlapped);
    if ((RF==0) && GetLastError() == ERROR_IO_PENDING) {
        // Asynch readfile started. I can do other operations now
        while( !GetOverlappedResult(file, &overlapped, &written_bytes, TRUE)) {
            if (GetLastError() == ERROR_IO_INCOMPLETE) {
                // printf("I/O pending: %d .\n",GetLastError());
            } else if  (GetLastError() == ERROR_HANDLE_EOF) {
                // printf("End of file reached.\n");
                return 0;
            } else {
                // printf("GetOverlappedResult failed with error:%d\n",GetLastError());
                return 0;
            }
        }
    } else if ((RF == 0) && GetLastError() != ERROR_IO_PENDING) {
        // printf ("Error reading file :%d\n",GetLastError());
        return 0;
    }

    return written_bytes;
}
#endif
