#ifndef STORJ_H
#define STORJ_H

#include <assert.h>
#include <neon/ne_request.h>
#include <nettle/aes.h>
#include <nettle/ripemd160.h>
#include <nettle/hmac.h>
#include <nettle/pbkdf2.h>
#include <nettle/sha.h>
#include <neon/ne_string.h>
#include <json-c/json.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <uv.h>
#include <math.h>

#ifdef _WIN32
#include <time.h>
#endif

#define ERROR 0
#define OK 1
#define FILE_ID_SIZE 12
#define SHARD_MULTIPLES_BACK 5

typedef struct {
    char *proto;
    char *host;
    int port;
    char *user;
    char *pass;
} storj_bridge_options_t;

typedef struct storj_env {
    storj_bridge_options_t *bridge_options;
    uv_loop_t *loop;
} storj_env_t;

typedef enum { false, true } storj_boolean_t;

typedef struct {
    storj_bridge_options_t *options;
    char *method;
    char *path;
    storj_boolean_t auth;
    struct json_object *body;
    struct json_object *response;
} json_request_t;


typedef enum {BUCKET_PUSH, BUCKET_PULL} storj_bucket_op_t;
static const char *BUCKET_OP[] = { "PUSH", "PULL" };

typedef struct {
} storj_shard_tree;

typedef struct {
} storj_shard_challenges;

typedef struct {
    int index;
    char *hash;
    uint64_t size;
    storj_shard_tree tree;
    storj_shard_challenges challenges;
} storj_shard_t;

typedef struct {
    int file_concurrency;
    int shard_concurrency;
    int redundancy;
    int shard_num;
    unsigned long long file_size;
    unsigned long long shard_size;
    char *bucket_id;
    char *file_path;
    char *file_id;
    char *file_name;
    char *key_pass;
} storj_upload_opts_t;

typedef struct {
    storj_env_t env;
    storj_upload_opts_t opts;
    uv_fs_t *open_req;
    uv_fs_t *read_req;
} storj_upload_work_data_t;

storj_env_t *storj_init_env(storj_bridge_options_t *options);

int storj_bridge_get_info(storj_env_t *env, uv_after_work_cb cb);

int storj_bridge_get_buckets(storj_env_t *env, uv_after_work_cb cb);

int storj_bridge_create_bucket(storj_env_t *env,
                               char *name,
                               uv_after_work_cb cb);

int storj_bridge_delete_bucket(storj_env_t *env, char *id, uv_after_work_cb cb);

int storj_bridge_list_files(storj_env_t *env, char *id, uv_after_work_cb cb);

int storj_bridge_create_bucket_token(storj_env_t *env,
                                     char *bucket_id,
                                     storj_bucket_op_t operation,
                                     uv_after_work_cb cb);

int storj_bridge_delete_file(storj_env_t *env,
                             char *bucket_id,
                             char *file_id,
                             uv_after_work_cb cb);

int storj_bridge_create_frame(storj_env_t *env, uv_after_work_cb cb);

int storj_bridge_get_frames(storj_env_t *env, uv_after_work_cb cb);

int storj_bridge_get_frame(storj_env_t *env,
                           char *frame_id,
                           uv_after_work_cb cb);

int storj_bridge_delete_frame(storj_env_t *env,
                              char *frame_id,
                              uv_after_work_cb cb);

int storj_bridge_add_shard_to_frame(storj_env_t *env,
                                    char *frame_id,
                                    storj_shard_t *shard,
                                    uv_after_work_cb cb);

int storj_bridge_get_file_info(storj_env_t *env,
                               char *bucket_id,
                               char *file_id,
                               uv_after_work_cb cb);

int storj_bridge_store_file(storj_env_t *env,
                            storj_upload_opts_t *opts);

int storj_bridge_get_file_pointers(storj_env_t *env, uv_after_work_cb cb);

int storj_bridge_resolve_file(storj_env_t *env, uv_after_work_cb cb);

int storj_bridge_replicate_file(storj_env_t *env, uv_after_work_cb cb);

unsigned long long check_file(storj_env_t *env, char *filepath);

int sha256_of_str(const uint8_t *str, int str_len, uint8_t *digest);

int ripemd160_of_str(const uint8_t *str, int str_len, uint8_t *digest);

void pbkdf2_hmac_sha512(unsigned key_length,
                        const uint8_t *key,
                        unsigned iterations,
                        unsigned salt_length, const uint8_t *salt,
                        unsigned length, uint8_t *dst);

void random_buffer(uint8_t *buf, size_t len);

unsigned long long determine_shard_size(storj_upload_opts_t *opts,
                                        int accumulator);

unsigned long long shardSize(int hops);

int calculate_file_id(char *bucket, char *file_name, char **buff);

void open_cb(uv_fs_t*);

void read_cb(uv_fs_t*);

void close_cb(uv_fs_t*);

#endif /* STORJ_H */
