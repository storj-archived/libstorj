#ifndef STORJ_H
#define STORJ_H

#include <assert.h>
#include <neon/ne_request.h>
#include <nettle/aes.h>
#include <neon/ne_string.h>
#include <json-c/json.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <uv.h>

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
    int64_t loop_counter;
} storj_env_t;

typedef enum { false, true } boolean_t;

typedef struct {
    storj_bridge_options_t *options;
    char *method;
    char *path;
    boolean_t auth;
    struct json_object *response;
} json_request_t;

storj_env_t *storj_init_env(storj_bridge_options_t *options);
int storj_bridge_get_info(storj_env_t *env, uv_after_work_cb cb);
int storj_bridge_get_buckets(storj_env_t *env, uv_after_work_cb cb);
struct json_object *storj_bridge_create_bucket();
struct json_object *storj_bridge_delete_bucket();
struct json_object *storj_bridge_list_files();
struct json_object *storj_bridge_create_bucket_token();
struct json_object *storj_bridge_delete_file();
struct json_object *storj_bridge_create_frame();
struct json_object *storj_bridge_get_frames();
struct json_object *storj_bridge_get_file_info();
struct json_object *storj_bridge_get_frame();
struct json_object *storj_bridge_delete_frame();
struct json_object *storj_bridge_add_shard_to_frame();
struct json_object *storj_bridge_replicate_file();
struct json_object *storj_bridge_store_file();
struct json_object *storj_bridge_get_file_pointers();
struct json_object *storj_bridge_resolve_file();

#endif /* STORJ_H */
