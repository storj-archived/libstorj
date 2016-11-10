#ifndef STORJ_H
#define STORJ_H

#include <neon/ne_request.h>
#include <nettle/aes.h>
#include <neon/ne_string.h>
#include <json-c/json.h>
#include <string.h>

typedef struct {
    char *proto;
    char *host;
    int port;
    char *user;
    char *pass;
} storj_bridge_options;

typedef enum { false, true } boolean;

struct json_object* storj_bridge_get_info(storj_bridge_options *options);
struct json_object* storj_bridge_get_buckets(storj_bridge_options *options);
struct json_object* storj_bridge_create_bucket();
struct json_object* storj_bridge_delete_bucket();
struct json_object* storj_bridge_list_files();
struct json_object* storj_bridge_create_bucket_token();
struct json_object* storj_bridge_delete_file();
struct json_object* storj_bridge_create_frame();
struct json_object* storj_bridge_get_frames();
struct json_object* storj_bridge_get_file_info();
struct json_object* storj_bridge_get_frame();
struct json_object* storj_bridge_delete_frame();
struct json_object* storj_bridge_add_shard_to_frame();
struct json_object* storj_bridge_replicate_file();
struct json_object* storj_bridge_store_file();
struct json_object* storj_bridge_get_file_pointers();
struct json_object* storj_bridge_resolve_file();

#endif /* STORJ_H */
