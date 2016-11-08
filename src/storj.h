#ifndef STORJ_H
#define STORJ_H

#include <neon/ne_request.h>
#include <nettle/aes.h>
#include <libwebsockets.h>
#include <json-c/json.h>

struct json_object* storj_bridge_get_info();

#endif /* STORJ_H */
