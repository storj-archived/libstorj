/**
 * @file uploader.h
 * @brief Storj upload methods and definitions.
 *
 * Structures and functions useful for uploading files.
 */
#ifndef STORJ_UPLOADER_H
#define STORJ_UPLOADER_H

#include "storj.h"
#include "http.h"
#include "utils.h"
#include "crypto.h"

#define MAX_SHARD_SIZE 1073741824
#define SHARD_MULTIPLES_BACK 5

static void queue_next_work(storj_upload_state_t *state);

static int queue_request_bucket_token(storj_upload_state_t *state);
static int queue_request_frame(storj_upload_state_t *state);
static int queue_encrypt_file(storj_upload_state_t *state);

static void request_token(uv_work_t *work);
static void request_frame(uv_work_t *work);
static void encrypt_file(uv_work_t *work);

static void after_request_token(uv_work_t *work, int status);
static void after_request_frame(uv_work_t *work, int status);
static void after_encrypt_file(uv_work_t *work, int status);

#endif /* STORJ_UPLOADER_H */
