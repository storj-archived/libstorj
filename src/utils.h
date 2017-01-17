/**
 * @file utils.h
 * @brief Storj utilities.
 *
 * Helper utilities
 */
#ifndef STORJ_UTILS_H
#define STORJ_UTILS_H

#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <math.h>
#include "crypto.h"

#ifdef _WIN32
#include <windows.h>
#else
#include <sys/time.h>
#endif

#define OK 0
#define ERROR 1

int hex2str(unsigned length, uint8_t *data, char *buffer);

void print_int_array(uint8_t *array, unsigned length);

int str2hex(unsigned length, char *data, uint8_t *buffer);

void random_buffer(uint8_t *buf, size_t len);

uint64_t shard_size(int hops);

int *read_encrypted_file(char *filename, char *key, char *salt, char **result);

int write_encrypted_file(char *filename, char *key, char *salt, char *data);

uint64_t get_time_milliseconds();

#endif /* STORJ_UTILS_H */
