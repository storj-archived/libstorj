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

#define OK 0
#define ERROR 1

int hex2str(unsigned length, uint8_t *data, char *buffer);

void print_int_array(uint8_t *array, unsigned length);

int str2hex(unsigned length, char *data, uint8_t *buffer);

void random_buffer(uint8_t *buf, size_t len);

uint64_t shard_size(int hops);

#endif /* STORJ_UTILS_H */
