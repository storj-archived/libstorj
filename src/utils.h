/**
 * @file utils.h
 * @brief Storj utilities.
 *
 * Helper utilities
 */
#ifndef STORJ_UTILS_H
#define STORJ_UTILS_H
#define _GNU_SOURCE

#include <assert.h>
#include <errno.h>
#include <math.h>
#include <nettle/base16.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>

#ifdef _WIN32
#include <windows.h>
#include <time.h>
#include <io.h>

ssize_t pread(int fd, void *buf, size_t count, uint64_t offset);
ssize_t pwrite(int fd, const void *buf, size_t count, uint64_t offset);

#else
#include <sys/time.h>
#include <sys/mman.h>
#endif

#define MAX_SHARD_SIZE 4294967296 // 4Gb
#define MIN_SHARD_SIZE 2097152 // 2Mb
#define SHARD_MULTIPLES_BACK 4

int allocatefile(int fd, uint64_t length);

char *hex2str(size_t length, uint8_t *data);

void print_int_array(uint8_t *array, unsigned length);

uint8_t *str2hex(size_t length, char *data);

char *str_concat_many(int count, ...);

/**
 * @brief Replace all occurrences of the search string with the replacement string
 *
 * The result string from this function must be freed.
 *
 * @param[in] search The value being searched for, otherwise known as the needle
 * @param[in] replace The replacement value that replaces found search values
 * @param[in] subject The string being searched and replaced on, otherwise known as the haystack.
 * @return A null value on error, otherwise a string with replaced values.
 */
char *str_replace(char *search, char *replace, char *subject);

void random_buffer(uint8_t *buf, size_t len);

uint64_t shard_size(int hops);

uint64_t get_time_milliseconds();

void memset_zero(void *v, size_t n);

uint64_t determine_shard_size(uint64_t file_size, int accumulator);

int unmap_file(uint8_t *map, uint64_t filesize);

int map_file(int fd, uint64_t filesize, uint8_t **map, bool read_only);

#endif /* STORJ_UTILS_H */
