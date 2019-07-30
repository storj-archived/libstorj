#ifndef __RS_H_
#define __RS_H_

/* use small value to save memory */
#ifndef DATA_SHARDS_MAX
#define DATA_SHARDS_MAX (255)
#endif

/* use other memory allocator */
#ifndef RS_MALLOC
#define RS_MALLOC(x)    malloc(x)
#endif

#ifndef RS_FREE
#define RS_FREE(x)      free(x)
#endif

#ifndef RS_CALLOC
#define RS_CALLOC(n, x) calloc(n, x)
#endif

typedef struct _reed_solomon {
    int data_shards;
    int parity_shards;
    int shards;
    uint8_t* m;
    uint8_t* parity;
} reed_solomon;

/**
 * @brief Initializes data structures used for computations in GF.
 */
void fec_init(void);

/**
 * @brief Will initialize new reed solomon
 *
 * @param[in] data_shards Total number of data shards
 * @param[in] parity_shards The total number of parity shards
 * @return A null value on error
 */
reed_solomon* reed_solomon_new(int data_shards, int parity_shards);

/**
 * @brief Will free existing reed solomon
 *
 * @param[in] rs
 */
void reed_solomon_release(reed_solomon* rs);

int reed_solomon_encode(reed_solomon* rs,
                        uint8_t** data_blocks,
                        uint8_t** fec_blocks,
                        uint64_t block_size,
                        uint64_t total_bytes);


int reed_solomon_decode(reed_solomon* rs,
                        uint8_t **data_blocks,
                        uint64_t  block_size,
                        uint8_t **dec_fec_blocks,
                        unsigned int *fec_block_nos,
                        unsigned int *erased_blocks,
                        int nr_fec_blocks,
                        uint64_t total_bytes);


/**
 * @brief Will encode large buffer into parity shards
 *
 * @param[in] rs
 * @param[in] data_blocks Data shards
 * @param[in] fec_blocks Parity shards
 * @param[in] nr_shards Total number of shards/blocks
 * @param[in] block_size The size of each shard
 * @param[in] total_bytes The total size used for zero padding the last shard
 * @return A non-zero error value on failure and 0 on success.
 */
int reed_solomon_encode2(reed_solomon* rs, uint8_t** data_blocks,
                         uint8_t** fec_blocks, int nr_shards, uint64_t block_size,
                         uint64_t total_bytes);

/**
 * @brief Will repair missing data in blocks
 *
 * @param[in] rs
 * @param[in] data_blocks Data shards
 * @param[in] fec_blocks Parity shards
 * @param[in] marks An array with 1 used to mark missing blocks
 * @param[in] nr_shards Total number of shards/blocks
 * @param[in] block_size The size of each shard
 * @param[in] total_bytes The total size used for zero padding the last shard
 * @return A non-zero error value on failure and 0 on success.
 */
int reed_solomon_reconstruct(reed_solomon* rs, uint8_t** data_blocks,
                             uint8_t** fec_blocks, uint8_t* marks,
                             int nr_shards, uint64_t block_size,
                             uint64_t total_bytes);
#endif
