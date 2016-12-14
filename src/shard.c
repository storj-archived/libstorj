#include "storj.h"

#define MAX_SHARD_SIZE 1073741824

uint64_t determine_shard_size(storj_upload_state_t *state, int accumulator)
{
    int shard_concurrency;
    uint64_t file_size;

    if (!state->file_size) {
      // TODO: Log the error
      printf("Cannot determine shard size when there is no file size.\n");
      return 0;
    } else {
      file_size = state->file_size;
    }

    if (!state->shard_concurrency) {
      shard_concurrency = 3;
    } else {
      shard_concurrency = state->shard_concurrency;
    }

    accumulator = accumulator ? accumulator : 0;
    // Determine hops back by accumulator
    int hops = ((accumulator - SHARD_MULTIPLES_BACK) < 0 ) ? 0: accumulator - SHARD_MULTIPLES_BACK;
    uint64_t byteMultiple = shardSize(accumulator);
    double check = (double) file_size / byteMultiple;

    // Determine if bytemultiple is highest bytemultiple that is still <= size
    if (check > 0 && check <= 1) {

      // Certify the number of concurrency * shardSize doesn't exceed freemem
      while (
        hops > 0 &&
        (MAX_SHARD_SIZE / shardSize(hops) <= shard_concurrency) //TODO: 1GB max memory
      ) {
        hops = hops - 1 <= 0 ? 0 : hops - 1;
      }

      return shardSize(hops);
    }

    return determine_shard_size(&state, ++accumulator);
}

uint64_t shardSize(int hops)
{
    return (8  * (1024 * 1024)) * pow(2, hops);
};
