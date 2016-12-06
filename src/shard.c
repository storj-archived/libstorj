#include "storj.h"

#define MAX_SHARD_SIZE 1073741824

unsigned long long determine_shard_size(storj_upload_opts_t *opts, int accumulator)
{
    int shard_concurrency;
    unsigned long long file_size;

    if (!opts->file_size) {
      // TODO: Log the error
      printf("Cannot determine shard size when there is no file size.\n");
      return 0;
    } else {
      file_size = opts->file_size;
    }

    if (!opts->shard_concurrency) {
      shard_concurrency = 3;
    } else {
      shard_concurrency = opts->shard_concurrency;
    }

    accumulator = accumulator ? accumulator : 0;
    // Determine hops back by accumulator
    int hops = ((accumulator - SHARD_MULTIPLES_BACK) < 0 ) ? 0: accumulator - SHARD_MULTIPLES_BACK;
    unsigned long long byteMultiple = shardSize(accumulator);
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

    return determine_shard_size(&opts, ++accumulator);
}

unsigned long long shardSize(int hops)
{
    return (8  * (1024 * 1024)) * pow(2, hops);
};
