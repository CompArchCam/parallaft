#define XXH_NO_STDLIB
#define XXH_INLINE_ALL
#define XXH_STATIC_LINKING_ONLY

#include "std/std.h"
#include <xxhash.h>
#include <sys/uio.h>

struct hasher_args_t
{
    const struct iovec *iovecs;
    size_t len;
};

void main(const struct hasher_args_t *args, XXH64_hash_t *result)
{
    XXH3_state_t state;
    XXH3_64bits_reset(&state);

    for (size_t i = 0; i < args->len; i++)
    {
        XXH3_64bits_update(&state, args->iovecs[i].iov_base, args->iovecs[i].iov_len);
    }

    *result = XXH3_64bits_digest(&state);
}
