#define XXH_NO_STDLIB
#define XXH_INLINE_ALL
#define XXH_STATIC_LINKING_ONLY

#include "std/std.h"
#include <xxhash.h>

struct hasher_args_t
{
    const void **addresses;
    size_t nr_pages;
    size_t page_size;
};

void main(const struct hasher_args_t *args, XXH64_hash_t *result)
{
    XXH3_state_t state;
    XXH3_64bits_reset(&state);

    for (size_t i = 0; i < args->nr_pages; i++)
    {
        XXH3_64bits_update(&state, args->addresses[i], args->page_size);
    }

    *result = XXH3_64bits_digest(&state);
}
