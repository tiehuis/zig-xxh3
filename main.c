#include <stdio.h>
#define XXH_STATIC_LINKING_ONLY
#define XXH_IMPLEMENTATION
#include "xxhash.h"

int main(void)
{
    char buf[1024];
    for (int i = 0; i < 1024; i++) {
        buf[i] = 'a';
    }

    for (int i = 0; i < 1024; i++) {
        XXH64_hash_t r = XXH3_64bits_withSeed(buf, i, 0);
        printf("%03d: %llx\n", i, r);
    }
}
