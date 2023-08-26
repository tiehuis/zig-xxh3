#include <stdio.h>
#define XXH_STATIC_LINKING_ONLY
#define XXH_IMPLEMENTATION
#include "xxhash.h"

int main(void)
{
    char buf[256];
    for (int i = 0; i < 256; i++) {
        buf[i] = 'a';
    }

    for (int i = 0; i < 240; i++) {
        XXH64_hash_t r = XXH3_64bits_withSeed(buf, i, 0);
        printf("%03d: %llx\n", i, r);
    }
}
