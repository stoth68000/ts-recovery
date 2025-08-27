
/*
 * Hashing implementation of FNV-1A as descripted in
 * https://en.wikipedia.org/wiki/Fowler–Noll–Vo_hash_function
 * 
 * Steven Toth <stoth@kernellabs.com>
 * Copyright (c) 2025 Kernel Labs Inc. All Rights Reserved.
 */

#include <stdint.h>
#include <stddef.h>

static inline uint64_t ltntstools_packet_fingerprint64(const uint8_t *pkt)
{
    const uint64_t FNV_OFFSET = 0xcbf29ce484222325ULL;
    const uint64_t FNV_PRIME  = 0x100000001b3ULL;

    uint64_t h = FNV_OFFSET;

    // Hash bytes 1..187 (skip sync 0x47 at pkt[0])
    for (size_t i = 1; i < 188; i++) {
        h ^= pkt[i];
        h *= FNV_PRIME;
    }

    return h;
}

