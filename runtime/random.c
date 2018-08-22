#include <runtime.h>

static u64 s[2] = { 0xa5a5beefa5a5cafe, 0xbeef55aaface55aa };

u64 random_u64(void) {
    u64 s0 = s[0];
    u64 s1 = s[1];
    u64 result = s0 + s1;

    s1 ^= s0;
    // xxx - no 32 bits
#ifndef BITS32    
    s[0] = rol(s0, 55) ^ s1 ^ (s1 << 14); // a, b
    s[1] = rol(s1, 36); // c
#endif
    return result;
}

