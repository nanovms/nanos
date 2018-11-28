#include <runtime.h>
#include <getrandom.h>
#include <buffer.h>

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

u64 do_getrandom(buffer b, u64 flags)
{
    u64 i;
    u64 len = buffer_length(b);
    u8 *buf = (u8 *) buffer_ref(b, 0);
    u64 random_val = random_u64();

    runtime_memset(buf, 0, len);

    for(i = 0; i < len; ) {
        buf[i] = ((u8 *) (&random_val))[i % 8];

        i ++;
        if (i % 8 == 0)
            random_val = random_u64();

        if (flags == GRND_RANDOM && i == (MAX_RANDOM_ENTROPY_COUNT - 1))
            break;
    }
    return i;
}


