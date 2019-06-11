#pragma once

static inline word fetch_and_add(word* variable, word value)
{
    asm volatile("lock; xadd %0, %1"
                     : "+r" (value), "+m" (*variable) // input+output
                     : // No input-only
                     : "memory"
                     );
    return value;
}
