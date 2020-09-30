#include <runtime.h>

/* Copy by advancing memory addresses in forward direction. */
static inline void memcpyf_8(void *dst, const void *src, bytes len)
{
    for (bytes i = 0; i < len; i++) {
        ((u8 *)dst)[i] = ((u8 *)src)[i];
    }
}

/* Copy by advancing memory addresses in backward direction. */
static inline void memcpyb_8(void *dst, const void *src, bytes len)
{
    for (bytes i = len - 1; i < len; i--) {
        ((u8 *)dst)[i] = ((u8 *)src)[i];
    }
}

static inline void memset_8(void *a, u8 b, bytes len)
{
    for (int i = 0; i < len; i++) {
        ((u8 *)a)[i] = b;
    }
}

static inline int memcmp_8(const void *a, const void *b, bytes len)
{
    int res;

    for (int i = 0; i < len; i++) {
        res = ((u8 *)a)[i] - ((u8 *)b)[i];
        if (res != 0) {
            return res;
        }
    }
    return 0;
}

void runtime_memcpy(void *a, const void *b, bytes len)
{
    unsigned int src_cnt, dest_cnt;
    bytes long_len, end_len;
    uintptr_t *p_long_src;
    uintptr_t *p_long_dest;
    uintptr_t long_word1;
    uintptr_t long_word2;

    if ((uintptr_t)a < (uintptr_t)b) {
        if (len < sizeof(uintptr_t)) {
            memcpyf_8(a, b, len);
            return;
        }
        src_cnt = sizeof(uintptr_t) - ((uintptr_t)b & (sizeof(uintptr_t) - 1));
        if (src_cnt == sizeof(uintptr_t)) {
            src_cnt = 0;
        }
        dest_cnt = sizeof(uintptr_t) - ((uintptr_t)a & (sizeof(uintptr_t) - 1));
        if (dest_cnt == sizeof(uintptr_t)) {
            dest_cnt = 0;
        }
        else {
            memcpyf_8(a, b, dest_cnt);
        }
        long_len = (len - dest_cnt) / sizeof(uintptr_t);
        end_len = (len - dest_cnt) & (sizeof(uintptr_t) - 1);
        p_long_src = (uintptr_t *)((u8 *)b + src_cnt);
        if (src_cnt > dest_cnt) {
            p_long_src--;
        }
        p_long_dest = (uintptr_t *)((u8 *)a + dest_cnt);
        if (src_cnt == dest_cnt) {
            while (long_len-- > 0) {
                *p_long_dest++ = *p_long_src++;
            }
        }
        else {
            unsigned int alignment = (src_cnt - dest_cnt) & (sizeof(uintptr_t) - 1);
            long_word1 = *p_long_src++;
            while (long_len-- > 0) {
                long_word2 = *p_long_src++;
                *p_long_dest++ =
                        (long_word1 >> (8 * (sizeof(uintptr_t) - alignment))) |
                        (long_word2 << (8 * alignment));
                long_word1 = long_word2;
            }
        }
        memcpyf_8(p_long_dest, b + len - end_len, end_len);
    }
    else {
        if (len < sizeof(uintptr_t)) {
            memcpyb_8(a, b, len);
            return;
        }
        src_cnt = (uintptr_t)((u8 *)b + len) & (sizeof(uintptr_t) - 1);
        dest_cnt = (uintptr_t)((u8 *)a + len) & (sizeof(uintptr_t) - 1);
        p_long_src = (uintptr_t *)((u8 *)b + len - dest_cnt);
        p_long_dest = (uintptr_t *)((u8 *)a + len - dest_cnt);
        memcpyb_8(p_long_dest, p_long_src, dest_cnt);
        p_long_src = (uintptr_t *)((u8 *)b + len - src_cnt);
        len -= dest_cnt;
        long_len = len / sizeof(uintptr_t);
        end_len = len & (sizeof(uintptr_t) - 1);
        if (src_cnt <= dest_cnt) {
            p_long_src--;
        }
        p_long_dest--;
        if (src_cnt == dest_cnt) {
            while (long_len-- > 0) {
                *p_long_dest-- = *p_long_src--;
            }
        }
        else {
            unsigned int alignment = (src_cnt - dest_cnt) & (sizeof(uintptr_t) - 1);
            long_word1 = *p_long_src--;
            while (long_len-- > 0) {
                long_word2 = *p_long_src--;
                *p_long_dest-- =
                        (long_word1 << (8 * (sizeof(uintptr_t) - alignment))) |
                        (long_word2 >> (8 * alignment));
                long_word1 = long_word2;
            }
        }
        memcpyb_8(a, b, end_len);
    }
}

void runtime_memset(u8 *a, u8 b, bytes len)
{
    if (len < sizeof(uintptr_t)) {
        memset_8(a, b, len);
        return;
    }
    unsigned int cnt = sizeof(uintptr_t) - ((uintptr_t)a & (sizeof(uintptr_t) - 1));
    if (cnt == sizeof(uintptr_t)) {
        cnt = 0;
    }
    else {
        memset_8(a, b, cnt);
        len -= cnt;
    }
    uintptr_t *dest = (uintptr_t *)((u8 *)a + cnt);
    uintptr_t word = 0;
    for (int i = 0; i < sizeof(word); i++) {
        word = (word << 8) | b;
    }
    bytes long_len = len / sizeof(uintptr_t);
    bytes end_len = len & (sizeof(uintptr_t) - 1);
    while (long_len-- > 0) {
        *dest++ = word;
    }
    memset_8(dest, b, end_len);
}

int runtime_memcmp(const void *a, const void *b, bytes len)
{
    uintptr_t res;

    if (len < sizeof(uintptr_t)) {
        return memcmp_8(a, b, len);
    }
    unsigned int a_cnt = sizeof(uintptr_t) - ((uintptr_t)a & (sizeof(uintptr_t) - 1));
    if (a_cnt == sizeof(uintptr_t)) {
        a_cnt = 0;
    }
    unsigned int b_cnt = sizeof(uintptr_t) - ((uintptr_t)b & (sizeof(uintptr_t) - 1));
    if (b_cnt == sizeof(uintptr_t)) {
        b_cnt = 0;
    }
    else {
        res = memcmp_8(a, b, b_cnt);
        if (res) {
            return res;
        }
    }
    bytes long_len = (len - b_cnt) / sizeof(uintptr_t);
    bytes end_len = (len - b_cnt) & (sizeof(uintptr_t) - 1);
    uintptr_t *p_long_a = (uintptr_t *)((u8 *)a + a_cnt);
    if (a_cnt > b_cnt) {
        p_long_a--;
    }
    uintptr_t *p_long_b = (uintptr_t *)((u8 *)b + b_cnt);
    if (a_cnt == b_cnt) {
        while (long_len-- > 0) {
            res = *p_long_a++ - *p_long_b++;
            if (res) {
                return 1;
            }
        }
    }
    else {
        unsigned int alignment = (a_cnt - b_cnt) & (sizeof(uintptr_t) - 1);
        uintptr_t long_word1, long_word2;
        long_word1 = *p_long_a++;
        while (long_len-- > 0) {
            long_word2 = *p_long_a++;
            res = ((long_word1 >> (8 * (sizeof(uintptr_t) - alignment))) |
                    (long_word2 << (8 * alignment))) - *p_long_b++;
            if (res) {
                return 1;
            }
            long_word1 = long_word2;
        }
    }
    return memcmp_8(a + len - end_len, p_long_b, end_len);
}
