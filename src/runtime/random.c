/*-
 * Copyright (c) 2017 The FreeBSD Foundation
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer
 *    in this position and unchanged.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#ifdef KERNEL
#include <kernel.h>
#define chacha20_lock() do { mutex_lock(chacha20inst.m); } while (0)
#define chacha20_unlock() do { mutex_unlock(chacha20inst.m); } while (0)
#else
#include <runtime.h>
#define chacha20_lock()
#define chacha20_unlock()
#endif
#include <crypto/chacha.h>

/*
 * Inspired by FreeBSD arc4random()
 *
 * See: https://svnweb.freebsd.org/base/head/sys/libkern/arc4random.c
 */

#define CHACHA20_RESEED_BYTES   65536
#define CHACHA20_RESEED_SECONDS 300
#define CHACHA20_KEYBYTES       32
#define CHACHA20_BUFFER_SIZE    64

static struct chacha20_s {
#ifdef KERNEL
    mutex m;
#endif
    int numbytes;
    u64 t_reseed;
    u8 m_buffer[CHACHA20_BUFFER_SIZE];
    struct chacha_ctx ctx;
} chacha20inst;

/* entropy source mux - for any rng, not just chacha */
bytes (*preferred_get_seed)(void *seed, bytes len);

static bytes fallback_get_seed(void *seed, bytes len)
{
    bytes n, remain;
    u64 s;
    remain = len;
    while (remain > 0) {
        n = MIN(sizeof(s), remain);
        s = hw_get_seed();
        runtime_memcpy(seed, &s, n);
        seed += n;
        remain -= n;
    }
    return len;
}

/* draw from preferred entropy source or resort to fallback */
void get_seed_complete(void *seed, bytes len)
{
    while (len > 0) {
        bytes s = preferred_get_seed ? preferred_get_seed(seed, len) : 0;
        if (s == 0)
            s = fallback_get_seed(seed, len);
        seed += s;
        assert(len >= s);
        len -= s;
    }
}

/*
 * Mix up the current context.
 */
static void
chacha20_randomstir_locked(struct chacha20_s *chacha20, timestamp t)
{
    u8 key[CHACHA20_KEYBYTES];
    get_seed_complete(key, CHACHA20_KEYBYTES);

    u64 now_sec = sec_from_timestamp(t);
    u64 now_usec = usec_from_timestamp(truncate_seconds(t));

    chacha_keysetup(&chacha20->ctx, key, CHACHA20_KEYBYTES*8);
    chacha_ivsetup(&chacha20->ctx, (u8 *) &now_sec, (u8 *) &now_usec);
    /* Reset for next reseed cycle. */
    chacha20->t_reseed = now_sec + CHACHA20_RESEED_SECONDS;
    chacha20->numbytes = 0;
}

void init_random(heap h)
{
#ifdef KERNEL
    chacha20inst.m = allocate_mutex(h, 2048);
    assert(chacha20inst.m != INVALID_ADDRESS);
#endif
    assert(CHACHA20_KEYBYTES*8 >= CHACHA_MINKEYLEN);
    chacha20_lock();
    chacha20_randomstir_locked(&chacha20inst, now(CLOCK_ID_MONOTONIC_RAW));
    chacha20_unlock();
}

void arc4rand(void *ptr, bytes len)
{
    struct chacha20_s *chacha20 = &chacha20inst;
    bytes length;
    u8 *p;

    chacha20_lock();
    timestamp t = now(CLOCK_ID_MONOTONIC_RAW);
    u64 now_sec = sec_from_timestamp(t);
    if ((chacha20->numbytes > CHACHA20_RESEED_BYTES) || (now_sec > chacha20->t_reseed))
        chacha20_randomstir_locked(chacha20, t);

    p = ptr;
    while (len) {
        length = MIN(CHACHA20_BUFFER_SIZE, len);
        chacha_encrypt_bytes(&chacha20->ctx, chacha20->m_buffer, p, length);
        p += length;
        len -= length;
        chacha20->numbytes += length;
        if (chacha20->numbytes > CHACHA20_RESEED_BYTES) {
            chacha20_randomstir_locked(chacha20, t);
        }
    }
    chacha20_unlock();
}

/* Can generate random numbers before init_random() is called. */
u64 random_early_u64(void)
{
    u8 key[CHACHA20_KEYBYTES];
    get_seed_complete(key, CHACHA20_KEYBYTES);
    u64 retval;
    chacha_keysetup(&chacha20inst.ctx, key, CHACHA20_KEYBYTES * 8);
    chacha_ivsetup(&chacha20inst.ctx, (u8 *)&retval, (u8 *)&retval);
    chacha_encrypt_bytes(&chacha20inst.ctx, chacha20inst.m_buffer, (u8 *)&retval, sizeof(retval));
    return retval;
}

u64 random_u64(void)
{
    u64 retval;
    arc4rand(&retval, sizeof(retval));
    return retval;
}

u64 random_buffer(buffer b)
{
    arc4rand(buffer_ref(b, 0), buffer_length(b));
    return buffer_length(b);
}

/* Do any cleanup necessary after a random_buffer() call has been interrupted by an exception when
 * writing to the supplied buffer. */
void random_buffer_aborted(void)
{
    chacha20_unlock();
}

void random_reseed(void)
{
    chacha20_lock();
    chacha20_randomstir_locked(&chacha20inst, now(CLOCK_ID_MONOTONIC_RAW));
    chacha20_unlock();
}
