/* Various now() callbacks that can be accessed from both the kernel and from
 * the userspace vdso
 *
 * Currently we only support callbacks for pvclock, but others could be
 * implemented by following the general model used here for pvclock
 *
 * NOTE: All functions that can be accessed from the VDSO must be prepended
 * with VDSO or marked static
 */

#include <kernel.h>
#include <pvclock.h>
#include <page.h>

#ifndef BUILD_VDSO
VVAR_DEF(struct vdso_dat_struct, vdso_dat) = {
    .platform_has_rdtscp = 0,
    .rtc_offset = 0,
    .pvclock_offset = 0,
    .clock_src = VDSO_CLOCK_SYSCALL
};
#endif

#define __vdso_dat (&(VVAR_REF(vdso_dat)))
extern VVAR void * pvclock_page;
#define __vdso_pvclock ((volatile struct pvclock_vcpu_time_info *)(((unsigned long)&pvclock_page) \
                                                                   + __vdso_dat->pvclock_offset))

VDSO u64
vdso_pvclock_now_ns(volatile struct pvclock_vcpu_time_info * vclock)
{
    u32 version;
    u64 result;

    do {
        /* mask update-in-progress so we don't match */
        version = vclock->version & ~1;
        read_barrier();
        u64 delta = rdtsc() - vclock->tsc_timestamp;
        if (vclock->tsc_shift < 0) {
            delta >>= -vclock->tsc_shift;
        } else {
            delta <<= vclock->tsc_shift;
        }
        /* when moving to SMP: if monotonicity flag is unset, we will
           have to check for last reading and insure that time doesn't
           regress */
        result = vclock->system_time +
            (((u128)delta * vclock->tsc_to_system_mul) >> 32);
        read_barrier();
    } while (version != vclock->version);
    return result;
}

static inline timestamp
vdso_now_pvclock(void)
{
    return nanoseconds(vdso_pvclock_now_ns(__vdso_pvclock));
}

static inline timestamp
vdso_now_none(void)
{
    return VDSO_NO_NOW;
}

typedef timestamp (*vdso_now_fn)(void);

static inline vdso_now_fn
vdso_get_now_fn(vdso_clock_id id)
{
    switch (id) {
    case VDSO_CLOCK_PVCLOCK:
        return vdso_now_pvclock;
    default:
        return vdso_now_none;
    }
}

/* don't want to mess with closures in the VDSO ... */
VDSO timestamp
vdso_now(clock_id id)
{
    timestamp _now = VDSO_NO_NOW, _off = 0;

    switch (id) {
    case CLOCK_ID_MONOTONIC:
    case CLOCK_ID_MONOTONIC_RAW:
    case CLOCK_ID_MONOTONIC_COARSE:
    case CLOCK_ID_BOOTTIME:
        _now = vdso_get_now_fn(__vdso_dat->clock_src)();
        break;

    case CLOCK_ID_REALTIME:
    case CLOCK_ID_REALTIME_COARSE:
        _now = vdso_get_now_fn(__vdso_dat->clock_src)();
        _off = __vdso_dat->rtc_offset;
        break;

    default:
        break;
    }

    if (_now == VDSO_NO_NOW)
        return VDSO_NO_NOW;

    return _now + _off;
}
