#include <runtime.h>
#include <x86_64.h>
#include <pvclock.h>

static volatile struct pvclock_vcpu_time_info *vclock;

u64 pvclock_now_ns(void)
{
    u32 version;
    u64 result;

    do {
        version = vclock->version & ~1; // XXX why mask?
        read_barrier();
        u64 delta = rdtsc() - vclock->tsc_timestamp;
        if (vclock->tsc_shift < 0) {
            delta >>= -vclock->tsc_shift;
        } else {
            delta <<= vclock->tsc_shift;
        }
        result = vclock->system_time +
            (((u128)delta * vclock->tsc_to_system_mul) >> 32);
        read_barrier();
    } while (version != vclock->version);
    return result;
}

CLOSURE_0_0(pvclock_now, timestamp);
timestamp pvclock_now(void)
{
    return nanoseconds(pvclock_now_ns());
}

void init_pvclock(heap h, struct pvclock_vcpu_time_info *vti)
{
    assert(vti);
    vclock = vti;
    register_platform_clock_now(closure(h, pvclock_now));
}
