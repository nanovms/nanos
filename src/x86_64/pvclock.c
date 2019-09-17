#include <runtime.h>
#include <x86_64.h>
#include <pvclock.h>

static CLOSURE_1_0(pvclock_now, timestamp, volatile struct pvclock_vcpu_time_info *);
static timestamp pvclock_now(volatile struct pvclock_vcpu_time_info *vclock)
{
    u64 r = rdtsc();
    u64 delta = r - vclock->tsc_timestamp;
    if (vclock->tsc_shift < 0) {
        delta >>= -vclock->tsc_shift;
    } else {
        delta <<= vclock->tsc_shift;
    }
    // ok - a 64 bit number (?) multiplied by a 32 bit number yields
    // a 96 bit result, chuck the bottom 32 bits
    u64 nsec = vclock->system_time +
            (((u128)delta * vclock->tsc_to_system_mul) >> 32);
    u64 sec = nsec / BILLION;
    nsec -= sec * BILLION;
    timestamp out = seconds(sec) + nanoseconds(nsec);
    return out;
}

void init_pvclock(heap h, struct pvclock_vcpu_time_info *pvclock)
{
    assert(pvclock);
    register_platform_clock_now(closure(h, pvclock_now, pvclock));
}
