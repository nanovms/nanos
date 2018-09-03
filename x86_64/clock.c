#include <runtime.h>

static struct pvclock_vcpu_time_info *vclock = 0;

#define CPUID_LEAF_4 0x40000001

#define MSR_KVM_SYSTEM_TIME 0x4b564d01

struct pvclock_vcpu_time_info {
    u32   version;
    u32   pad0;
    u64   tsc_timestamp;
    u64   system_time;
    u32   tsc_to_system_mul;
    s8    tsc_shift;
    u8    flags;
    u8    pad[2];
} __attribute__((__packed__));


#define MSR_KVM_WALL_CLOCK 0x4b564d00 
struct pvclock_wall_clock {
    u32   version;
    u32   sec;
    u32   nsec;
} __attribute__((__packed__));

typedef __uint128_t u128;

time now()
{
    u64 r = rdtsc();
    u64 nano = 1000000000ull;
    u64 delta = r - vclock->tsc_timestamp;
    if (vclock->tsc_shift < 0) {
        delta >>= -vclock->tsc_shift;
    } else {
        delta <<= vclock->tsc_shift;
    }
    // ok - a 64 bit number (?) multiplied by a 32 bit number yields
    // a 96 bit result, chuck the bottom 32 bits
    u64 nsec =  ((u128)delta * vclock->tsc_to_system_mul) >> 32;
    u64 sec = nsec / nano;
    nsec -= sec * nano;
    time out  = (sec<<32) + time_from_nsec(nsec);
    return out;
}

void init_clock(heap backed_virtual)
{
    // xxx - figure out how to deal with cpu id so we can
    // test for the presence of this feature
    vclock = allocate(backed_virtual, backed_virtual->pagesize);
    zero(vclock,sizeof(struct pvclock_vcpu_time_info));
    // add the enable bit 1
    write_msr(MSR_KVM_SYSTEM_TIME, physical_from_virtual(vclock)| 1);
    if (0 == vclock->system_time)
    {
        halt("FATAL ERROR:system clock is inaccessible\n");
    }
}
