#include <sruntime.h>

static struct pvclock_vcpu_time_info *vclock;

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


time now()
{
    
}

void init_clock(heap backed_virtual)
{
    vclock = allocate(backed_virtual, backed_virtual->pagesize);
    write_msr(MSR_KVM_SYSTEM_TIME, physical_from_virtual(vclock));
    rprintf("time: %x %x %x\n", vclock->system_time, vclock->tsc_timestamp, rdtsc());
}
