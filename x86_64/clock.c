#include <runtime.h>
#include "hpet.h"
#include "rtc.h"

static struct pvclock_vcpu_time_info *vclock = 0;

static time rtc_offset;

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
typedef time (*clock_now)(void);

extern time now_hpet();

time now_kvm()
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
    u64 nsec =  ((u128)delta * vclock->tsc_to_system_mul) >> 32;
    u64 sec = nsec / nano;
    nsec -= sec * nano;
    time out  = (sec<<32) + time_from_nsec(nsec);
    return out;
}

static clock_now clock_function = now_kvm;

time now() {
  return rtc_offset + clock_function();
}

void init_clock(kernel_heaps kh)
{
    heap backed = heap_backed(kh);
    // xxx - figure out how to deal with cpu id so we can
    // test for the presence of this feature
    // this is just used for rdtsc scaling, as both kvm and non-kvm are assumed
    // to have hpet support
    vclock = allocate(backed, backed->pagesize);
    zero(vclock,sizeof(struct pvclock_vcpu_time_info));
    // add the enable bit 1
    write_msr(MSR_KVM_SYSTEM_TIME, physical_from_virtual(vclock) | 1);

    if(init_hpet(heap_general(kh), heap_virtual_page(kh), heap_pages(kh))) {
	console("Using HPET clock source.\n");
	clock_function = now_hpet;
    } else {
	if (vclock->system_time) {
	    console("Couldn't initialize HPET; defaulting to KVM clock source.\n");
	    clock_function = now_kvm;
	} else {
	    halt("ERROR: No clock source available.\n");
	}
    }

    rtc_offset = rtc_gettimeofday() << 32;
}
