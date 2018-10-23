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

time now_hpet() {
  u64 counter = hpet_counter();
  /*
INFO:
      We haven't 128 bit arithmetic. We can't divide 128 bit number.
      The default type  CLK_PERIOD is femtoseconds but we need nanoseconds.
      There is potential problem if hpet multiplier less than 1000000 ul.
      But qemu set it value to 10 000 000. Another problem  may there is rounding.
      the prefer code will be (u64)((u128)counter*hpet_multiplier())/1000000ul;
  */
  u32 multiply = hpet_multiplier()/1000000ul;
  u64 nsec = (u64)((u128)counter*multiply);
  return nsec;
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
    vclock = allocate(backed, backed->pagesize);
    zero(vclock,sizeof(struct pvclock_vcpu_time_info));
    // add the enable bit 1
    write_msr(MSR_KVM_SYSTEM_TIME, physical_from_virtual(vclock)| 1);
    if (0 == vclock->system_time)
    {
        deallocate(backed, vclock, backed->pagesize);
        console("INFO: KVM clock is inaccessible\n");
        if( !init_hpet(heap_virtual_page(kh), heap_pages(kh))) {
          halt("ERROR: HPET clock is inaccessible\n");
        }
        clock_function = now_hpet;
    }
    rtc_offset = rtc_gettimeofday() << 32;
}
