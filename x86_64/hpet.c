#include <runtime.h>
#include "hpet.h"
#include "x86_64.h"

#define HPET_TABLE_ADDRESS 0xfed00000ull
#define HPET_MAXIMUM_INCREMENT_PERIOD 0x05F5E100ul

struct HPETGCapabilitiesIDRegister {
    u16 revID : 8;
    u16 numTimCap : 5;
    u16 countSizeCap : 1;
    u16 reserved : 1;
    u16 legRouteCap : 1;
    u16 vendorID;
    u32 counterClkPeriod;
} __attribute__((__packed__));

struct HPETGConfigurationRegister {
    u16 enableCnf : 1;
    u16 legRtCnf : 1;
    u16 reserved6 : 6;
    u16 reservedForNonOS : 8;
    u16 reserved16;
    u32 reserved32;
} __attribute__((__packed__));

struct HPETInterruptStatusRegister {
    u32 T0IntSts : 1;
    u32 T1IntSts : 1;
    u32 TIntSts : 1;
    u32 TnIntSts : 29;
    u32 reserved32;
} __attribute__((__packed__));

union HPETMainCounterRegister {
    struct _bit32 {
        volatile u32 lo;
        volatile u32 hi;
    } __attribute__((__packed__)) counters32bit;
    volatile u64 couter64bit;
} __attribute__((__packed__));

struct HPETMemoryMap {
    volatile struct HPETGCapabilitiesIDRegister capabilities;
    u64 reserved1;
    volatile struct HPETGConfigurationRegister configuration;
    u64 reserved2;
    volatile struct HPETInterruptStatusRegister interruptStatus;
    char reserved3[200];
    volatile union HPETMainCounterRegister mainCounterRegister;
    u64 reserved4;
} __attribute__((__packed__));

static struct HPETMemoryMap* hpet = 0;

boolean init_hpet(heap backed_virtual) {
    // Is it correct?
    map((u64)hpet, HPET_TABLE_ADDRESS, backed_virtual->pagesize, backed_virtual);

    if (HPET_MAXIMUM_INCREMENT_PERIOD < hpet->capabilities.counterClkPeriod || !hpet->capabilities.counterClkPeriod) {
        console("ERROR: Can't initialize HPET\n");
        return false;
    }

    hpet->configuration.enableCnf |= 1;
    u64 prev = hpet->mainCounterRegister.couter64bit;
    console("HPET counter started\n");

    if (prev == hpet->mainCounterRegister.couter64bit) {
        console("Error: No increment HPET main counter\n");
        return false;
    }
    return true;
}

u32 hpet_multiplier(void) {
    return hpet->capabilities.counterClkPeriod;
}

u64 hpet_counter(void) {
    return hpet->mainCounterRegister.couter64bit;
}
