#include <runtime.h>
#include <hpet.h>
#include <x86_64.h>
#include <pci.h>

extern heap interrupt_vectors;

#define HPET_TABLE_ADDRESS 0xfed00000ull
#define HPET_MAXIMUM_INCREMENT_PERIOD 0x05F5E100ul

struct HPETGCapabilitiesIDRegister {
    u16 revID : 8;
    u16 numTimCap : 5;
    u16 countSizeCap : 1;
    u16 reserved : 1;
    u16 legRouteCap : 1;
    volatile  u16 vendorID;
    volatile  u32 counterClkPeriod;
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

struct HPETTimer {
    u64 config;
    u64 comparator;
    u64 fsb_routing;
    u64 reserved;        
}  __attribute__((__packed__));
    

struct HPETMemoryMap {
    volatile struct HPETGCapabilitiesIDRegister capabilities;
    u64 reserved1;
    volatile struct HPETGConfigurationRegister configuration;
    u64 reserved2;
    volatile struct HPETInterruptStatusRegister interruptStatus;
    char reserved3[200]; 
    u64 mainCounterRegister;
    u64 reserved4;
    volatile struct HPETTimer timers[32];
} __attribute__((__packed__));

static volatile struct HPETMemoryMap* hpet;

#define TN_INT_TYPE_CNF (1ull<<1)
#define TN_INT_ENB_CNF (1ull<<2)
#define TN_TYPE_CNF (1ull<<3)
#define TN_PER_INT_CAP (1ull<<4)
#define TN_SIZE_CAP (1ull<<5)
#define TN_VAL_SET_CNF (1ull<<6)
#define TN_32MODE_CNF (1ull<<8)
#define TN_INT_ROUTE_CNF (1ull<<9)
#define TN_FSB_EN_CNF (1ull<<14)
#define TN_FSB_INT_DEL_CAP (1ull<<15)
#define TN_INT_ROUTE_CAP (1ull<<32)

static void hpet_timer()
{
}

// make one-shot
void configure_hpet_timer(int timer, time rate, thunk t)
{
    u32 a, d;

    hpet->timers[timer].config = TN_FSB_EN_CNF | TN_INT_ENB_CNF | TN_VAL_SET_CNF;
    int v =allocate_u64(interrupt_vectors, 1);
    msi_format(&a, &d, v);
    
    register_interrupt(v, t);
    hpet->timers[timer].fsb_routing = ((u64)a << 32) | d;
    // normalize!
    hpet->timers[timer].comparator = 100;
}

boolean init_hpet(heap virtual_pagesized, heap pages) {
    u64 hpet_page = allocate_u64(virtual_pagesized, PAGESIZE);
    if (INVALID_ADDRESS == (void*)hpet_page) {
        console("ERROR: Can't allocate page to map HPET registers\n");
        return false;
    }

    map(hpet_page, HPET_TABLE_ADDRESS, PAGESIZE, pages);
    hpet = (struct HPETMemoryMap*)hpet_page;

    if (HPET_MAXIMUM_INCREMENT_PERIOD < hpet->capabilities.counterClkPeriod || !hpet->capabilities.counterClkPeriod) {
        console("ERROR: Can't initialize HPET\n");
        return false;
    }

    hpet->configuration.enableCnf |= 1;
    u64 prev = hpet->mainCounterRegister;

    if (prev == hpet->mainCounterRegister) {
        console("Error: No increment HPET main counter\n");
        return false;
    }
    return true;
}

u32 hpet_multiplier(void) {
    return hpet->capabilities.counterClkPeriod;
}

u64 hpet_counter(void) {
    return hpet->mainCounterRegister;
}
