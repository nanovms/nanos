#include <runtime.h>
#include <pci.h>

extern heap interrupt_vectors;
static heap timers;
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
static u64 femtoperiod;
#define TN_ENABLE_CNF (1ull<<0)
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

// 52 bits
#define femto 1000000000000000ull
static int hpet_interrupts[4];

static void timer_config(int timer, time rate, thunk t, boolean periodic)
{
    periodic = 1;

    if (!hpet_interrupts[timer]) {
        u32 a, d;
        hpet_interrupts[timer] = allocate_u64(interrupt_vectors, 1);
        msi_format(&a, &d, hpet_interrupts[timer]);    
        hpet->timers[timer].fsb_routing = ((u64)a << 32) | d;
    }
    u64 c = TN_ENABLE_CNF | TN_FSB_EN_CNF | TN_INT_ENB_CNF | TN_VAL_SET_CNF | (periodic?TN_TYPE_CNF:0);
    hpet->timers[timer].config = c;
    // assume that overwrite is ok
    // we're getting level style behaviour for some reason
    register_interrupt(hpet_interrupts[timer], t);

    // overflow for large periods (> 1s)    
    u64 femtorate = (u64)(((u128)rate * femto) >> 32)/femtoperiod;
    rprintf("hpet: %p %p %p %p\n", rate, femtoperiod, femtorate, hpet->mainCounterRegister);
    // we can close the Floyd gap here by storing the interrupt time
    hpet->timers[timer].comparator = femtorate + hpet->mainCounterRegister;
}

// allocate timers .. right now its at most 1 one-shot and periodic,
// because we dont want to wire up the free
void hpet_timer(time rate, thunk t)
{
    timer_config(0, rate, t, false);
}

void hpet_periodic_timer(time rate, thunk t)
{
    timer_config(1, rate, t, true);
}


time now_hpet()
{
    u64 counter = hpet->mainCounterRegister;
    u64 multiply = femtoperiod*(1ull<<32)/femto;
    u64 ticks = counter*multiply;
    return ticks;
}

boolean init_hpet(heap misc, heap virtual_pagesized, heap pages) {
    u64 hpet_page = allocate_u64(virtual_pagesized, PAGESIZE);
    if (INVALID_ADDRESS == (void*)hpet_page) {
        console("ERROR: Can't allocate page to map HPET registers\n");
        return false;
    }

    map(hpet_page, HPET_TABLE_ADDRESS, PAGESIZE, pages);
    hpet = (struct HPETMemoryMap*)hpet_page;

    // xxx - set to set size to 64?
    femtoperiod = hpet->capabilities.counterClkPeriod;
    // this is like half the field size, we can do a better probe
    if ((femtoperiod > HPET_MAXIMUM_INCREMENT_PERIOD) || !femtoperiod) {
        console("ERROR: Can't initialize HPET\n");
        return false;
    }

    timers = create_id_heap(misc, 0, 4, 1);
    hpet->configuration.enableCnf |= 1;
    u64 prev = hpet->mainCounterRegister;
    if (prev == hpet->mainCounterRegister) 
        halt("Error: No increment HPET main counter\n");

    return true;
}
