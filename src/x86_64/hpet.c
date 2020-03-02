#include <kernel.h>
#include <pci.h>
#include <page.h>

#define HPET_TABLE_ADDRESS 0xfed00000ull
#define HPET_MAXIMUM_INCREMENT_PERIOD 0x05F5E100ul /* 100ns */

/* Note: hpet registers allow only 32 and 64 bit accesses */
#define HPET_CAPID_COUNTER_CLOCK_PERIOD_SHIFT	32
#define HPET_CAPID_COUNTER_CLOCK_PERIOD_BITS	32
#define HPET_CAPID_VENDOR_ID_SHIFT	16
#define HPET_CAPID_VENDOR_ID_BITS	16
#define HPET_CAPID_LEG_RT_CAP_SHIFT	15
#define HPET_CAPID_LEG_RT_CAP_BITS	1
#define HPET_CAPID_RESERVED_SHIFT	14
#define HPET_CAPID_RESERVED_BITS	1
#define HPET_CAPID_COUNT_SIZE_CAP_SHIFT	13
#define HPET_CAPID_COUNT_SIZE_CAP_BITS	1
#define HPET_CAPID_NUM_TIM_CAP_SHIFT	8
#define HPET_CAPID_NUM_TIM_CAP_BITS	5
#define HPET_CAPID_REV_ID_SHIFT		0
#define HPET_CAPID_REV_ID_BITS		8

#define HPET_CONF_RESERVED_SHIFT		62
#define HPET_CONF_RESERVED_BITS			62
#define HPET_CONF_LEG_RT_CNF_SHIFT		1
#define HPET_CONF_LEG_RT_CNF_BITS		1
#define HPET_CONF_ENABLE_CNF_SHIFT		0
#define HPET_CONF_ENABLE_CNF_BITS		1

#define HPET_ISR_RESERVED_SHIFT			32
#define HPET_ISR_RESERVED_BITS			32
#define HPET_ISR_TN_INT_STS_SHIFT		0
#define HPET_ISR_TN_INT_STS_BITS		32

#define HPET_TIMER_CONFIG_INT_ROUTE_CAP_SHIFT	32
#define HPET_TIMER_CONFIG_INT_ROUTE_CAP_BITS	32
#define HPET_TIMER_CONFIG_RESERVED_SHIFT	16
#define HPET_TIMER_CONFIG_RESERVED_BITS		16
#define HPET_TIMER_CONFIG_FSB_INT_DEL_CAP_SHIFT	15
#define HPET_TIMER_CONFIG_FSB_INT_DEL_CAP_BITS	1
#define HPET_TIMER_CONFIG_FSB_EN_CNF_SHIFT	14
#define HPET_TIMER_CONFIG_FSB_EN_CNF_BITS	1
#define HPET_TIMER_CONFIG_INT_ROUTE_CNF_SHIFT	9
#define HPET_TIMER_CONFIG_INT_ROUTE_CNF_BITS	5
#define HPET_TIMER_CONFIG_32MODE_CNF_SHIFT	8
#define HPET_TIMER_CONFIG_32MODE_CNF_BITS	1
#define HPET_TIMER_CONFIG_RESERVED2_SHIFT	7
#define HPET_TIMER_CONFIG_RESERVED2_BITS	1
#define HPET_TIMER_CONFIG_VAL_SET_CNF_SHIFT	6
#define HPET_TIMER_CONFIG_VAL_SET_CNF_BITS	1
#define HPET_TIMER_CONFIG_SIZE_CAP_SHIFT	5
#define HPET_TIMER_CONFIG_SIZE_CAP_BITS		1
#define HPET_TIMER_CONFIG_PER_INT_CAP_SHIFT	4
#define HPET_TIMER_CONFIG_PER_INT_CAP_BITS	1
#define HPET_TIMER_CONFIG_TYPE_CNF_SHIFT	3
#define HPET_TIMER_CONFIG_TYPE_CNF_BITS		1
#define HPET_TIMER_CONFIG_INT_ENB_CNF_SHIFT	2
#define HPET_TIMER_CONFIG_INT_ENB_CNF_BITS	1
#define HPET_TIMER_CONFIG_INT_TYPE_CNF_SHIFT	1
#define HPET_TIMER_CONFIG_INT_TYPE_CNF_BITS	1
#define HPET_TIMER_CONFIG_RESERVED3_SHIFT	0
#define HPET_TIMER_CONFIG_RESERVED3_BITS	1

#define HPET_TIMER_COMPARATOR_ADDR_SHIFT	0
#define HPET_TIMER_COMPARATOR_ADDR_BITS		32

#define HPET_TIMER_FSB_INT_ADDR_SHIFT		32
#define HPET_TIMER_FSB_INT_ADDR_BITS		32
#define HPET_TIMER_FSB_INT_VAL_SHIFT		0
#define HPET_TIMER_FSB_INT_VAL_BITS		32

#define TCONF(f) U64_FROM_BIT(HPET_TIMER_CONFIG_ ## f ## _SHIFT)

struct HPETTimer {
    u64 config;
    u64 comparator;
    u64 fsb_int;
    u64 reserved;
}  __attribute__((__packed__));

struct HPETMemoryMap {
    u64 capid;
    u64 reserved1;
    u64 conf;
    u64 reserved2;
    u64 isr;
    u64 reserved3[25];
    u64 mainCounterRegister;
    u64 reserved4;
    struct HPETTimer timers[32];
} __attribute__((__packed__));

static volatile struct HPETMemoryMap* hpet;
static timestamp hpet_period_scaled_32;
static int hpet_interrupts[4];

static u64 hpet_config_get() __attribute__((noinline));

static u64 hpet_config_get()
{
    return hpet->conf;
}

static void hpet_config_set(u64 conf)
{
    hpet->conf = conf;
}

static u64 hpet_main_counter() __attribute__((noinline));

static u64 hpet_main_counter()
{
    return hpet->mainCounterRegister;
}

static void timer_config(int timer, timestamp rate, thunk t, boolean periodic)
{
    if (!hpet_interrupts[timer]) {
        u32 a, d;
        hpet_interrupts[timer] = allocate_interrupt();
        msi_format(&a, &d, hpet_interrupts[timer]);
        hpet->timers[timer].fsb_int = ((u64)a << 32) | d;
        register_interrupt(hpet_interrupts[timer], t, "hpet timer");
    }

    u64 c = TCONF(FSB_EN_CNF) | TCONF(32MODE_CNF) | TCONF(INT_ENB_CNF);
    if (periodic) {
        if ((hpet->timers[timer].config & TCONF(PER_INT_CAP)) == 0) {
	    console("HPET timer not capable of periodic interrupts.\n");
	    return;
	}
	c |= TCONF(VAL_SET_CNF) | TCONF(TYPE_CNF);
    }
    hpet->timers[timer].config = c;

    /* We don't have __udivti3, so there's some loss of precision with
       seconds, otherwise use:

       u64 hprate_high = (((u128)(rate & ~MASK(32))) << 32) / hpet_period_scaled_32;
    */
    u64 hprate_high = (rate & ~MASK(32)) / (hpet_period_scaled_32 >> 32);
    u64 hprate_low = (rate << 32) / hpet_period_scaled_32;
    u64 comparator = hprate_high + hprate_low + hpet_main_counter();
    // we can close the Floyd gap here by storing the interrupt time
    hpet->timers[timer].comparator = comparator;
}

closure_function(0, 1, void, hpet_runloop_timer,
                 timestamp, duration)
{
    timer_config(0, duration, ignore, false);
}

closure_function(0, 0, timestamp, hpet_now)
{
    return (((u128)hpet_main_counter()) * hpet_period_scaled_32) >> 32;
}

boolean init_hpet(kernel_heaps kh) {
    void *hpet_page = allocate((heap)heap_virtual_page(kh), PAGESIZE);
    if (hpet_page == INVALID_ADDRESS) {
        msg_err("failed to allocate page for HPET\n");
        return false;
    }

    map(u64_from_pointer(hpet_page), HPET_TABLE_ADDRESS, PAGESIZE, PAGE_DEV_FLAGS, heap_pages(kh));
    hpet = (struct HPETMemoryMap*)hpet_page;

    u64 femtoperiod = field_from_u64(hpet->capid, HPET_CAPID_COUNTER_CLOCK_PERIOD);
    if ((femtoperiod > HPET_MAXIMUM_INCREMENT_PERIOD) || !femtoperiod) {
        msg_err("failed to initialize HPET; invalid femtoperiod\n");
        return false;
    }

    /* femtoperiod < 2^32 by definition */
    hpet_period_scaled_32 = femtoseconds(femtoperiod << 32);
    hpet_config_set(hpet_config_get() | U64_FROM_BIT(HPET_CONF_ENABLE_CNF_SHIFT));
    u64 prev = hpet_main_counter();
    for (int i = 0; i < 10; i ++) {
        if (prev == hpet_main_counter())
            continue;
        register_platform_clock_now(closure(heap_general(kh), hpet_now), VDSO_CLOCK_HPET);
        register_platform_clock_timer(closure(heap_general(kh), hpet_runloop_timer), 0 /* no per-cpu init */);
        return true;
    }
    msg_err("failed to initialize HPET; main counter not incrementing\n");
    return false;
}
