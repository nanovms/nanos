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

struct pvclock_wall_clock {
    u32   version;
    u32   sec;
    u32   nsec;
} __attribute__((__packed__));

u64 pvclock_now_ns(void);
boolean init_tsc_deadline_timer(clock_timer *ct, thunk *per_cpu_init);
void init_pvclock(heap h, struct pvclock_vcpu_time_info *pvclock);
physical pvclock_get_physaddr(void);
