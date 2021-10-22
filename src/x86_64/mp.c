//#define MP_DEBUG

#include <kernel.h>
#include <apic.h>

static void *apboot = INVALID_ADDRESS;
extern u8 apinit, apinit_end;
extern void *ap_pagetable, *ap_idt_pointer, *ap_stack;
void *ap_stack;
u64 ap_lock;
heap ap_heap;

#define ICR_TYPE_INIT         0x00000500
#define ICR_TYPE_STARTUP      0x00000600

static void (*start_callback)();

#ifdef MP_DEBUG
#define mp_debug(x) rputs(x)
#define mp_debug_u64(x) print_u64(x)
#else
#define mp_debug(x)
#define mp_debug_u64(x)
#endif

#define CPUID_XSAVE (1<<26)
#define CPUID_AVX (1<<28)

#define XCR0_SSE (1<<1)
#define XCR0_AVX (1<<2)
u8 use_xsave;
u64 extended_frame_size = 512;

void init_cpu_features()
{
    u64 cr;
    u32 v[4];

    cpuid(1, 0, v);
    if (v[2] & CPUID_XSAVE)
        use_xsave = 1;
    mov_from_cr("cr4", cr);
    cr |= CR4_PGE | CR4_OSFXSR | CR4_OSXMMEXCPT;
    if (use_xsave)
        cr |= CR4_OSXSAVE;
    mov_to_cr("cr4", cr);
    mov_from_cr("cr0", cr);
    cr |= C0_MP | C0_WP;
    cr &= ~C0_EM;
    mov_to_cr("cr0", cr);
    if (use_xsave) {
        xgetbv(0, &v[0], &v[1]);
        v[0] |= XCR0_SSE;
        if (v[2] & CPUID_AVX)
            v[0] |= XCR0_AVX;
        xsetbv(0, v[0], v[1]);
        cpuid(0xd, 0, v);
        extended_frame_size = v[1];
    }
}

void cpu_init(int cpu)
{
    u64 addr = u64_from_pointer(cpuinfo_from_id(cpu));
    write_msr(KERNEL_GS_MSR, 0); /* clear user GS */
    write_msr(GS_MSR, addr);
    if (VVAR_REF(vdso_dat).platform_has_rdtscp)
        write_msr(TSC_AUX_MSR, cpu);    /* used by vdso_getcpu() */
    init_syscall_handler();
}

static void __attribute__((noinline)) ap_new_stack()
{
    mp_debug("ap_new_stack for cpu ");

    u64 id = apic_id();
    mp_debug_u64(id);
    int cid = cpuid_from_apicid(id);
    fetch_and_add(&total_processors, 1);
    cpu_init(cid);
    cpuinfo ci = current_cpu();

    set_running_frame(ci, frame_from_kernel_context(get_kernel_context(ci)));
    mp_debug(", enable apic");
    apic_enable();
    mp_debug(", clear ap lock, enable ints, start_callback\n");
    memory_barrier();
    ap_lock = 0;
    start_callback();
}

void ap_start()
{
    apic_per_cpu_init();
    init_cpu_features();
    int id = cpuid_from_apicid(apic_id());
    cpuinfo ci = init_cpuinfo(ap_heap, id);
    if (ci == INVALID_ADDRESS)
        return;
    switch_stack(stack_from_kernel_context(get_kernel_context(ci)), ap_new_stack);
}

void allocate_apboot(heap stackheap, void (*ap_entry)())
{
    start_callback = ap_entry;
    apboot = pointer_from_u64(AP_BOOT_START);
    map((u64)apboot, (u64)apboot, PAGESIZE,
        pageflags_writable(pageflags_exec(pageflags_memory())));

    set_page_write_protect(false);
    asm("sidt %0": "=m"(ap_idt_pointer));
    mov_from_cr("cr3", ap_pagetable);
    set_page_write_protect(true);
    // just one function call

    void *rsp = allocate_stack(stackheap, 4 * PAGESIZE);
    ap_stack = rsp;

    runtime_memcpy(apboot, &apinit, &apinit_end - &apinit);
    ap_heap = stackheap;
}

void deallocate_apboot(heap stackheap)
{
    deallocate_stack(stackheap, 4 * PAGESIZE, ap_stack);
    unmap((u64)apboot, PAGESIZE);
}

#define AP_START_TIMEOUT_MS 200
void start_cpu(int index) {
    u8 vector = (((u64)apboot) >> 12) & 0xff;

    int nproc = total_processors;
    apic_ipi(index, ICR_TYPE_INIT | ICR_ASSERT, 0);
    kernel_delay(milliseconds(10));
    apic_ipi(index, ICR_TYPE_STARTUP | ICR_ASSERT, vector);
    kernel_delay(microseconds(200));
    apic_ipi(index, ICR_TYPE_STARTUP | ICR_ASSERT, vector);
    for (u64 to = 0; total_processors != nproc + 1 && to < AP_START_TIMEOUT_MS; to++)
        kernel_delay(milliseconds(1));
}
