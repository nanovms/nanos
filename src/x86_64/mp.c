//#define MP_DEBUG

#include <kernel.h>
#include <apic.h>

static void *apboot = INVALID_ADDRESS;
extern u8 apinit, apinit_end;
extern void *ap_pagetable, *ap_idt_pointer, *ap_stack;
void *ap_stack;
u64 ap_lock;

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

void cpu_init(int cpu)
{
    u64 cr;
    mov_from_cr("cr4", cr);
    cr |= CR4_PGE | CR4_OSFXSR | CR4_OSXMMEXCPT;
    mov_to_cr("cr4", cr);
    mov_from_cr("cr0", cr);
    cr |= C0_MP | C0_WP;
    cr &= ~C0_EM;
    mov_to_cr("cr0", cr);
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

    set_ist(id, IST_EXCEPTION, u64_from_pointer(ci->m.exception_stack));
    set_ist(id, IST_INTERRUPT, u64_from_pointer(ci->m.int_stack));
    set_running_frame(ci, frame_from_kernel_context(get_kernel_context(ci)));
    mp_debug(", install gdt");
    install_gdt64_and_tss(id);
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
    int id = cpuid_from_apicid(apic_id());
    switch_stack(stack_from_kernel_context(get_kernel_context(cpuinfo_from_id(id))), ap_new_stack);
}

void allocate_apboot(heap stackheap, void (*ap_entry)())
{
    start_callback = ap_entry;
    apboot = pointer_from_u64(AP_BOOT_START);
    map((u64)apboot, (u64)apboot, PAGESIZE,
        pageflags_writable(pageflags_exec(pageflags_memory())));

    asm("sidt %0": "=m"(ap_idt_pointer));
    mov_from_cr("cr3", ap_pagetable);
    // just one function call

    void *rsp = allocate_stack(stackheap, 4 * PAGESIZE);
    ap_stack = rsp;

    runtime_memcpy(apboot, &apinit, &apinit_end - &apinit);
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
    apic_ipi(index, ICR_TYPE_INIT, 0);
    kernel_delay(milliseconds(10));
    apic_ipi(index, ICR_TYPE_STARTUP, vector);
    kernel_delay(microseconds(200));
    apic_ipi(index, ICR_TYPE_STARTUP, vector);
    for (u64 to = 0; total_processors != nproc + 1 && to < AP_START_TIMEOUT_MS; to++)
        kernel_delay(milliseconds(1));
}
