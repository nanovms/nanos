//#define MP_DEBUG

#include <runtime.h>
#include <x86_64.h>
#include <apic.h>
#include <page.h>

static void *apboot = INVALID_ADDRESS;
extern u8 apinit, apinit_end;
extern void *ap_pagetable, *ap_start_vector, *ap_gdt_pointer, *ap_idt_pointer, *ap_stack;
extern u64 ap_lock;

#define ICR_TYPE_INIT         0x00000500
#define ICR_TYPE_STARTUP      0x00000600

static heap pages;
static void (*start_callback)();

#ifdef MP_DEBUG
#define mp_debug(x) console(x)
#define mp_debug_u64(x) print_u64(x)
#else
#define mp_debug(x)
#define mp_debug_u64(x)
#endif

static void __attribute__((noinline)) ap_new_stack()
{
    mp_debug("ap_new_stack for cpu ");

    u64 id = apic_id();
    mp_debug_u64(id);
    cpu_setgs(id);
    cpuinfo ci = current_cpu();

    set_ist(id, IST_PAGEFAULT, u64_from_pointer(ci->fault_stack));
    set_ist(id, IST_INTERRUPT, u64_from_pointer(ci->int_stack));
    set_running_frame(ci->misc_frame);
    mp_debug(", install gdt");
    install_gdt64_and_tss(id);
    mp_debug(", enable apic");
    enable_apic();
    mp_debug(", clear ap lock, enable ints, start_callback\n");
    ap_lock = 0;
    enable_interrupts();
    start_callback();
}

void ap_start()
{
    void *n = allocate_stack(pages, 16);
    switch_stack(n, ap_new_stack);
}

void start_cpu(heap h, heap p, int index, void (*ap_entry)()) {
    pages = p;
    start_callback = ap_entry;
    if (apboot == INVALID_ADDRESS) {
        apboot = pointer_from_u64(AP_BOOT_START);
        map((u64)apboot, (u64)apboot, PAGESIZE, PAGE_WRITABLE, h);
    }
    asm("sgdt %0": "=m"(ap_gdt_pointer));
    asm("sidt %0": "=m"(ap_idt_pointer));    
    mov_from_cr("cr3", ap_pagetable);
    // just one function call
    void *rsp = allocate_stack(pages, 1);
    ap_stack = rsp;

    runtime_memcpy(apboot, &apinit, &apinit_end - &apinit);
    u8 vector = (((u64)apboot) >> 12) & 0xff;
    
    apic_ipi(index, ICR_TYPE_INIT, 0);
    kernel_delay(microseconds(10));
    apic_ipi(index, ICR_TYPE_STARTUP, vector);
    kernel_delay(microseconds(200));
    apic_ipi(index, ICR_TYPE_STARTUP, vector);
    kernel_delay(microseconds(200));    
}
