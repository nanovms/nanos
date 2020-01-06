#include <x86_64.h>
#include <apic.h>
#include <page.h>

static void *apboot = 0;
extern u8 apinit, apinit_end;
extern void *ap_pagetable, *ap_start_vector, *ap_gdt_pointer, *ap_idt_pointer, *ap_stack;
extern u64 ap_lock;

#define ICR_TYPE_INIT         0x00000500
#define ICR_TYPE_STARTUP      0x00000600

static heap pages;
static void (*start_callback)();

static void ap_new_stack()
{
    console("start ");
    u64 x = read_msr(IA32_APIC_BASE_MSR);
    print_u64(x);
    console(" ");
    //    write_msr(IA32_APIC_BASE_MSR, 0xfee00000);
    //    x = read_msr(IA32_APIC_BASE_MSR);
    //    print_u64(x);
    console(" ");    
    //    enable_apic();
    print_u64(apic_id());
    console("\n");
    ap_lock = 0;
//    __asm__("hlt");
    start_callback();
}

void ap_start()
{
    //   console("start ");
    //    print_u64(apic_id());
    //       console("\n");
    void *n = allocate_stack(pages, 16);
    asm ("mov %0, %%rsp": :"m"(n));
    ap_new_stack();
}


void start_cpu(heap h, heap p, int index, void (*ap_entry)()) {
    pages = p ;
    start_callback = ap_entry;
    if (!apboot) {
        apboot =  (void *)0x8000;
        map((u64)apboot, (u64)apboot, 4096, PAGE_WRITABLE, h);
    }
    asm("sgdt %0": "=m"(ap_gdt_pointer));
    asm("sidt %0": "=m"(ap_idt_pointer));    
    mov_from_cr("cr3", ap_pagetable);
    // just one function call
    void *rsp = allocate_stack(pages, 1);
    ap_stack = rsp;

    runtime_memcpy(apboot, &apinit, &apinit_end - &apinit);
    u8 vector = (((u64)apboot) >> 12) & 0xff;
    
    apic_ipi(index, ICR_TYPE_INIT);
    kernel_delay(microseconds(10));
    apic_ipi(index, ICR_TYPE_STARTUP | vector);
    kernel_delay(microseconds(200));
    apic_ipi(index, ICR_TYPE_STARTUP | vector);
    kernel_delay(microseconds(200));    
}
