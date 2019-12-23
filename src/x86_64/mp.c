#include <x86_64.h>
#include <apic.h>
#include <page.h>

static void *apentry = 0;
extern u8 apinit, apinit_end;
extern void *ap_pagetable, **ap_start_vector, *ap_gdt_pointer;

#define ICR_TYPE_INIT         0x00000500
#define ICR_TYPE_STARTUP      0x00000600

static void *setup(heap h, void *entry)
{
    if (!apentry) {
        apentry =  (void *)0x8000;
        map((u64)apentry, (u64)apentry, 4096, PAGE_WRITABLE, h);
    }
    asm("sgdt %0": "=m"(ap_gdt_pointer));
    mov_from_cr("cr3", ap_pagetable);
    ap_start_vector = entry;
    runtime_memcpy(apentry, &apinit, &apinit_end - &apinit);
    return(apentry);
}


// do we have buffer-based marshalling routines
#define field(__p, __length)
void start_cpu(heap h, int index, void (*ap_entry)()) {
    // we are modifying ap_entry in place without any serialization
    void *x = setup(h, ap_entry);
    u8 vector = (((u64)x) >> 12) & 0xff;
    
    apic_ipi(index, ICR_TYPE_INIT);
    kernel_delay(microseconds(10));
    apic_ipi(index, ICR_TYPE_STARTUP | vector);
    kernel_delay(microseconds(200));
    apic_ipi(index, ICR_TYPE_STARTUP | vector);
    kernel_delay(microseconds(200));    
}
