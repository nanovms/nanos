#include <virtio_internal.h>

static CLOSURE_4_3(attach, void, heap, heap, heap, heap, int, int, int);
static void attach(heap general, heap page_allocator, heap pages, heap virtual, int bus, int slot, int function)
{
    console("storage\n");
    vtpci v = attach_vtpci(general, page_allocator, bus, slot, function);
    u32 len;
    u32 base = pci_readbar(bus, slot, function, 0, &len);

    //    void *target = allocate(virtual);
    //    map(u64_from_pointer(target), (u64)base, len, pages);
    base &= ~1;
    rprintf("base: %p %x\n", base, len);    
    for (int i = 0; i < len ;i+=4)
        rprintf ("%08x\n", in32(i + base));
    pci_set_bus_master(bus, slot, function);
    //    QEMU_HALT();
}

void init_virtio_storage(heap h, heap page_allocator, heap pages, heap virtual)
{
    register_pci_driver(VIRTIO_PCI_VENDORID, VIRTIO_PCI_DEVICEID_STORAGE, closure(h, attach, h, page_allocator, pages, virtual));
}
