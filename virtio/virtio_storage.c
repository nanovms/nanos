#include <virtio_internal.h>

static CLOSURE_3_3(attach, void, heap, heap, heap, int, int, int);
static void attach(heap general, heap physical, heap pages, int bus, int slot, int function)
{
    vtpci v = attach_vtpci(general, bus, slot, function);
    u32 len;
    u32 base = pci_readbar(bus, slot, function, 0, &len);

    //    void *target = pointer_from_u64(0xf00000000);
    //    map(u64_from_pointer(target), (u64)base, len, pages);
    base &= ~1;
    rprintf("base: %p %x\n", base, len);    
    for (int i = 0; i < len ;i+=4)
        rprintf ("%08x\n", in32(i + base));
    pci_set_bus_master(bus, slot, function);
    QEMU_HALT();

}

void init_virtio_storage(heap h, heap physical, heap pages)
{
    register_pci_driver(VIRTIO_PCI_VENDORID, VIRTIO_PCI_DEVICEID_STORAGE, closure(h, attach, h, physical, pages));
}
