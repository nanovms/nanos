#include <acpi.h>
#include <kernel.h>
#include <drivers/acpi.h>
#include <pci.h>

//#define ACPI_DEBUG
#ifdef ACPI_DEBUG
#define acpi_debug(x, ...) rprintf("ACPI: " x "\n", ##__VA_ARGS__)
#else
#define acpi_debug(x, ...)
#endif

#define acpi_heap   heap_locked(get_kernel_heaps())

typedef struct acpi_pci_res_ctx {
    range bridge_window;
    id_heap iomem;
} *acpi_pci_res_ctx;

boolean acpi_walk_madt(madt_handler mh)
{
    ACPI_TABLE_HEADER *madt;
    ACPI_STATUS rv = AcpiGetTable(ACPI_SIG_MADT, 1, &madt);
    if (ACPI_FAILURE(rv))
        return false;
    u8 *p = (u8 *)madt + sizeof(ACPI_TABLE_MADT);
    u8 *pe = (u8 *)madt + madt->Length;
    for (; p < pe; p += p[1])
        apply(mh, p[0], p);
    AcpiPutTable(madt);
    return true;
}

boolean acpi_walk_mcfg(mcfg_handler h)
{
    ACPI_TABLE_HEADER *mcfg;
    ACPI_STATUS rv = AcpiGetTable(ACPI_SIG_MCFG, 1, &mcfg);
    if (ACPI_FAILURE(rv))
        return false;
    ACPI_MCFG_ALLOCATION *a = (ACPI_MCFG_ALLOCATION *)(((ACPI_TABLE_MCFG *)mcfg) + 1);
    int n = (mcfg->Length - sizeof(ACPI_TABLE_MCFG)) / sizeof(ACPI_MCFG_ALLOCATION);
    for (int i = 0; i < n; i++) {
        if (apply(h, a->Address, a->PciSegment, a->StartBusNumber, a->EndBusNumber))
            break;
    }
    AcpiPutTable(mcfg);
    return true;
}

boolean acpi_parse_spcr(spcr_handler h)
{
    ACPI_TABLE_HEADER *t;
    ACPI_STATUS rv = AcpiGetTable(ACPI_SIG_SPCR, 1, &t);
    if (ACPI_FAILURE(rv))
        return false;
    ACPI_TABLE_SPCR *spcr = (ACPI_TABLE_SPCR *)t;
    apply(h, spcr->InterfaceType, spcr->SerialPort.Address);
    AcpiPutTable(t);
    return true;
}

closure_function(1, 0, void, acpi_eject,
                 ACPI_HANDLE, device)
{
    ACPI_HANDLE device = bound(device);
    acpi_debug("eject %p", device);
    ACPI_OBJECT arg = {
        .Integer = {
            .Type = ACPI_TYPE_INTEGER,
            .Value = 1,
        },
    };
    ACPI_OBJECT_LIST arg_list;
    arg_list.Count = 1;
    arg_list.Pointer = &arg;
    ACPI_STATUS rv = AcpiEvaluateObject(device, "_EJ0", &arg_list, NULL);
    if (ACPI_FAILURE(rv))
        msg_err("failed to eject device (%d)\n", rv);
    closure_finish();
}

static void acpi_pci_notify(ACPI_HANDLE device, UINT32 value, void *context)
{
    acpi_debug("PCI notify %p %d", device, value);
    struct pci_dev dev;
    dev.bus = u64_from_pointer(context);
    ACPI_OBJECT obj;
    ACPI_BUFFER retb = {
            .Pointer = &obj,
            .Length = sizeof(obj),
    };
    ACPI_STATUS rv = AcpiEvaluateObjectTyped(device, METHOD_NAME__ADR, NULL,
                                             &retb, ACPI_TYPE_INTEGER);
    if (ACPI_FAILURE(rv)) {
        msg_err("failed to get device address (%d)\n", rv);
        return;
    }
    u32 adr = obj.Integer.Value;
    dev.slot = (adr >> 16) & 0xFFFF;
    dev.function = adr & 0xFFFF;
    thunk complete;
    switch (value) {
    case ACPI_NOTIFY_DEVICE_CHECK:
        pci_probe_device(&dev);
        break;
    case ACPI_NOTIFY_EJECT_REQUEST:
        complete = closure(acpi_heap, acpi_eject, device);
        if (complete != INVALID_ADDRESS)
            pci_remove_device(&dev, complete);
        else
            msg_err("failed to allocate device ejection closure\n");
        break;
    }
}

ACPI_STATUS acpi_pci_res_handler(ACPI_RESOURCE *resource, void *context)
{
    ACPI_RESOURCE_ADDRESS64 a64;
    if (ACPI_FAILURE(AcpiResourceToAddress64(resource, &a64)))
        return AE_OK;
    acpi_pci_res_ctx ctx = context;
    u64 base, len;
    switch(a64.ResourceType) {
    case ACPI_MEMORY_RANGE:
        base = a64.Address.Minimum + a64.Address.TranslationOffset;
        len = a64.Address.AddressLength;

        /* Skip low memory addresses, which may be reserved in some platforms (e.g. video memory at
         * 0xA0000 in the PC platform). */
        if ((base >= MB) && !(base & MASK(PAGELOG)) && !(len & MASK(PAGELOG)))
            id_heap_add_range(ctx->iomem, base, len);

        break;
    case ACPI_BUS_NUMBER_RANGE:
        ctx->bridge_window = irangel(a64.Address.Minimum, a64.Address.AddressLength);
        break;
    }
    return AE_OK;
}

static ACPI_STATUS acpi_device_handler(ACPI_HANDLE object, u32 nesting_level, void *context,
                                       void **return_value)
{
    ACPI_DEVICE_INFO *dev_info;
    ACPI_STATUS rv = AcpiGetObjectInfo(object, &dev_info);
    if (ACPI_SUCCESS(rv)) {
        if (dev_info->Flags & ACPI_PCI_ROOT_BRIDGE) {
            acpi_debug("retrieving PCI root bridge resources for %p", object);
            id_heap iomem = allocate_id_heap(acpi_heap, acpi_heap, PAGESIZE, true);
            assert(iomem != INVALID_ADDRESS);
            struct acpi_pci_res_ctx ctx = {
                    .bridge_window = irange(0, 0),
                    .iomem = iomem,
            };
            rv = AcpiWalkResources(object, METHOD_NAME__CRS, acpi_pci_res_handler, &ctx);
            if (ACPI_SUCCESS(rv))
                pci_bridge_set_iomem(ctx.bridge_window, iomem);
            else
                msg_err("cannot retrieve PCI root bridge resources: %d\n", rv);
        }
        ACPI_FREE(dev_info);
    }

    /* Install notification handlers for hotpluggable PCI slots. */
    ACPI_HANDLE tmp;
    if (ACPI_FAILURE(AcpiGetHandle(object, METHOD_NAME__ADR, &tmp)) ||
        ACPI_FAILURE(AcpiGetHandle(object, "_EJ0", &tmp)) ||
        ACPI_FAILURE(AcpiGetParent(object, &tmp)))
        return AE_OK;
    ACPI_DEVICE_INFO *parent_info;
    rv = AcpiGetObjectInfo(tmp, &parent_info);
    if (ACPI_SUCCESS(rv)) {
        if (parent_info->Flags & ACPI_PCI_ROOT_BRIDGE) {
            acpi_debug("installing PCI notify handler for %p", object);
            rv = AcpiInstallNotifyHandler(object, ACPI_SYSTEM_NOTIFY, acpi_pci_notify,
                                          pointer_from_u64(parent_info->Address));
            if (ACPI_FAILURE(rv))
                msg_err("cannot install PCI notify handler: %d\n", rv);
        }
        ACPI_FREE(parent_info);
    }
    return rv;
}

void init_acpi_tables(kernel_heaps kh)
{
    assert(ACPI_SUCCESS(AcpiInitializeSubsystem()));
    ACPI_STATUS rv = AcpiInitializeTables(NULL, 0, true);
    if (ACPI_FAILURE(rv)) {
        acpi_debug("AcpiInitializeTables returned %d", rv);
        return;
    }
    rv = AcpiLoadTables();
    if (ACPI_FAILURE(rv))
        acpi_debug("AcpiLoadTables returned %d", rv);
    AcpiGetDevices(NULL, acpi_device_handler, NULL, NULL);
}

static UINT32 acpi_sleep(void *context)
{
    acpi_debug("sleep");
    const u64 sleep_state = 3;  /* S3 state */
    ACPI_STATUS rv = AcpiEnterSleepStatePrep(sleep_state);
    if (ACPI_FAILURE(rv)) {
        msg_err("failed to prepare to sleep (%d)\n", rv);
        goto exit;
    }
    rv = AcpiEnterSleepState(sleep_state);
    if (ACPI_FAILURE(rv)) {
        msg_err("failed to enter sleep state (%d)\n", rv);
        goto exit;
    }
    rv = AcpiLeaveSleepStatePrep(sleep_state);
    if (ACPI_FAILURE(rv)) {
        msg_err("failed to prepare to leave sleep state (%d)\n", rv);
        goto exit;
    }
    rv = AcpiLeaveSleepState(sleep_state);
    if (ACPI_FAILURE(rv))
        msg_err("failed to leave sleep state (%d)\n", rv);
  exit:
    return ACPI_INTERRUPT_HANDLED;
}

static UINT32 acpi_shutdown(void *context)
{
    acpi_debug("shutdown");
    kernel_powerdown();
    return ACPI_INTERRUPT_HANDLED;
}

closure_function(2, 1, void, acpi_powerdown_sleepctrl,
                 ACPI_TABLE_FADT *, fadt, u8, slp_typ,
                 int status)
{
    acpi_debug("powerdown");
    ACPI_STATUS rv = AcpiWrite(ACPI_SLEEPCTRL_SLP_EN | ACPI_SLEEPCTRL_SLP_TYP(bound(slp_typ)), &bound(fadt)->SleepControl);
    if (ACPI_FAILURE(rv))
        acpi_debug("failed to write to Sleep Control register: %d", rv);
}

closure_function(3, 1, void, acpi_powerdown_pm1,
                 ACPI_TABLE_FADT *, fadt, u16, pm1a_slp_typ, u16, pm1b_slp_typ,
                 int status)
{
    acpi_debug("powerdown");
    ACPI_TABLE_FADT *fadt = bound(fadt);
    AcpiOsWritePort(fadt->Pm1aControlBlock,
                    ACPI_PM1_SLP_EN | ACPI_PM1_SLP_TYP(bound(pm1a_slp_typ)), 16);
    AcpiOsWritePort(fadt->Pm1bControlBlock,
                    ACPI_PM1_SLP_EN | ACPI_PM1_SLP_TYP(bound(pm1b_slp_typ)), 16);
}

static void acpi_pwrbtn_handler(ACPI_HANDLE device, UINT32 value, void *context)
{
    acpi_debug("power button value 0x%x", value);
    if (value == 0x80)  /* button pressed */
        acpi_shutdown(context);
}

static ACPI_STATUS acpi_pwrbtn_probe(ACPI_HANDLE object, u32 nesting_level, void *context,
                                     void **return_value)
{
    acpi_debug("found power button");
    ACPI_STATUS rv = AcpiInstallNotifyHandler(object, ACPI_DEVICE_NOTIFY,
                                              acpi_pwrbtn_handler, NULL);
    if (ACPI_FAILURE(rv))
        msg_err("failed to install power button handler: %d\n", rv);
    return rv;
}

closure_function(2, 0, void, acpi_ged_handler,
                 ACPI_HANDLE, event, int, gsi)
{
    acpi_debug("GED event");
    ACPI_OBJECT arg = {
        .Integer = {
            .Type = ACPI_TYPE_INTEGER,
            .Value = bound(gsi),
        },
    };
    ACPI_OBJECT_LIST arg_list;
    arg_list.Count = 1;
    arg_list.Pointer = &arg;
    AcpiEvaluateObject(bound(event), NULL, &arg_list, NULL);
}

static ACPI_STATUS acpi_ged_res_probe(ACPI_RESOURCE *resource, void *context)
{
    switch (resource->Type) {
    case ACPI_RESOURCE_TYPE_EXTENDED_IRQ:
        if (resource->Data.ExtendedIrq.InterruptCount == 1) {
            int gsi = resource->Data.ExtendedIrq.Interrupts[0];
            char ev_name[5];
            ACPI_HANDLE event;
            ACPI_STATUS rv;
            switch (gsi) {
            case 0 ... 255:
                rsnprintf(ev_name, sizeof(ev_name), "_%c%02x",
                          resource->Data.ExtendedIrq.Triggering == ACPI_EDGE_SENSITIVE ? 'E' : 'L',
                          gsi);
                if (ACPI_SUCCESS(AcpiGetHandle(context, ev_name, &event)))
                    break;
                /* fall through */
            default:
                rv = AcpiGetHandle(context, "_EVT", &event);
                if (ACPI_FAILURE(rv)) {
                    msg_err("failed to locate _EVT method: %d\n", rv);
                    return rv;
                }
            }
            thunk handler = closure(acpi_heap, acpi_ged_handler, event, gsi);
            assert(handler != INVALID_ADDRESS);
            acpi_register_irq_handler(gsi, handler, ss("acpi-ged"));
        }
        break;
    }
    return AE_OK;
}

static ACPI_STATUS acpi_ged_probe(ACPI_HANDLE object, u32 nesting_level, void *context,
                                  void **return_value)
{
    acpi_debug("found Generic Event Device");
    return AcpiWalkResources(object, METHOD_NAME__CRS, acpi_ged_res_probe, object);
}

static void acpi_powerdown_init(kernel_heaps kh)
{
    ACPI_TABLE_HEADER *fadt;
    ACPI_STATUS rv = AcpiGetTable(ACPI_SIG_FADT, 1, &fadt);
    if (ACPI_FAILURE(rv)) {
        acpi_debug("cannot find FADT: %d", rv);
        return;
    }

    /* Retrieve SLP_TYP register values to be used when powering down the system. */
    ACPI_BUFFER retb = {
        .Length = ACPI_ALLOCATE_BUFFER,
    };
    rv = AcpiEvaluateObjectTyped(NULL, "\\_S5", NULL, &retb, ACPI_TYPE_PACKAGE);
    if (ACPI_FAILURE(rv)) {
        acpi_debug("failed to get _S5 object (%d)", rv);
        return;
    }
    ACPI_OBJECT *obj = retb.Pointer;
    halt_handler handler = 0;
    switch (obj->Package.Count) {
    case 0:
        break;
    case 1:
        if (obj->Package.Elements[0].Type == ACPI_TYPE_INTEGER)
            handler = closure(heap_general(kh), acpi_powerdown_sleepctrl, (ACPI_TABLE_FADT *)fadt,
                              obj->Package.Elements[0].Integer.Value);
        break;
    default:
        if ((obj->Package.Elements[0].Type == ACPI_TYPE_INTEGER) &&
            (obj->Package.Elements[1].Type == ACPI_TYPE_INTEGER))
            handler = closure(heap_general(kh), acpi_powerdown_pm1, (ACPI_TABLE_FADT *)fadt,
                              obj->Package.Elements[0].Integer.Value,
                              obj->Package.Elements[1].Integer.Value);
    }
    if (handler) {
        assert(handler != INVALID_ADDRESS);
        vm_halt = handler;
    } else {
        acpi_debug("unexpected _S5 object value (%d elements)", obj->Package.Count);
        AcpiPutTable(fadt);
    }
    AcpiOsFree(obj);
}

void init_acpi(kernel_heaps kh)
{
    ACPI_STATUS rv = AcpiEnableSubsystem(ACPI_FULL_INITIALIZATION);
    if (ACPI_FAILURE(rv)) {
        acpi_debug("AcpiEnableSubsystem returned %d", rv);
        return;
    }
    rv = AcpiInitializeObjects(ACPI_FULL_INITIALIZATION);
    if (ACPI_FAILURE(rv)) {
        acpi_debug("AcpiInitializeObjects returned %d", rv);
        return;
    }
    acpi_powerdown_init(kh);
    AcpiGetDevices("ACPI0013", acpi_ged_probe, NULL, NULL);
    AcpiGetDevices("PNP0C0C", acpi_pwrbtn_probe, NULL, NULL);
    rv = AcpiInstallFixedEventHandler(ACPI_EVENT_POWER_BUTTON, acpi_shutdown, 0);
    if (ACPI_FAILURE(rv))
        acpi_debug("cannot install power button hander: %d", rv);
    rv = AcpiInstallFixedEventHandler(ACPI_EVENT_SLEEP_BUTTON, acpi_sleep, 0);
    if (ACPI_FAILURE(rv))
        acpi_debug("cannot install sleep button hander: %d", rv);
    rv = AcpiUpdateAllGpes();
    if (ACPI_FAILURE(rv))
        acpi_debug("cannot update GPEs: %d", rv);
}

static ACPI_STATUS acpi_mmio_res_handler(ACPI_RESOURCE *resource, void *context)
{
    acpi_mmio_dev dev = context;
    switch(resource->Type) {
    case ACPI_RESOURCE_TYPE_FIXED_MEMORY32:
        dev->membase = resource->Data.FixedMemory32.Address;
        dev->memsize = resource->Data.FixedMemory32.AddressLength;
        break;
    case ACPI_RESOURCE_TYPE_EXTENDED_IRQ:
        if (resource->Data.ExtendedIrq.InterruptCount == 1)
            dev->irq = resource->Data.ExtendedIrq.Interrupts[0];
        break;
    }
    return AE_OK;
}

static ACPI_STATUS acpi_mmio_parse(ACPI_HANDLE object, u32 nesting_level, void *context,
                                   void **return_value)
{
    struct acpi_mmio_dev dev = {0};
    ACPI_STATUS rv = AcpiWalkResources(object, METHOD_NAME__CRS, acpi_mmio_res_handler, &dev);
    if (ACPI_SUCCESS(rv) && dev.membase && dev.memsize && dev.irq) {
        acpi_mmio_handler handler = context;
        apply(handler, &dev);
    }
    return rv;
}

void acpi_get_vtmmio_devs(acpi_mmio_handler handler)
{
    AcpiGetDevices("LNRO0005", acpi_mmio_parse, handler, NULL);
}

/* OS services layer */

ACPI_STATUS AcpiOsInitialize(void)
{
    return AE_OK;
}

void *AcpiOsAllocate(ACPI_SIZE size)
{
    heap h = heap_malloc();
    void *p = allocate(h, size);
    return (p != INVALID_ADDRESS) ? p : 0;
}

void AcpiOsFree(void *memory)
{
    heap h = heap_malloc();
    deallocate(h, memory, -1ull);
}

void *AcpiOsMapMemory(ACPI_PHYSICAL_ADDRESS where, ACPI_SIZE length)
{
    acpi_debug("%s(0x%lx, %ld)", func_ss, where, length);
    u64 page_offset = where & PAGEMASK;
    length += page_offset;
    heap vh = (heap)heap_virtual_page(get_kernel_heaps());
    void *v = allocate(vh, length);
    if (v == INVALID_ADDRESS)
        return 0;
    acpi_debug("  mapping 0x%lx(%ld) to 0x%lx", v, length, where & ~PAGEMASK);
    map(u64_from_pointer(v), where & ~PAGEMASK, length, pageflags_writable(pageflags_memory()));
    return v + page_offset;
}

void AcpiOsUnmapMemory(void *where, ACPI_SIZE length)
{
    acpi_debug("%s(0x%lx, %ld)", func_ss, where, length);
    u64 page_offset = u64_from_pointer(where) & PAGEMASK;
    where -= page_offset;
    length = pad(length + page_offset, PAGESIZE);
    acpi_debug("  unmapping 0x%lx(%ld)", where, length);
    unmap(u64_from_pointer(where), length);
    heap vh = (heap)heap_virtual_page(get_kernel_heaps());
    deallocate(vh, where, length);
}

ACPI_STATUS AcpiOsReadMemory(ACPI_PHYSICAL_ADDRESS address, UINT64 *value, UINT32 width)
{
    void *v = AcpiOsMapMemory(address, sizeof(UINT64));
    if (!v)
        return AE_NO_MEMORY;
    switch (width) {
    case 8:
        *value = *(u8 *)v;
        break;
    case 16:
        *value = *(u16 *)v;
        break;
    case 32:
        *value = *(u32 *)v;
        break;
    case 64:
        *value = *(u64 *)v;
        break;
    default:
        return AE_BAD_PARAMETER;
    }
    AcpiOsUnmapMemory(v, sizeof(UINT64));
    return AE_OK;
}

ACPI_STATUS AcpiOsWriteMemory(ACPI_PHYSICAL_ADDRESS address, UINT64 value, UINT32 width)
{
    void *v = AcpiOsMapMemory(address, sizeof(UINT64));
    if (!v)
        return AE_NO_MEMORY;
    switch (width) {
    case 8:
        *(u8 *)v = value;
        break;
    case 16:
        *(u16 *)v = value;
        break;
    case 32:
        *(u32 *)v = value;
        break;
    case 64:
        *(u64 *)v = value;
        break;
    default:
        return AE_BAD_PARAMETER;
    }
    AcpiOsUnmapMemory(v, sizeof(UINT64));
    return AE_OK;
}

ACPI_STATUS AcpiOsReadPciConfiguration(ACPI_PCI_ID *pci_id, UINT32 reg, UINT64 *value, UINT32 width)
{
    struct pci_dev dev = {
            .bus = pci_id->Bus,
            .slot = pci_id->Device,
            .function = pci_id->Function,
    };
    *value = pci_cfgread(&dev, reg, width / 8);
    return AE_OK;
}

ACPI_STATUS AcpiOsWritePciConfiguration(ACPI_PCI_ID *pci_id, UINT32 reg, UINT64 value, UINT32 width)
{
    struct pci_dev dev = {
            .bus = pci_id->Bus,
            .slot = pci_id->Device,
            .function = pci_id->Function,
    };
    pci_cfgwrite(&dev, reg, width / 8, value);
    return AE_OK;
}

UINT64 AcpiOsGetTimer(void)
{
    if (!platform_monotonic_now)    /* platform clock not available yet */
        return 0;
    timestamp t = now(CLOCK_ID_MONOTONIC);
    return nsec_from_timestamp(t) / 100;    /* return time in 100-nanosecond units */
}

void AcpiOsStall(UINT32 usecs)
{
    kernel_delay(microseconds(usecs));
}

void AcpiOsSleep(UINT64 msecs)
{
    halt("%s not supported\n", func_ss);
}

ACPI_STATUS AcpiOsSignal(UINT32 function, void *info)
{
    return AE_NOT_IMPLEMENTED;
}

void AcpiOsPrintf(const char *fmt, ...)
{
    /* We don't handle null-terminated strings, so don't parse the format string. */
}

ACPI_STATUS AcpiOsTableOverride(ACPI_TABLE_HEADER *existing_table, ACPI_TABLE_HEADER **new_table)
{
    *new_table = 0;
    return AE_OK;
}

ACPI_STATUS AcpiOsPhysicalTableOverride(ACPI_TABLE_HEADER *existing_table,
                                        ACPI_PHYSICAL_ADDRESS *new_address,
                                        UINT32 *new_table_length)
{
    *new_address = 0;
    return AE_OK;
}

ACPI_STATUS AcpiOsPredefinedOverride(const ACPI_PREDEFINED_NAMES *init_val, ACPI_STRING *new_val)
{
    *new_val = 0;
    return AE_OK;
}

ACPI_STATUS AcpiOsCreateCache(char *cache_name, UINT16 object_size, UINT16 max_depth,
                              ACPI_CACHE_T **return_cache)
{
    caching_heap h = allocate_objcache(acpi_heap, (heap)heap_page_backed(get_kernel_heaps()),
                                       object_size, PAGESIZE, false);
    if (h == INVALID_ADDRESS)
        return AE_NO_MEMORY;
    *return_cache = (ACPI_CACHE_T *)h;
    return AE_OK;
}

void *AcpiOsAcquireObject(ACPI_CACHE_T *cache)
{
    heap h = (heap)cache;
    void *obj = allocate_zero(h, h->pagesize);
    return (obj != INVALID_ADDRESS) ? obj : 0;
}

ACPI_STATUS AcpiOsReleaseObject(ACPI_CACHE_T *cache, void *object)
{
    heap h = (heap)cache;
    deallocate(h, object, h->pagesize);
    return AE_OK;
}

ACPI_STATUS AcpiOsPurgeCache(ACPI_CACHE_T *cache)
{
    caching_heap ch = (caching_heap)cache;
    cache_drain(ch, CACHE_DRAIN_ALL, 0);
    return AE_OK;
}

ACPI_STATUS AcpiOsCreateLock(ACPI_SPINLOCK *out_handle)
{
    spinlock l = allocate(acpi_heap, sizeof(*l));
    if (l == INVALID_ADDRESS)
        return AE_NO_MEMORY;
    spin_lock_init(l);
    *out_handle = l;
    return AE_OK;
}

ACPI_CPU_FLAGS AcpiOsAcquireLock(ACPI_SPINLOCK handle)
{
    return spin_lock_irq(handle);
}

void AcpiOsReleaseLock(ACPI_SPINLOCK handle, ACPI_CPU_FLAGS flags)
{
    spin_unlock_irq(handle, flags);
}

void AcpiOsDeleteLock(ACPI_SPINLOCK handle)
{
    deallocate(acpi_heap, handle, sizeof(struct spinlock));
}

ACPI_STATUS AcpiOsCreateSemaphore(UINT32 max_units, UINT32 initial_units, ACPI_HANDLE *out_handle)
{
    ACPI_STATUS rv;
    if (max_units != 1)
        return AE_NOT_IMPLEMENTED;
    rv = AcpiOsCreateLock(out_handle);
    if (rv != AE_OK)
        return rv;
    if (initial_units == 0)
        spin_lock(*out_handle);
    return AE_OK;
}

ACPI_STATUS AcpiOsWaitSemaphore(ACPI_HANDLE handle, UINT32 units, UINT16 msec_timeout)
{
    if (units == 1) {
        spin_lock(handle);
        return AE_OK;
    }
    return AE_NOT_IMPLEMENTED;
}

ACPI_STATUS AcpiOsSignalSemaphore(ACPI_HANDLE handle, UINT32 units)
{
    if (units == 1) {
        spin_unlock(handle);
        return AE_OK;
    }
    return AE_NOT_IMPLEMENTED;
}

ACPI_STATUS AcpiOsDeleteSemaphore(ACPI_HANDLE handle)
{
    AcpiOsDeleteLock(handle);
    return AE_OK;
}

closure_function(2, 0, void, acpi_async_func,
                 ACPI_OSD_EXEC_CALLBACK, function, void *, context)
{
    acpi_debug("async %p", bound(function));
    bound(function)(bound(context));
    closure_finish();
}

ACPI_STATUS AcpiOsExecute(ACPI_EXECUTE_TYPE type, ACPI_OSD_EXEC_CALLBACK function, void *context)
{
    acpi_debug("execute %p", function);
    thunk t = closure(acpi_heap, acpi_async_func, function, context);
    if (t == INVALID_ADDRESS)
        return AE_NO_MEMORY;
    async_apply_bh(t);
    return AE_OK;
}

ACPI_THREAD_ID AcpiOsGetThreadId(void)
{
    return 1;   /* dummy value */
}

ACPI_STATUS AcpiOsEnterSleep(UINT8 sleep_state, UINT32 rega_value, UINT32 regb_value)
{
    return AE_OK;
}

closure_function(2, 0, void, acpi_irq,
                 ACPI_OSD_HANDLER, service_routine, void *, context)
{
    acpi_debug("irq");
    bound(service_routine)(bound(context));
}

UINT32 AcpiOsInstallInterruptHandler(UINT32 interrupt_number, ACPI_OSD_HANDLER service_routine,
                                     void *context)
{
    thunk irq_handler = closure(acpi_heap, acpi_irq, service_routine, context);
    if (irq_handler == INVALID_ADDRESS)
        return AE_NO_MEMORY;
    acpi_register_irq_handler(interrupt_number, irq_handler, ss("ACPI"));
    return AE_OK;
}

ACPI_STATUS AcpiOsRemoveInterruptHandler(UINT32 interrupt_number, ACPI_OSD_HANDLER service_routine)
{
    return AE_NOT_IMPLEMENTED;
}
