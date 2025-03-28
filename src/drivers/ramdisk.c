#include <kernel.h>
#include <storage.h>

#include "ramdisk.h"

typedef struct storage *storage;

declare_closure_struct(2, 3, void, ramdisk_io,
                       storage, st, boolean, write,
                       void *buf, range blocks, status_handler sh);

typedef struct storage
{
    closure_struct(storage_simple_req_handler, req_handler);
    closure_struct(ramdisk_io, read);
    closure_struct(ramdisk_io, write);
    void *ramdisk;
    u64 ramdisk_size;
} *storage;

define_closure_function(2, 3, void, ramdisk_io,
                        storage, st, boolean, write,
                        void *buf, range blocks, status_handler sh)
{
    storage st = bound(st);
    boolean write = bound(write);

    if (write)
    {
        apply(sh, timm("result", "read-only device"));
        return;
    }

    u64 start_byte_offset = blocks.start * SECTOR_SIZE;
    u64 end_byte_offset = blocks.end * SECTOR_SIZE;
    if (start_byte_offset > end_byte_offset || end_byte_offset > st->ramdisk_size)
    {
        apply(sh, timm("result", "read out of bounds"));
        return;
    }

    runtime_memcpy(buf, st->ramdisk + start_byte_offset, end_byte_offset - start_byte_offset);
    apply(sh, STATUS_OK);
}

void init_ramdisk(kernel_heaps kh, storage_attach a)
{
    range ramdisk_phys = kern_get_ramdisk();
    if (ramdisk_phys.start == INVALID_PHYSICAL)
    {
        msg_print("RAMDISK: not detected");
        return;
    }
    u64 ramdisk_size = range_span(ramdisk_phys);
    u64 v = allocate_u64((heap)heap_virtual_huge(kh), ramdisk_size);
    map(v, ramdisk_phys.start, ramdisk_size, pageflags_memory());

    heap h = heap_locked(kh);
    storage st = allocate(h, sizeof(struct storage));
    st->ramdisk = pointer_from_u64(v);
    st->ramdisk_size = ramdisk_size;
    apply(a,
          storage_init_req_handler(&st->req_handler,
                                   init_closure(&st->read, ramdisk_io, st, false),
                                   init_closure(&st->write, ramdisk_io, st, true)),
          ramdisk_size, -1);
    msg_print("RAMDISK: %u bytes at %p", st->ramdisk_size, st->ramdisk);
}