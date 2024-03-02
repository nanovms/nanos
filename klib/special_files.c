#include <unix_internal.h>
#include <filesystem.h>
#include <storage.h>

static heap specfiles_heap;

typedef struct specfiles_disks {
    file f;
    closure_struct(file_io, read);
    closure_struct(fdesc_close, close);
} *specfiles_disks;

closure_function(1, 4, void, disks_handler,
                 buffer, b,
                 u8 *uuid, sstring label, filesystem fs, inode mount_point)
{
    buffer b = bound(b);
    buffer_write_cstring(b, "[\n");
    if (!sstring_is_empty(label))
        bprintf(b, "\tNAME=%s\n", label);
    if (uuid) {
        buffer_write_cstring(b, "\tUUID=");
        print_uuid(b, uuid);
        push_u8(b, '\n');
    }
    buffer_write_cstring(b, "]\n");
}

closure_func_basic(file_io, sysreturn, disks_read,
                   void * dest, u64 len, u64 offset_arg, context ctx, boolean bh, io_completion completion)
{
    specfiles_disks disks = struct_from_field(closure_self(), specfiles_disks, read);
    buffer b = allocate_buffer(specfiles_heap, 64);
    if (b == INVALID_ADDRESS)
        io_complete(completion, -ENOMEM);
    storage_iterate(stack_closure(disks_handler, b));
    boolean is_file_offset = (offset_arg == infinity);
    u64 offset = is_file_offset ? disks->f->offset : offset_arg;
    sysreturn rv = !context_set_err(ctx) ? buffer_read_at(b, offset, dest, len) : -EFAULT;
    deallocate_buffer(b);
    if ((rv > 0) && is_file_offset)
        disks->f->offset += rv;
    return io_complete(completion, rv);
}

closure_func_basic(fdesc_close, sysreturn, disks_close,
                   context ctx, io_completion completion)
{
    specfiles_disks disks = struct_from_field(closure_self(), specfiles_disks, close);
    file_release(disks->f);
    deallocate(specfiles_heap, disks, sizeof(*disks));
    return io_complete(completion, 0);
}

closure_func_basic(spec_file_open, sysreturn, disks_open,
                   file f)
{
    specfiles_disks disks = allocate(specfiles_heap, sizeof(struct specfiles_disks));
    if (disks == INVALID_ADDRESS)
        return -ENOMEM;
    disks->f = f;
    f->f.read = init_closure_func(&disks->read, file_io, disks_read);
    f->f.close = init_closure_func(&disks->close, fdesc_close, disks_close);
    return 0;
}

int init(status_handler complete)
{
    specfiles_heap = heap_locked(get_kernel_heaps());
    tuple root = get_root_tuple();
    if (!root)
        return KLIB_INIT_FAILED;
    tuple cfg = get_tuple(root, sym_this("special_files"));
    if (!cfg)
        return KLIB_INIT_OK;
    boolean error = false;
    tuple disks_cfg = get_tuple(cfg, sym_this("disks"));
    if (disks_cfg) {
        spec_file_open open = closure_func(specfiles_heap, spec_file_open, disks_open);
        if (open == INVALID_ADDRESS)
            error = true;
        else if (!create_special_file(ss("/sys/devices/disks"), open, 0, 0)) {
            deallocate_closure(open);
            error = true;
        }
    }
    if (error)
        return KLIB_INIT_FAILED;
    return KLIB_INIT_OK;
}
