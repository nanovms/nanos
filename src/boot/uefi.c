#include <runtime.h>
#include <page.h>
#include <elf64.h>
#include <pagecache.h>
#include <storage.h>
#include <tfs.h>
#include <uefi.h>

/* Number of spare memory descriptors allocated to cover any additional descriptors that may be
 * inserted in the memory map between a get_memory_map() call and a exit_boot_services() call. */
#define UEFI_MEMDESC_SPARE_COUNT    8

//#define UEFI_DEBUG
#ifdef UEFI_DEBUG
# define uefi_debug(x, ...) rprintf("UEFI: " x "\n", ##__VA_ARGS__)
#else
# define uefi_debug(...)
#endif

struct efi_guid uefi_block_io_proto = {
        0x964e5b21, 0x6459, 0x11d2, {0x8e, 0x39, 0x00, 0xa0, 0xc9, 0x69, 0x72, 0x3b}
};
struct efi_guid uefi_rng_proto = {
        0x3152bca5, 0xeade, 0x433d, {0x86, 0x2e, 0xc0, 0x1c, 0xdc, 0x29, 0x1f, 0x44}
};

struct efi_guid uefi_smbios_table = {
        0xeb9d2d31, 0x2d88, 0x11d3, {0x9a, 0x16, 0x00, 0x90, 0x27, 0x3f, 0xc1, 0x4d}
};
struct efi_guid uefi_acpi20_table = {
        0x8868e871, 0xe4f1, 0x11d3, {0xbc, 0x22, 0x00, 0x80, 0xc7, 0x3c, 0x88, 0x81}
};

static void *uefi_image_handle;
static efi_system_table uefi_system_table;
static struct heap general;

/* UEFI Boot Services */
#define UBS uefi_system_table->boot_services

void console_write(const char *s, bytes count)
{
    u16 buf[2 * count + 1];
    int out_count = 0;
    for (int i = 0; i < count; i++, out_count++) {
        if (s[i] == '\n')
            buf[out_count++] = '\r';    /* needed for proper carriage return under Hyper-V */
        buf[out_count] = s[i];
    }
    buf[out_count] = '\0';
    uefi_system_table->con_out->output_string(uefi_system_table->con_out, buf);
}

void klog_write(const char *s, bytes count)
{
}

void print_frame_trace_from_here(void)
{
}

u64 random_u64()
{
    static void **handle_buffer;
    static efi_rng_protocol rng;

    if (!rng) {
        u64 handle_count;
        efi_status status = UBS->locate_handle_buffer(by_protocol, &uefi_rng_proto, 0,
            &handle_count, &handle_buffer);
        if (EFI_ERROR(status)) {
            msg_err("failed to locate RNG handles: %d\n", status);
            return 0;
        }
        for (u64 index = 0; index < handle_count; index++) {
            status = UBS->open_protocol(handle_buffer[index], &uefi_rng_proto, (void **)&rng,
                uefi_image_handle, 0, EFI_OPEN_PROTOCOL_GET_PROTOCOL);
            if (EFI_ERROR(status))
                msg_err("failed to open RNG protocol: %d\n", status);
            else
                break;
        }
    }
    if (rng) {
        u64 result;
        rng->get_rng(rng, 0, sizeof(result), &result);
        return result;
    } else {
        return 0;
    }
}

void halt_with_code(u8 code, char *format, ...)
{
    vlist a;
    buffer b = little_stack_buffer(512);
    vstart(a, format);
    vbprintf(b, alloca_wrap_cstring(format), &a);
    buffer_print(b);
    UBS->exit(uefi_image_handle, EFI_LOAD_ERROR, 0, 0); /* does not return */
    while(1);   /* to honor "noreturn" attribute */
}

heap heap_dma(void)
{
    return &general;
}

static u64 uefi_alloc(heap h, bytes b)
{
    void *buf;
    efi_status status = UBS->allocate_pool(efi_loader_data, b, &buf);
    if (EFI_ERROR(status) || !buf)
        return INVALID_PHYSICAL;
    return u64_from_pointer(buf);
}

static void uefi_dealloc(struct heap *h, u64 a, bytes b)
{
    UBS->free_pool(pointer_from_u64(a));
}

/* Returns page-aligned addresses */
static u64 uefi_alloc_aligned(heap h, bytes b)
{
    u64 buf = uefi_alloc(h, pad(b, h->pagesize) + h->pagesize);
    if (buf != INVALID_PHYSICAL)
        buf = pad(buf, h->pagesize);
    return buf;
}

closure_function(1, 2, void, uefi_io_sh,
                 status_handler, sh,
                 status, s, bytes, length)
{
    apply(bound(sh), s);
}

closure_function(1, 4, void, uefi_kernel_load,
                 fsfile, kernel,
                 u64, offset, u64, length, void *, dest, status_handler, sh)
{
    filesystem_read_linear(bound(kernel), dest, irangel(offset, length),
                           stack_closure(uefi_io_sh, sh));
}

closure_function(1, 1, void, uefi_kernel_loaded,
                 u64 *, kernel_entry,
                 status, s)
{
    if (!is_ok(s))
        halt("UEFI: failed to load kernel %v\n", s);
    u64 entry = *bound(kernel_entry);
    uefi_debug("starting kernel at %p", entry);
    uefi_start_kernel(uefi_image_handle, uefi_system_table, 0, pointer_from_u64(entry));
}

closure_function(1, 1, status, uefi_kernel_complete,
                 heap, h,
                 buffer, b)
{
    uefi_debug("kernel read complete, loaded at %p", buffer_ref(b, 0));
    void *kernel_entry = load_kernel_elf(b, bound(h));
    if (!kernel_entry)
        halt("UEFI: kernel ELF parse failed\n");
    uefi_debug("starting kernel at %p", kernel_entry);
    uefi_start_kernel(uefi_image_handle, uefi_system_table, b, kernel_entry);
    halt("UEFI: failed to start kernel\n");
    return STATUS_OK;
}

closure_function(0, 1, void, uefi_kernel_fail,
                 status, s)
{
    halt("UEFI: failed to read kernel file\n");
}

closure_function(2, 1, void, uefi_blkdev_read,
                 efi_block_io_protocol , block_io, u64, offset,
                 storage_req, req)
{
    if (req->op != STORAGE_OP_READSG)
        halt("%s: invalid storage op %d\n", __func__, req->op);
    sg_list sg = req->data;
    efi_block_io_protocol block_io = bound(block_io);
    efi_status status = EFI_SUCCESS;
    while (range_span(req->blocks)) {
        sg_buf sgb = sg_list_head_peek(sg);
        u64 length = sg_buf_len(sgb);
        assert((length & (SECTOR_SIZE - 1)) == 0);
        length = MIN(length, range_span(req->blocks) << SECTOR_OFFSET);
        status = block_io->read_blocks(block_io, block_io->media->media_id,
            bound(offset) + req->blocks.start, length, sgb->buf + sgb->offset);
        if (EFI_ERROR(status))
            break;
        sg_consume(sg, length);
        req->blocks.start += length >> SECTOR_OFFSET;
    }
    apply(req->completion,
          EFI_ERROR(status) ? timm("result", "read_blocks status %d", status) : STATUS_OK);
}

closure_function(3, 2, void, uefi_bootfs_complete,
                 heap, general, heap, aligned, uefi_arch_options, options,
                 filesystem, fs, status, s)
{
    if (!is_ok(s))
        halt("UEFI: failed to read boot filesystem\n");
    uefi_debug("boot filesystem opened");
    tuple t = lookup(filesystem_getroot(fs), sym(kernel));
    if (!t)
        halt("UEFI: kernel file not found\n");
    heap general = bound(general);
    heap aligned = bound(aligned);
    if (bound(options)->load_to_physical) {
        fsfile fsf = fsfile_from_node(fs, t);
        if (!fsf)
            halt("UEFI: invalid kernel file\n");
        u64 kernel_entry;
        load_elf_to_physical(general, stack_closure(uefi_kernel_load, fsf), &kernel_entry,
                             stack_closure(uefi_kernel_loaded, &kernel_entry));
    } else {
        buffer_handler bh = closure(general, uefi_kernel_complete, aligned);
        assert(bh != INVALID_ADDRESS);
        status_handler sh = closure(general, uefi_kernel_fail);
        assert(sh != INVALID_ADDRESS);
        filesystem_read_entire(fs, t, aligned, bh, sh);
    }
}

heap boot_buffer_heap;

efi_status efi_main(void *image_handle, efi_system_table system_table)
{
    uefi_image_handle = image_handle;
    uefi_system_table = system_table;
    zero(&general, sizeof(general));
    general.alloc = uefi_alloc;
    general.dealloc = uefi_dealloc;
    struct heap aligned_heap;
    zero(&aligned_heap, sizeof(aligned_heap));
    aligned_heap.alloc = uefi_alloc_aligned;
    aligned_heap.dealloc = leak;
    aligned_heap.pagesize = PAGESIZE;
    init_runtime(&general, &general);
    init_integers(allocate_tagged_region(&general, tag_integer));
    init_tuples(allocate_tagged_region(&general, tag_table_tuple));
    init_symbols(allocate_tagged_region(&general, tag_symbol), &general);
    init_vectors(allocate_tagged_region(&general, tag_vector), &general);
    init_strings(allocate_tagged_region(&general, tag_string), &general);

    /* given our rewind tag, all values must be tagged - even untyped buffers */
    boot_buffer_heap = allocate_tagged_region(&general, tag_unknown);
    init_sg(&general);
    struct uefi_arch_options options;
    uefi_arch_setup(&general, &aligned_heap, &options);

    u64 handle_count;
    void **handle_buffer;
    efi_status status = UBS->locate_handle_buffer(by_protocol, &uefi_block_io_proto, 0,
        &handle_count, &handle_buffer);
    if (EFI_ERROR(status)) {
        msg_err("failed to locate block I/O handles: %d\n", status);
        return status;
    }
    for (u64 index = 0; index < handle_count; index++) {
        efi_block_io_protocol block_io;
        status = UBS->open_protocol(handle_buffer[index], &uefi_block_io_proto,
            (void **)&block_io, image_handle, 0, EFI_OPEN_PROTOCOL_GET_PROTOCOL);
        if (EFI_ERROR(status) || !block_io->media->media_present)
            continue;
        u8 mbr[SECTOR_SIZE];
        status = block_io->read_blocks(block_io, block_io->media->media_id, 0, SECTOR_SIZE, &mbr);
        if (EFI_ERROR(status)) {
            msg_err("failed to read first sector: %d\n", status);
            continue;
        }
        struct partition_entry *bootfs_part = partition_get(mbr, PARTITION_BOOTFS);
        if (!bootfs_part || (bootfs_part->lba_start == 0) || (bootfs_part->nsectors == 0))
            continue;
        uefi_debug("found boot filesystem at LBA 0x%lx, length 0x%lx sectors",
                   bootfs_part->lba_start, bootfs_part->nsectors);
        init_pagecache(&general, &general, PAGESIZE);
        create_filesystem(&general, SECTOR_SIZE, bootfs_part->nsectors * SECTOR_SIZE,
                          closure(&general, uefi_blkdev_read, block_io, bootfs_part->lba_start), true, 0,
                          closure(&general, uefi_bootfs_complete, &general, &aligned_heap, &options));
    }
    UBS->free_pool(handle_buffer);
    return EFI_LOAD_ERROR;  /* should never reach here */
}

void uefi_exit_bs(uefi_mem_map map)
{
    u64 allocated_size;
    u64 map_key;
    map->map_size = 0;
    efi_status status = UBS->get_memory_map(&map->map_size, 0, &map_key, &map->desc_size,
        &map->desc_version);
    assert(status == EFI_BUFFER_TOO_SMALL);
  retry:
    map->map_size += UEFI_MEMDESC_SPARE_COUNT * map->desc_size;
    status = UBS->allocate_pool(efi_loader_data, map->map_size, &map->map);
    assert(!EFI_ERROR(status) && map->map);
    allocated_size = map->map_size;
    status = UBS->get_memory_map(&map->map_size, map->map, &map_key, &map->desc_size,
        &map->desc_version);
    if (status == EFI_BUFFER_TOO_SMALL) {
        uefi_debug("memory map size %ld too small, required %ld", allocated_size, map->map_size);
        UBS->free_pool(map->map);
        goto retry;
    }
    uefi_debug("memory descriptors before exiting boot services:");
#ifdef UEFI_DEBUG
    u64 num_desc = map->map_size / map->desc_size;
    for (u64 i = 0; i < num_desc; i++) {
        efi_memory_desc d = map->map + i * map->desc_size;
        uefi_debug("  type %d, start 0x%lx, size 0x%lx, attributes 0x%lx", d->type,
                   d->physical_start, d->number_of_pages * PAGESIZE, d->attribute);
    }
#endif
    status = UBS->exit_boot_services(uefi_image_handle, map_key);
    if (status == EFI_INVALID_PARAMETER) {
        /* The memory map changed: retrieve it again. */
        map->map_size = allocated_size;
        status = UBS->get_memory_map(&map->map_size, map->map, &map_key, &map->desc_size,
            &map->desc_version);
        assert(status == EFI_SUCCESS);
        status = UBS->exit_boot_services(uefi_image_handle, map_key);
        assert(status == EFI_SUCCESS);
    }
}
