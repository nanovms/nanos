#include <kernel.h>
#include <io.h>
#include <pci.h>
#include "console.h"
#include "vga.h"

/*
 * See
 * - https://wiki.osdev.org/VGA_Hardware
 * - https://wiki.osdev.org/Text_mode
 * - https://wiki.osdev.org/Text_Mode_Cursor
 *
 * Refer also to vga_*() functions in FreeBSD sys/dev/fb/vga.c
 */

#ifdef VGA_DEBUG
#include "serial.h"

static void vga_debug_sstring(sstring format, ...)
{
    static char buf[PAGESIZE * 4];

    buffer b = alloca_wrap_buffer(buf, sizeof(buf));
    b->end = 0;

    vlist a;
    vstart(a, format);
    vbprintf(b, format, &a);

    foreach_character(_, c, b) {
        serial_putchar(c);
    }
}
#define vga_debug(fmt, ...) vga_debug_sstring(ss(fmt), ##__VA_ARGS__)
#else
#define vga_debug(...) do { } while(0)
#endif // VGA_DEBUG

#define VGA_BUF_BASE            0xb8000
#define VGA_BUF_SIZE            0x08000

#define VGA_ATTR(fc, bc)        ((((bc) & 0xf) << 4) | ((fc) & 0xf))

/* white on black */
#define VGA_CONSOLE_ATTR        VGA_ATTR(7, 0)

struct vga_console_driver {
    struct console_driver c;    // should be first

    u32 crtc_addr;              // CRTC I/O port
    u16 *buffer;                // screen buffer
    int buffer_size;            // screen buffer size (chars)
    int width;                  // screen width
    int height;                 // screen height
    int cur_x, cur_y;           // current cursor position

    /*
     * Mode 3 screen size is 80x25 which requires 80x25x2 = 4000 bytes of video memory
     * Available VGA memory is bigger (32Kb) so we use it as a circular line buffer
     */
    int y_offset;               // visible screen start
    int max_lines;              // max buffer lines
};

static void vga_get_cursor(struct vga_console_driver *d, int *x, int *y)
{
    u16 off;

    out8(d->crtc_addr, 14);
    off = in8(d->crtc_addr + 1);
    out8(d->crtc_addr, 15);
    off = (off << 8) | in8(d->crtc_addr + 1);

    *x = off % d->width;
    *y = off / d->width;
    vga_debug("%s: off = %d: (x, y) = (%d, %d)\n", func_ss, off, *x, *y);
}

static void vga_set_cursor(struct vga_console_driver *d, int x, int y)
{
    u16 off = (d->y_offset + y) * d->width + x;
    vga_debug("%s: (x, y) = (%d, %d): off = %d\n", func_ss, x, y, off);

    out8(d->crtc_addr, 14);
    out8(d->crtc_addr + 1, off >> 8);
    out8(d->crtc_addr, 15);
    out8(d->crtc_addr + 1, off & 0xff);
}

static void vga_set_offset(struct vga_console_driver *d, int y)
{
    u16 off = y * d->width;
    vga_debug("%s: y = %d: off = %d\n", func_ss, y, off);

    out8(d->crtc_addr, 12);
    out8(d->crtc_addr + 1, off >> 8);
    out8(d->crtc_addr, 13);
    out8(d->crtc_addr + 1, off & 0xff);
}

/*
 * Add new line
 *
 * Change y_offset and maintain circular screen buffer appropriately.
 */
static void vga_newline(struct vga_console_driver *d)
{
    // add new line
    d->cur_y++;
    if (d->cur_y < d->height)
        return;

    int add_lines = d->cur_y - d->height + 1;
    d->y_offset += add_lines;
    d->cur_y -= add_lines;
    vga_debug("%s: add lines %d\n", func_ss, add_lines);

    // check circular buffer wrapping
    if (d->y_offset + d->cur_y >= d->max_lines) {
        int idx = d->y_offset * d->width;
        assert(add_lines < d->height);
        int copy_chars = (d->height - add_lines) * d->width;
        d->y_offset = 0;
        vga_debug("%s: copy chars %d\n", func_ss, copy_chars);
        runtime_memcpy(d->buffer, d->buffer + idx, copy_chars * sizeof(*d->buffer));
    }

    // fill new lines with spaces
    int fill_offset = (d->y_offset + d->cur_y) * d->width;
    int fill_chars = add_lines * d->width;
    vga_debug("%s: y_offset %d, cur_y %d, fill offset %d, fill chars %d\n",
              func_ss, d->y_offset, d->cur_y, fill_offset, fill_chars);
    while (fill_chars--) {
        d->buffer[fill_offset++] = ' ' | (VGA_CONSOLE_ATTR << 8);
    }

    vga_set_offset(d, d->y_offset);
}

static void vga_console_write(void *_d, const char *s, bytes count)
{
    struct vga_console_driver *d = (struct vga_console_driver *) _d;

    for (; count--; s++) {
        switch (*s) {
        case '\n':
            vga_newline(d);
            /* FALLTHRU */
	case '\r':
            d->cur_x = 0;
	    continue;
	case '\b':
            if (d->cur_x > 0)
                d->cur_x--;
            continue;
        }

        int idx = (d->y_offset + d->cur_y) * d->width + d->cur_x;
        assert(idx < d->buffer_size);
        u16 val = *s | (VGA_CONSOLE_ATTR << 8);
        d->buffer[idx] = val;

        d->cur_x++;
        if (d->cur_x >= d->width) {
            d->cur_x = 0;
            vga_newline(d);
        }
    }

    vga_debug("%s: new cursor position: (%d, %d)\n", func_ss, d->cur_x, d->cur_y);
    vga_set_cursor(d, d->cur_x, d->cur_y);
}

closure_function(2, 1, boolean, vga_pci_probe,
                 heap, general, heap, virtual,
                 pci_dev _d)
{
    if ((pci_get_class(_d) != PCIC_DISPLAY) || (pci_get_subclass(_d) != PCIS_VGA))
        return false;

    vga_debug("%s\n", func_ss);
    /* Check misc output register to see if display buffer is set up.
     * This whole byte appears to be 0 on the UEFI systems using GOP that I tested,
     * but to be safe, just check bit 1, "RAM Enable" 
     * See http://www.osdever.net/FreeVGA/vga/extreg.htm */
    if ((in8(0x3cc) & 0x02) == 0) {
        vga_debug("%s: display buffer not enabled\n", func_ss);
        return false;
    }
    struct vga_console_driver *d = allocate_zero(bound(general), sizeof(*d));
    assert(d != INVALID_ADDRESS);
    d->c.write = vga_console_write;
    d->c.name = ss("vga");
    d->crtc_addr = 0x3d4;

    /* Check if device is initialized in VGA mode 3 */
    d->width = 80;
    d->height = 25;
    vga_get_cursor(d, &d->cur_x, &d->cur_y);
    vga_debug("%s: current cursor position: (%d, %d)\n", func_ss, d->cur_x, d->cur_y);
    if ( d->cur_y >= d->height) {
        deallocate(bound(general), d, sizeof(*d));
        return false;
    }

    d->buffer = allocate(bound(virtual), VGA_BUF_SIZE);
    d->buffer_size = VGA_BUF_SIZE / sizeof(*d->buffer);
    map(u64_from_pointer(d->buffer), VGA_BUF_BASE, VGA_BUF_SIZE,
        pageflags_writable(pageflags_device()));
    d->y_offset = 0;
    d->max_lines = d->buffer_size / d->width;
    vga_debug("%s: max buffer lines %d\n", func_ss, d->max_lines);
    vga_set_offset(d, d->y_offset);

    attach_console_driver(&d->c);
    return true;
}

void vga_pci_register(kernel_heaps kh)
{
    heap h = heap_general(kh);
    register_pci_driver(closure(h, vga_pci_probe, h, (heap)heap_virtual_page(kh)), 0);
}
