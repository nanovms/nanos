#include <kernel.h>
#include <io.h>
#ifdef KERNEL
#include <apic.h>
#endif

#define SERIAL_TX_RING_ORDER 16
#define SERIAL_TX_RING_SIZE  (U64_FROM_BIT(SERIAL_TX_RING_ORDER))
#define BASE                 0x3f8
#define SERIAL_IRQ           4

struct serial_ring;
static boolean serial_buffered_tx = false;

void serial_init(void)
{
    out8(BASE+3, 0x80);         // dlab
    out8(BASE+0, 0x0c);         // 9600
    out8(BASE+1, 0x0);          // divisor latch
    out8(BASE+3, 0x3);          // 8n1
    out8(BASE+2, 0xc7);         // fifo control
    out8(BASE+5, 0xc7);         // dtr, rts, out2
}

static inline boolean tx_avail(void) {
    return in8(BASE + 5) & 0x20;
}

#ifdef KERNEL
typedef struct serial_ring {
    struct spinlock lock;
    buffer buf;
    u64 head;
    u64 tail;
} *serial_ring;

static serial_ring serial_tx_ring;

static inline u8 *tx_ring_ref(u64 n)
{
    return buffer_ref(serial_tx_ring->buf, n & MASK(SERIAL_TX_RING_ORDER));
}

static inline boolean tx_ring_empty(void)
{
    return serial_tx_ring->tail == serial_tx_ring->head;
}

static void update_tx_int(void)
{
    static boolean enabled = false;
    boolean enable = !tx_ring_empty();
    if (enable != enabled) {
        out8(BASE+1, enable ? 2 : 0);
        enabled = enable;
    }
}

static void service_tx_ring(void)
{
    while (tx_avail() && !tx_ring_empty()) {
        u64 n = serial_tx_ring->head++;
        u8 *cp = tx_ring_ref(n);
        out8(BASE, *cp);
    }
    update_tx_int();
}

static void flush_tx_ring(void)
{
    while (!tx_ring_empty()) {
        u64 n = serial_tx_ring->head++;
        u8 *cp = tx_ring_ref(n);
        while (!tx_avail())
            kern_pause();
        out8(BASE, *cp);
    }
}

static void serial_tx_queue(char c)
{
    u64 flags = spin_lock_irq(&serial_tx_ring->lock);
    while (serial_tx_ring->tail - serial_tx_ring->head >= SERIAL_TX_RING_SIZE) {
        service_tx_ring();
        kern_pause();
    }
    u8 *cp = buffer_ref(serial_tx_ring->buf, serial_tx_ring->tail & MASK(SERIAL_TX_RING_ORDER));
    *cp = c;
    serial_tx_ring->tail++;
    service_tx_ring();
    spin_unlock_irq(&serial_tx_ring->lock, flags);
}

closure_function(0, 0, void, serial_interrupt)
{
    spin_lock(&serial_tx_ring->lock);
    service_tx_ring();
    spin_unlock(&serial_tx_ring->lock);
}
                 
void serial_enable_buffered_output(heap h)
{
    serial_tx_ring = allocate(h, sizeof(*serial_tx_ring));
    assert(serial_tx_ring != INVALID_ADDRESS);
    serial_tx_ring->buf = allocate_buffer(h, SERIAL_TX_RING_SIZE);
    assert(serial_tx_ring->buf != INVALID_ADDRESS);
    spin_lock_init(&serial_tx_ring->lock);
    serial_tx_ring->head = serial_tx_ring->tail = 0;
    ioapic_register_int(SERIAL_IRQ, closure(h, serial_interrupt), "serial");
    serial_buffered_tx = true;
}

void serial_flush_and_disable_buffered_output(void)
{
    if (!serial_buffered_tx)
        return;
    serial_buffered_tx = false;
    assert(serial_tx_ring);
    u64 flags = spin_lock_irq(&serial_tx_ring->lock);
    out8(BASE+1, 0);            /* disable ints */
    flush_tx_ring();
    spin_unlock_irq(&serial_tx_ring->lock, flags);
}
#endif

/* This floods the ftrace buffers when user is outputting lots of data */
NOTRACE
void serial_putchar(char c)
{
    if (!serial_buffered_tx) {
        while (!tx_avail())
            kern_pause();
        out8(BASE, c);
        return;
    }
#ifdef KERNEL
    serial_tx_queue(c);
#endif
}
