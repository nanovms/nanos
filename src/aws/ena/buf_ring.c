#include <kernel.h>
#include <page.h>
#include <pci.h>
#include <lwip/pbuf.h>
#include "ena.h"
#include "buf_ring.h"

#define powerof2(x) ((((x)-1)&(x))==0)

struct buf_ring *buf_ring_alloc(int count, heap h)
{
    struct buf_ring *br;

    assert(powerof2(count)); // buf ring must be size power of 2

    br = allocate_zero(h, sizeof(struct buf_ring) + count*sizeof(caddr_t));
    assert(br != INVALID_ADDRESS);

    br->br_size = br->br_prod_size = br->br_cons_size = count;
    br->br_prod_mask = br->br_cons_mask = count-1;
    br->br_prod_head = br->br_cons_head = 0;
    br->br_prod_tail = br->br_cons_tail = 0;

    return (br);
}

void buf_ring_free(struct buf_ring *br, heap h)
{
    deallocate(h, br, sizeof(struct buf_ring) + br->br_size*sizeof(caddr_t));
}
