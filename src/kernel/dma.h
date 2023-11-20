#ifndef DMA_H_
#define DMA_H_

heap heap_dma(void);

#ifdef DMA_BUFFERING

void dma_init(kernel_heaps kh);
void dma_sg_io(sg_io op, sg_list sg, range r, boolean write, status_handler completion);

#else

static inline void dma_init(void *arg) {}

static inline void dma_sg_io(sg_io op, sg_list sg, range r, boolean write,
                             status_handler completion)
{
    apply(op, sg, r, completion);
}

#endif

static inline void dma_sg_read(sg_io op, sg_list sg, range r, status_handler completion)
{
    dma_sg_io(op, sg, r, false, completion);
}

static inline void dma_sg_write(sg_io op, sg_list sg, range r, status_handler completion)
{
    dma_sg_io(op, sg, r, true, completion);
}

#endif
