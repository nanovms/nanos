#ifndef DMA_H_
#define DMA_H_

heap heap_dma(void);

#ifdef DMA_BUFFERING

void dma_init(kernel_heaps kh);

sg_io dma_new_reader(heap h, sg_io_func read, void *priv);
sg_io dma_new_writer(heap h, sg_io_func write, void *priv);

#else

static inline void dma_init(void *arg) {}

#endif

#endif
