#include <core/core.h>

typedef struct demux {
    struct heap h;
    int min, max;
    heap children[];
} *demux;


static void *free(heap h, bits size)
{
}

static void *alloc(heap h, bits size)
{
}


heap allocate_demux_size(heap parent)
{
}

