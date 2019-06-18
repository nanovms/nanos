#pragma once

#include <runtime/runtime.h>

typedef closure_type(storage_attach, void, block_io, block_io, u64);

void init_storage(kernel_heaps kh, storage_attach);
