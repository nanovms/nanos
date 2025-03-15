macro define offsetof(t, f) (size_t)&((t *)0)->f
macro define container_of(p, t, f) (t *)((void *)p - offsetof(t, f))

source tools/nanos_gdb.py

