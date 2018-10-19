#pragma once

#include <runtime.h>
#include <buffer.h>
#include <list.h>

#define PATH_SEPARATOR '/'
#define PATH_UP ".."
#define PATH_DOT "."
#define PATH_SEPARATOR_STRING "/"

struct path_list {
    char *s;
    struct list elem;
};

extern char *canonicalize_path(heap, buffer, buffer);
