#include <runtime.h>
#include <path.h>
#include <list.h>
#include <stringtok.h>
#include <string.h>

char *canonicalize_path(heap h, buffer cwd, buffer input) {
    struct list out;

    list_init(&out);

    /*
     * If we have a relative path, we need to canonicalize
     * the working directory and insert it into the stack.
     */
    if (buffer_length(input) && peek_char(input) != PATH_SEPARATOR) {
        // Make a copy of the working directory
        char *path = allocate(h, (buffer_length(cwd) + 1) * sizeof(char));
        runtime_memcpy(path, buffer_ref(cwd, 0), buffer_length(cwd) + 1);

        // Setup tokenizer
        char *pch;
        char *save;
        pch = strtok_r(path, PATH_SEPARATOR_STRING, &save);

        // Start tokenizing
        while (pch != 0) {
            // Make copies of the path elements
            char *s = allocate(h, sizeof(char) * (runtime_strlen(pch) + 1));
            struct path_list *pl = allocate(h, sizeof(*pl));
            runtime_memcpy(s, pch, runtime_strlen(pch) + 1);
            pl->s = s;

            // And push them
            list_push_back(&out, &pl->elem);
            pch = strtok_r(0, PATH_SEPARATOR_STRING, &save);
        }
        deallocate(h, path, (buffer_length(cwd) + 1) * sizeof(char));
    }

    // Similarly, we need to push the elements from the new path
    char *path = allocate(h, (buffer_length(input) + 1) * sizeof(char));
    runtime_memcpy(path, buffer_ref(input, 0), buffer_length(input) + 1);

    // Initialize the tokenizer...
    char *pch;
    char *save;
    pch = strtok_r(path, PATH_SEPARATOR_STRING, &save);

    /*
     * Tokenize the path, this time, taking care to properly
     * handle .. and . to represent up (stack pop) and current
     * (do nothing)
     */
    while (pch != 0) {
        if (!strcmp(pch, PATH_UP)) {
            // Pop
            if (!list_empty(&out)) {
                struct list *elem = list_pop_back(&out);
                if (elem) {
                    struct path_list *n = struct_from_list(elem,
                                struct path_list *, elem);
                    deallocate(h, n->s, runtime_strlen(n->s) + 1);
                    deallocate(h, n, sizeof(*n));
                }
            }
        } else if (!strcmp(pch, PATH_DOT)) {
            // Do nothing
        } else {
            // Push
            char *s = allocate(h, sizeof(char) * (runtime_strlen(pch) + 1));
            struct path_list *pl = allocate(h, sizeof(*pl));
            runtime_memcpy(s, pch, runtime_strlen(pch) + 1);
            pl->s = s;
            list_push_back(&out, &pl->elem);
        }
        pch = strtok_r(0, PATH_SEPARATOR_STRING, &save);
    }
    deallocate(h, path, (buffer_length(input) + 1) * sizeof(char));

    // Calculate the size of the path string
    // TODO: fold this into the previous loop
    u64 size = 0;
    struct list *elem;
    list_foreach(&out, elem) {
        struct path_list *item = struct_from_list(elem, struct path_list *, elem);
        size += runtime_strlen(item->s) + 1;
    }

    // join the list together to form the final path
    char *output = allocate(h, sizeof(char) * (size + 1));
    char *output_offset = output;
    if (size == 0) {
        // fixup empty path to be "/"
        deallocate(h, output, sizeof(char));
        output = allocate(h, sizeof(char) * 2);
        output[0] = PATH_SEPARATOR;
        output[1] = '\0';
    } else {
        // otherwise, append
        list_foreach(&out, elem) {
            struct path_list *item = struct_from_list(elem, struct path_list *, elem);
            output_offset[0] = PATH_SEPARATOR;
            output_offset++;
            runtime_memcpy(output_offset, item->s, runtime_strlen(item->s) + 1);
            output_offset += runtime_strlen(item->s);
        }
    }

    // TODO: the list 'out' has a bunch of stuff that we need to free
    // return to this when deallocate doesn't need to take the length of the data

    return output;
}
