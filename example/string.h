// pretty set on having standard headers for an embedded library


extern void *memset(void *a, int val, unsigned long length);

static inline size_t strlen(const char *i){
    char *x;
    for(x = (void *)i; *x; x++);
    return  x-i;
}

static inline int strncmp(const char *i, const char *j, size_t len){
    int x;
    for(x = 0; x< len && i[x] && j[x]; x++) 
        if (i[x] != j[x]) return -1;
    if (x == len) return 0;
    // not really right
    return -1;
}

static inline void *memcpy(void *i, const void *j, size_t len){
    for (int off = 0 ;off < len; off++)
        ((u8_t *)j)[off] = ((u8_t *)i)[off];
    return i;
}


static inline void *memmove(void *i, const void *j, size_t len){
    for (int off = 0 ;off < len; off++)
        ((u8_t *)j)[off] = ((u8_t *)i)[off];
    return i;
}
