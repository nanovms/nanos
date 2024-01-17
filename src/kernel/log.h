#define TRACE_OTHER         U64_FROM_BIT(0)
#define TRACE_THREAD_RUN    U64_FROM_BIT(1)
#define TRACE_PAGE_FAULT    U64_FROM_BIT(2)

u64 trace_get_flags(value v);

typedef struct klog_dump {
    u8 header[4];
    u64 boot_id;
    s32 exit_code;
    char msgs[KLOG_DUMP_SIZE - 16]; /* total size of the struct must match KLOG_DUMP_SIZE */
} __attribute__((packed)) *klog_dump;

void klog_write(const char *s, bytes count);

void klog_disk_setup(u64 disk_offset, storage_req_handler req_handler);
void klog_set_boot_id(u64 id);
void klog_load(klog_dump dest, status_handler sh);
void klog_save(int exit_code, status_handler sh);
void klog_dump_clear(void);
