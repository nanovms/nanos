typedef struct klog_dump {
    u8 header[4];
    u64 boot_id;
    s32 exit_code;
    char msgs[KLOG_DUMP_SIZE - 16]; /* total size of the struct must match KLOG_DUMP_SIZE */
} __attribute__((packed)) *klog_dump;

void klog_write(const char *s, bytes count);

static inline void klog_print(const char *s)
{
    klog_write(s, runtime_strlen(s));
}

void klog_disk_setup(u64 disk_offset, block_io disk_read, block_io disk_write);
void klog_set_boot_id(u64 id);
void klog_load(klog_dump dest, status_handler sh);
void klog_save(int exit_code, status_handler sh);
void klog_dump_clear(void);
