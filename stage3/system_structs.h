// structs that live on the user-kernel boundary

struct stat
  {
    u64 st_dev;		
      u64 st_ino;		//16
      u32 st_nlink; //20
      u32 pad; // size is off by 8  in this layout - double mode and link?
      u32 st_mode;	//28
      u32 st_uid;		 //32
      u32 st_gid;		//36
      u64 st_rdev; //44
      u32 pad2; // size is off by 8  in this layout - double mode and link?
      u64 st_size; //48	
      u64 st_blksize;	
      u64 st_blocks;	
} __attribute__((packed));
// better to just do this by offset

#define S_IFMT  00170000
#define S_IFSOCK 0140000
#define S_IFLNK	 0120000
#define S_IFREG  0100000
#define S_IFBLK  0060000
#define S_IFDIR  0040000
#define S_IFCHR  0020000
#define S_IFIFO  0010000
#define S_ISUID  0004000
#define S_ISGID  0002000
#define S_ISVTX  0001000

// take this from filesystem
struct utsname {
    char sysname[65];    
    char nodename[65];   
    char release[65];    
    char version[65];    
    char machine[65];    
};
    
typedef struct iovec {
    void *address;
    u64 length;
} *iovec;

#define EPERM           1               /* Operation not permitted */
#define ENOENT          2               /* No such file or directory */
#define ESRCH           3               /* No such process */
#define EINTR           4               /* Interrupted system call */
#define EIO             5               /* Input/output error */
#define ENXIO           6               /* Device not configured */
#define E2BIG           7               /* Argument list too long */
#define ENOEXEC         8               /* Exec format error */
#define EBADF           9               /* Bad file descriptor */
#define ECHILD          10              /* No child processes */
#define EAGAIN          11              /* Resource deadlock avoided */
#define ENOMEM          12              /* Cannot allocate memory */
#define EACCES          13              /* Permission denied */
#define EFAULT          14              /* Bad address */
#define EBUSY           16              /* Device busy */
#define EEXIST          17              /* File exists */
#define EXDEV           18              /* Cross-device link */
#define ENODEV          19              /* Operation not supported by device */
#define ENOTDIR         20              /* Not a directory */
#define EISDIR          21              /* Is a directory */
#define EINVAL          22              /* Invalid argument */
#define ENFILE          23              /* Too many open files in system */
#define EMFILE          24              /* Too many open files */
#define ENOTTY          25              /* Inappropriate ioctl for device */
#define EFBIG           27              /* File too large */
#define ENOSPC          28              /* No space left on device */
#define ESPIPE          29              /* Illegal seek */
#define EROFS           30              /* Read-only filesystem */
#define EMLINK          31              /* Too many links */
#define EPIPE           32              /* Broken pipe */

#define O_RDONLY	00000000
#define O_WRONLY	00000001
#define O_RDWR		00000002
#define O_CREAT		00000100
#define O_TRUNC		00001000
#define O_APPEND	00002000
#define O_NONBLOCK	00004000

#define AT_NULL         0               /* End of vector */
#define AT_IGNORE       1               /* Entry should be ignored */
#define AT_EXECFD       2               /* File descriptor of program */
#define AT_PHDR         3               /* Program headers for program */
#define AT_PHENT        4               /* Size of program header entry */
#define AT_PHNUM        5               /* Number of program headers */
#define AT_PAGESZ       6               /* System page size */
#define AT_BASE         7               /* Base address of interpreter */
#define AT_FLAGS        8               /* Flags */
#define AT_ENTRY        9               /* Entry point of program */
#define AT_NOTELF       10              /* Program is not ELF */
#define AT_UID          11              /* Real uid */
#define AT_EUID         12              /* Effective uid */
#define AT_GID          13              /* Real gid */
#define AT_EGID         14              /* Effective gid */
#define AT_CLKTCK       17              /* Frequency of times() */

#define MAP_FIXED 0x10
#define MAP_ANONYMOUS 0x20
#define MAP_PRIVATE	0x02

// straight from linux
#define ARCH_SET_GS 0x1001
#define ARCH_SET_FS 0x1002
#define ARCH_GET_FS 0x1003
#define ARCH_GET_GS 0x1004

struct timespec {
	u64 tv_sec;
	u64 tv_nsec;
};

// straight from linux
#define FUTEX_WAIT		0
#define FUTEX_WAKE		1
#define FUTEX_FD		2
#define FUTEX_REQUEUE		3
#define FUTEX_CMP_REQUEUE	4
#define FUTEX_WAKE_OP		5
#define FUTEX_LOCK_PI		6
#define FUTEX_UNLOCK_PI		7
#define FUTEX_TRYLOCK_PI	8
#define FUTEX_WAIT_BITSET	9
#define FUTEX_WAKE_BITSET	10
#define FUTEX_WAIT_REQUEUE_PI	11
#define FUTEX_CMP_REQUEUE_PI	12
