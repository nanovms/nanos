#define  P9_NOTAG       ((u16)-1)
#define  P9_NOFID       ((u32)-1)
#define  P9_NONUNAME    ((u32)-1)

#define P9_IOHDR_SIZE   23  /* maximum header size for read/write requests */

#define P9_GETATTR_MODE     U64_FROM_BIT(0)
#define P9_GETATTR_NLINK    U64_FROM_BIT(1)
#define P9_GETATTR_UID      U64_FROM_BIT(2)
#define P9_GETATTR_GID      U64_FROM_BIT(3)
#define P9_GETATTR_RDEV     U64_FROM_BIT(4)
#define P9_GETATTR_ATIME    U64_FROM_BIT(5)
#define P9_GETATTR_MTIME    U64_FROM_BIT(6)
#define P9_GETATTR_CTIME    U64_FROM_BIT(7)
#define P9_GETATTR_INO      U64_FROM_BIT(8)
#define P9_GETATTR_SIZE     U64_FROM_BIT(9)
#define P9_GETATTR_BLOCKS   U64_FROM_BIT(10)
#define P9_GETATTR_BASIC    (P9_GETATTR_MODE | P9_GETATTR_NLINK | P9_GETATTR_UID |  \
                             P9_GETATTR_GID | P9_GETATTR_RDEV | P9_GETATTR_ATIME |  \
                             P9_GETATTR_MTIME | P9_GETATTR_CTIME | P9_GETATTR_INO | \
                             P9_GETATTR_SIZE | P9_GETATTR_BLOCKS)

#define P9_SETATTR_SIZE U64_FROM_BIT(3)

#define P9_DOTL_AT_REMOVEDIR    0x200

struct p9_string {
    u16 length;
    char str[0];
} __attribute__((packed));

#define p9_strlen(str)  (2 + (str).len)
#define p9_buflen(buf)  (2 + buffer_length(buf))

enum p9_msg_t {
    P9_TSTATFS = 8,
    P9_RSTATFS,
    P9_TLOPEN = 12,
    P9_RLOPEN,
    P9_TLCREATE = 14,
    P9_RLCREATE,
    P9_TSYMLINK = 16,
    P9_RSYMLINK,
    P9_TMKNOD = 18,
    P9_RMKNOD,
    P9_TREADLINK = 22,
    P9_RREADLINK,
    P9_TGETATTR = 24,
    P9_RGETATTR,
    P9_TSETATTR = 26,
    P9_RSETATTR,
    P9_TREADDIR = 40,
    P9_RREADDIR,
    P9_TFSYNC = 50,
    P9_RFSYNC,
    P9_TMKDIR = 72,
    P9_RMKDIR,
    P9_TRENAMEAT = 74,
    P9_RRENAMEAT,
    P9_TUNLINKAT = 76,
    P9_RUNLINKAT,
    P9_TVERSION = 100,
    P9_RVERSION,
    P9_TATTACH = 104,
    P9_RATTACH,
    P9_TWALK = 110,
    P9_RWALK,
    P9_TREAD = 116,
    P9_RREAD,
    P9_TWRITE = 118,
    P9_RWRITE,
    P9_TCLUNK = 120,
    P9_RCLUNK,
};

#define P9_QID_TYPE_SYMLINK 0x02
#define P9_QID_TYPE_DIR     0x80

struct p9_qid {
    u8 type;
    u32 version;
    u64 path;
} __attribute__((packed));

struct p9_msg_hdr {
    u32 size;
    u8 type;
    u16 tag;
} __attribute__((packed));

#define p9_fill_hdr(hdr, s, ty, ta) do {    \
    (hdr)->size = s;                        \
    (hdr)->type = ty;                       \
    (hdr)->tag = ta;                        \
} while (0)

#define p9_fill_req_hdr(xaction, ty, ta)    \
    p9_fill_hdr(&(xaction)->req.hdr, sizeof((xaction)->req), ty, ta)

struct p9_lerror {
    struct p9_msg_hdr hdr;
    u32 ecode;
} __attribute__((packed));

union p9_minimal_resp {
    struct p9_msg_hdr hdr;
    struct p9_lerror err;
};

union p9_qid_resp {
    struct {
        struct p9_msg_hdr hdr;
        struct p9_qid qid;
    } __attribute__((packed));
    struct p9_lerror err;
};

struct p9_version_req {
    struct p9_msg_hdr hdr;
    u32 msize;
    struct p9_string version;
} __attribute__((packed));

union p9_version_resp {
    struct {
        struct p9_msg_hdr hdr;
        u32 msize;
        struct p9_string version;
    } __attribute__((packed));
    struct p9_lerror err;
};

struct p9_statfs {
    struct {
        struct p9_msg_hdr hdr;
        u32 fid;
    } __attribute__((packed)) req;
    union {
        struct {
            struct p9_msg_hdr hdr;
            u32 type;
            u32 bsize;
            u64 blocks;
            u64 bfree;
            u64 bavail;
            u64 files;
            u64 ffree;
            u64 fsid;
            u32 namelen;
        } __attribute__((packed));
        struct p9_lerror err;
    } resp;
};

struct p9_lopen {
    struct {
        struct p9_msg_hdr hdr;
        u32 fid;
        u32 flags;
    } __attribute__((packed)) req;
    union {
        struct {
            struct p9_msg_hdr hdr;
            struct p9_qid qid;
            u32 iounit;
        } __attribute__((packed));
        struct p9_lerror err;
    } resp;
};

union p9_lcreate_resp {
    struct {
        struct p9_msg_hdr hdr;
        struct p9_qid qid;
        u32 iounit;
    } __attribute__((packed));
    struct p9_lerror err;
};

struct p9_readlink {
    struct {
        struct p9_msg_hdr hdr;
        u32 fid;
    } __attribute__((packed)) req;
    union {
        struct {
            struct p9_msg_hdr hdr;
            struct p9_string target;
        } __attribute__((packed));
        struct p9_lerror err;
    } resp;
};

struct p9_getattr {
    struct {
        struct p9_msg_hdr hdr;
        u32 fid;
        u64 request_mask;
    } __attribute__((packed)) req;
    union {
        struct {
            struct p9_msg_hdr hdr;
            u64 valid;
            struct p9_qid qid;
            u32 mode;
            u32 uid;
            u32 gid;
            u64 nlink;
            u64 rdev;
            u64 size;
            u64 blksize;
            u64 blocks;
            u64 atime_sec;
            u64 atime_nsec;
            u64 mtime_sec;
            u64 mtime_nsec;
            u64 ctime_sec;
            u64 ctime_nsec;
            u64 btime_sec;
            u64 btime_nsec;
            u64 gen;
            u64 data_version;
        } __attribute__((packed));
        struct p9_lerror err;
    } resp;
};

struct p9_setattr {
    struct {
        struct p9_msg_hdr hdr;
        u32 fid;
        u32 valid;
        u32 mode;
        u32 uid;
        u32 gid;
        u64 size;
        u64 atime_sec;
        u64 atime_nsec;
        u64 mtime_sec;
        u64 mtime_nsec;
    } __attribute__((packed)) req;
    union p9_minimal_resp resp;
};

typedef struct p9_readdir_entry {
    struct p9_qid qid;
    u64 offset;
    u8 type;
    struct p9_string name;
} __attribute__((packed)) *p9_readdir_entry;

struct p9_readdir {
    struct {
        struct p9_msg_hdr hdr;
        u32 fid;
        u64 offset;
        u32 count;
    } __attribute__((packed)) req;
    union {
        struct {
            struct p9_msg_hdr hdr;
            u32 count;
            struct p9_readdir_entry data[0];
        } __attribute__((packed));
        struct p9_lerror err;
    } resp;
};

struct p9_fsync {
    struct {
        struct p9_msg_hdr hdr;
        u32 fid;
        u32 datasync;
    } __attribute__((packed)) req;
    union p9_minimal_resp resp;
};

typedef union p9_qid_resp *p9_symlink_resp;
typedef union p9_qid_resp *p9_mknod_resp;
typedef union p9_qid_resp *p9_attach_resp;
typedef union p9_qid_resp *p9_mkdir_resp;

struct p9_walk_req {
    struct p9_msg_hdr hdr;
    u32 fid;
    u32 newfid;
    u16 nwname;
} __attribute__((packed));

union p9_walk_resp {
    struct {
        struct p9_msg_hdr hdr;
        u16 nwqid;
        struct p9_qid wqid[0];
    } __attribute__((packed));
    struct p9_lerror err;
};

typedef union p9_minimal_resp *p9_renameat_resp;
typedef union p9_minimal_resp *p9_unlinkat_resp;

struct p9_clunk {
    struct {
        struct p9_msg_hdr hdr;
        u32 fid;
    } __attribute__((packed)) req;
    union p9_minimal_resp resp;
};

struct p9_statfs_resp {
    u32 type;
    u32 bsize;
    u64 blocks;
    u64 bfree;
    u64 bavail;
    u64 files;
    u64 ffree;
    u64 fsid;
    u32 namelen;
};

struct p9_getattr_resp {
    u64 valid;
    struct p9_qid qid;
    u32 mode;
    u32 uid;
    u32 gid;
    u64 nlink;
    u64 rdev;
    u64 size;
    u64 blksize;
    u64 blocks;
    timestamp atime;
    timestamp mtime;
    timestamp ctime;
};

struct p9_read {
    struct {
        struct p9_msg_hdr hdr;
        u32 fid;
        u64 offset;
        u32 count;
    } __attribute__((packed)) req;
    union {
        struct {
            struct p9_msg_hdr hdr;
            u32 count;
            u8 data[0];
        } __attribute__((packed));
        struct p9_lerror err;
    } resp;
};

struct p9_write_req {
    struct p9_msg_hdr hdr;
    u32 fid;
    u64 offset;
    u32 count;
    u8 data[0];
} __attribute__((packed));

union p9_write_resp {
    struct {
        struct p9_msg_hdr hdr;
        u32 count;
    } __attribute__((packed));
    struct p9_lerror err;
};

void p9_create_fs(heap h, void *transport, boolean readonly, filesystem_complete complete);

void p9_strcpy(struct p9_string *dest, sstring str);
void p9_bufcpy(struct p9_string *dest, buffer b);
int p9_strcmp(struct p9_string *s1, sstring s2);

fs_status p9_parse_minimal_resp(u8 req_type, union p9_minimal_resp *resp, u32 resp_len);
fs_status p9_parse_qid_resp(u8 req_type, union p9_qid_resp *resp, u32 resp_len, u64 *qid);
fs_status p9_ecode_to_fs_status(u32 ecode);
