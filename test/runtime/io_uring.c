#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/eventfd.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <time.h>
#include <unistd.h>

#include "runtime.h"

#ifndef SYS_io_uring_setup
#define SYS_io_uring_setup      425
#endif
#ifndef SYS_io_uring_enter
#define SYS_io_uring_enter      426
#endif
#ifndef SYS_io_uring_register
#define SYS_io_uring_register   427
#endif

#define IORING_SETUP_CQSIZE     (1 << 3)

#define IO_URING_OP_SUPPORTED   (1 << 0)

#define IORING_OFF_SQ_RING  0ULL
#define IORING_OFF_SQES     0x10000000ULL

struct io_sqring_offsets {
    uint32_t head;
    uint32_t tail;
    uint32_t ring_mask;
    uint32_t ring_entries;
    uint32_t flags;
    uint32_t dropped;
    uint32_t array;
    uint32_t resv[3];
};

struct io_cqring_offsets {
    uint32_t head;
    uint32_t tail;
    uint32_t ring_mask;
    uint32_t ring_entries;
    uint32_t overflow;
    uint32_t cqes;
    uint32_t resv[4];
};

struct io_uring_params {
    uint32_t sq_entries;
    uint32_t cq_entries;
    uint32_t flags;
    uint32_t sq_thread_cpu;
    uint32_t sq_thread_idle;
    uint32_t features;
    uint32_t resv[4];
    struct io_sqring_offsets sq_off;
    struct io_cqring_offsets cq_off;
};

struct io_uring_sqe {
    uint8_t opcode;
    uint8_t flags;
    uint16_t ioprio;
    uint32_t fd;
    union {
        uint64_t off;
        uint64_t addr2;
    };
    uint64_t addr;
    uint32_t len;
    union {
        uint32_t rw_flags;
        uint32_t fsync_flags;
        uint16_t poll_events;
        uint32_t sync_range_flags;
        uint32_t msg_flags;
        uint32_t timeout_flags;
        uint32_t accept_flags;
        uint32_t cancel_flags;
    };
    uint32_t user_data;
    union {
        struct {
            uint16_t buf_index;
            uint16_t personality;
        };
        uint64_t __pad2[3];
    };
};

struct io_uring_cqe {
    uint64_t user_data;
    uint32_t res;
    uint32_t flags;
};

struct io_uring_probe_op {
    uint8_t op;
    uint8_t resv;
    uint16_t flags;
    uint32_t resv2;
};

struct io_uring_probe {
    uint8_t last_op;
    uint8_t ops_len;
    uint16_t resv;
    uint32_t resv2[3];
    struct io_uring_probe_op ops[0];
};

struct io_uring_files_update {
    uint32_t offset;
    uint32_t resv;
    int32_t *fds;
};

enum {
    IORING_OP_NOP,
    IORING_OP_READV,
    IORING_OP_WRITEV,
    IORING_OP_FSYNC,
    IORING_OP_READ_FIXED,
    IORING_OP_WRITE_FIXED,
    IORING_OP_POLL_ADD,
    IORING_OP_POLL_REMOVE,
    IORING_OP_SYNC_FILE_RANGE,
    IORING_OP_SENDMSG,
    IORING_OP_RECVMSG,
    IORING_OP_TIMEOUT,
    IORING_OP_TIMEOUT_REMOVE,
    IORING_OP_ACCEPT,
    IORING_OP_ASYNC_CANCEL,
    IORING_OP_LINK_TIMEOUT,
    IORING_OP_CONNECT,
    IORING_OP_FALLOCATE,
    IORING_OP_OPENAT,
    IORING_OP_CLOSE,
    IORING_OP_FILES_UPDATE,
    IORING_OP_STATX,
    IORING_OP_READ,
    IORING_OP_WRITE,
};

#define IORING_FEAT_SINGLE_MMAP (1 << 0)

#define IOSQE_FIXED_FILE    (1 << 0)

#define IORING_TIMEOUT_ABS  (1 << 0)

#define IORING_ENTER_GETEVENTS  (1 << 0)

#define IORING_REGISTER_BUFFERS         0
#define IORING_UNREGISTER_BUFFERS       1
#define IORING_REGISTER_FILES           2
#define IORING_UNREGISTER_FILES         3
#define IORING_REGISTER_EVENTFD         4
#define IORING_UNREGISTER_EVENTFD       5
#define IORING_REGISTER_FILES_UPDATE    6
#define IORING_REGISTER_EVENTFD_ASYNC   7
#define IORING_REGISTER_PROBE           8

#define BUF_SIZE        8192

#define test_assert(expr) do { \
    if (!(expr)) { \
        printf("Error: %s -- failed at %s:%d\n", #expr, __FILE__, __LINE__); \
        exit(EXIT_FAILURE); \
    } \
} while (0)

struct iour {
    struct io_uring_params params;
    int fd;
    uint8_t *rings;
    struct io_uring_sqe *sqes;
    uint32_t *sq_head;
    uint32_t *sq_tail;
    uint32_t sq_mask;
    uint32_t *sq_array;
    uint32_t *cq_head;
    uint32_t *cq_tail;
    uint32_t cq_mask;
    struct io_uring_cqe *cqes;
};

static int iour_init(struct iour *iour, unsigned int entries)
{
    iour->fd = syscall(SYS_io_uring_setup, entries, &iour->params);
    if (iour->fd < 0)
        return iour->fd;

    test_assert(iour->params.features & IORING_FEAT_SINGLE_MMAP);

    /* Exploit the single mmap feature and map both SQ and CQ rings with a
     * single syscall. */
    uint32_t sqring_size = iour->params.sq_off.array +
            iour->params.sq_entries * sizeof(uint32_t);
    uint32_t cqring_size = iour->params.cq_off.cqes +
            iour->params.cq_entries * sizeof(struct io_uring_cqe);
    iour->rings = mmap(0, MAX(sqring_size, cqring_size), PROT_READ | PROT_WRITE,
        MAP_SHARED | MAP_POPULATE, iour->fd, IORING_OFF_SQ_RING);
    test_assert(iour->rings != MAP_FAILED);

    iour->sq_head = (uint32_t *)(iour->rings + iour->params.sq_off.head);
    iour->sq_tail = (uint32_t *)(iour->rings + iour->params.sq_off.tail);
    iour->sq_mask = *(uint32_t *)(iour->rings + iour->params.sq_off.ring_mask);
    iour->sq_array = (uint32_t *)(iour->rings + iour->params.sq_off.array);
    iour->cq_head = (uint32_t *)(iour->rings + iour->params.cq_off.head);
    iour->cq_tail = (uint32_t *)(iour->rings + iour->params.cq_off.tail);
    iour->cq_mask = *(uint32_t *)(iour->rings + iour->params.cq_off.ring_mask);
    iour->cqes =
            (struct io_uring_cqe *)(iour->rings + iour->params.cq_off.cqes);
    iour->sqes = mmap(0, iour->params.sq_entries * sizeof(struct io_uring_sqe),
        PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE, iour->fd,
        IORING_OFF_SQES);
    test_assert(iour->sqes != MAP_FAILED);

    test_assert(iour->params.sq_entries >= entries);
    test_assert(*iour->sq_head == 0 && *iour->sq_tail == 0);
    test_assert(iour->sq_mask == iour->params.sq_entries - 1);
    test_assert(*(uint32_t *)(iour->rings + iour->params.sq_off.flags) == 0);
    test_assert(*(uint32_t *)(iour->rings + iour->params.sq_off.dropped) == 0);
    test_assert(iour->params.cq_entries >= entries);
    test_assert(*iour->cq_head == 0 && *iour->cq_tail == 0);
    test_assert(iour->cq_mask == iour->params.cq_entries - 1);
    test_assert(*(uint32_t *)(iour->rings + iour->params.cq_off.overflow) == 0);

    /* Use some non-trivial ordering of SQEs */
    for (int i = 0; i < iour->params.sq_entries; i++)
        iour->sq_array[i] = iour->params.sq_entries - 1  - i;

    return 0;
}

static struct io_uring_sqe *iour_get_sqe(struct iour *iour)
{
    test_assert(*iour->sq_tail >= *iour->sq_head);
    test_assert(*iour->sq_tail - *iour->sq_head <= iour->params.sq_entries);
    if (*iour->sq_tail == *iour->sq_head + iour->params.sq_entries)
        return NULL;
    return &iour->sqes[iour->sq_array[*iour->sq_tail & iour->sq_mask]];
}

static void iour_setup_sqe(struct iour *iour, uint8_t opcode, int fd,
                           uint64_t addr, uint32_t len, uint64_t offset,
                           uint64_t user_data)
{
    struct io_uring_sqe *sqe = iour_get_sqe(iour);

    test_assert(sqe);
    memset(sqe, 0, sizeof(*sqe));
    sqe->opcode = opcode;
    sqe->fd = fd;
    sqe->addr = addr;
    sqe->len = len;
    sqe->off = offset;
    sqe->user_data = user_data;
    write_barrier();
    (*iour->sq_tail)++;
}

static void iour_setup_nop(struct iour *iour, uint64_t user_data)
{
    iour_setup_sqe(iour, IORING_OP_NOP, 0, 0, 0, 0, user_data);
}

static void iour_setup_readv(struct iour *iour, int fd, struct iovec *iov,
                            uint32_t len, uint64_t offset, uint64_t user_data)
{
    iour_setup_sqe(iour, IORING_OP_READV, fd, (uint64_t)iov, len, offset,
        user_data);
}

static void iour_setup_writev(struct iour *iour, int fd, struct iovec *iov,
                            uint32_t len, uint64_t offset, uint64_t user_data)
{
    iour_setup_sqe(iour, IORING_OP_WRITEV, fd, (uint64_t)iov, len, offset,
        user_data);
}

static void iour_setup_rw_fixed(struct iour *iour, int fd, uint16_t buf_index,
                                bool write, uint8_t *buf, uint32_t len,
                                uint64_t offset, uint64_t user_data)
{
    struct io_uring_sqe *sqe = iour_get_sqe(iour);

    test_assert(sqe);
    memset(sqe, 0, sizeof(*sqe));
    sqe->opcode = write? IORING_OP_WRITE_FIXED : IORING_OP_READ_FIXED;
    sqe->fd = fd;
    sqe->off = offset;
    sqe->addr = (uint64_t)buf;
    sqe->len = len;
    sqe->user_data = user_data;
    sqe->buf_index = buf_index;
    write_barrier();
    (*iour->sq_tail)++;
}

static void iour_setup_poll_add(struct iour *iour, int fd, uint16_t events,
                                uint64_t user_data)
{
    struct io_uring_sqe *sqe = iour_get_sqe(iour);

    test_assert(sqe);
    memset(sqe, 0, sizeof(*sqe));
    sqe->opcode = IORING_OP_POLL_ADD;
    sqe->fd = fd;
    sqe->poll_events = events;
    sqe->user_data = user_data;
    write_barrier();
    (*iour->sq_tail)++;
}

static void iour_setup_poll_remove(struct iour *iour, uint64_t addr,
                                   uint64_t user_data)
{
    iour_setup_sqe(iour, IORING_OP_POLL_REMOVE, 0, addr, 0, 0, user_data);
}

static void iour_setup_poll_fixed_file(struct iour *iour, int fd_index,
                                       uint16_t events, uint64_t user_data)
{
    struct io_uring_sqe *sqe = iour_get_sqe(iour);

    test_assert(sqe);
    memset(sqe, 0, sizeof(*sqe));
    sqe->opcode = IORING_OP_POLL_ADD;
    sqe->flags = IOSQE_FIXED_FILE;
    sqe->fd = fd_index;
    sqe->poll_events = events;
    sqe->user_data = user_data;
    write_barrier();
    (*iour->sq_tail)++;
}

static void iour_setup_timeout(struct iour *iour, struct timespec *ts,
                               uint64_t off, uint32_t flags, uint64_t user_data)
{
    struct io_uring_sqe *sqe = iour_get_sqe(iour);

    test_assert(sqe);
    memset(sqe, 0, sizeof(*sqe));
    sqe->opcode = IORING_OP_TIMEOUT;
    sqe->fd = 0;
    sqe->off = off;
    sqe->addr = (uint64_t)ts;
    sqe->len = 1;
    sqe->timeout_flags = flags;
    sqe->user_data = user_data;
    write_barrier();
    (*iour->sq_tail)++;
}

static void iour_setup_timeout_remove(struct iour *iour, uint64_t addr,
                                      uint64_t user_data)
{
    iour_setup_sqe(iour, IORING_OP_TIMEOUT_REMOVE, 0, addr, 0, 0, user_data);
}

static void iour_setup_close(struct iour *iour, int fd, uint64_t user_data)
{
    iour_setup_sqe(iour, IORING_OP_CLOSE, fd, 0, 0, 0, user_data);
}

static void iour_setup_files_update(struct iour *iour, int *fds, uint32_t len,
                                    uint64_t offset, uint64_t user_data)
{
    iour_setup_sqe(iour, IORING_OP_FILES_UPDATE, 0, (uint64_t)fds, len, offset,
        user_data);
}

static void iour_setup_read(struct iour *iour, int fd, uint8_t *buf,
                            uint32_t len, uint64_t offset, uint64_t user_data)
{
    iour_setup_sqe(iour, IORING_OP_READ, fd, (uint64_t)buf, len, offset,
        user_data);
}

static void iour_setup_write(struct iour *iour, int fd, uint8_t *buf,
                             uint32_t len, uint64_t offset, uint64_t user_data)
{
    iour_setup_sqe(iour, IORING_OP_WRITE, fd, (uint64_t)buf, len, offset,
        user_data);
}

static int iour_submit(struct iour *iour, unsigned int count,
                       unsigned int min_complete)
{
    return syscall(SYS_io_uring_enter, iour->fd, count, min_complete,
        IORING_ENTER_GETEVENTS, NULL);
}

static struct io_uring_cqe *iour_get_cqe(struct iour *iour)
{
    struct io_uring_cqe *cqe;

    read_barrier();
    if (*iour->cq_tail == *iour->cq_head)
        return NULL;
    test_assert(*iour->cq_tail > *iour->cq_head);
    test_assert(*iour->cq_tail - *iour->cq_head <= iour->params.cq_entries);
    cqe = &iour->cqes[*iour->cq_head & iour->cq_mask];
    (*iour->cq_head)++;
    return cqe;
}

static int iour_exit(struct iour *iour)
{
    return close(iour->fd);
}

static void iour_test_basic(void)
{
    struct iour iour;
    struct io_uring_params params;
    int fd;
    struct io_uring_probe *probe;
    const int probe_ops = IORING_OP_WRITE + 1;
    void *ptr;
    struct timespec ts;
    struct io_uring_cqe *cqe;
    int ret;

    test_assert(syscall(SYS_io_uring_setup, 1, NULL) == -1);
    test_assert(errno == EFAULT);

    memset(&iour.params, 0, sizeof(iour.params));
    memset(&params, 0, sizeof(params));

    test_assert(syscall(SYS_io_uring_setup, 0, &params) == -1);
    test_assert(errno == EINVAL);

    params.resv[3] = 1;
    test_assert(syscall(SYS_io_uring_setup, 1, &params) == -1);
    test_assert(errno == EINVAL);
    params.resv[3] = 0;

    /* CQ size smaller than SQ size */
    params.flags = IORING_SETUP_CQSIZE;
    params.cq_entries = 1;
    test_assert(syscall(SYS_io_uring_setup, 2, &params) == -1);
    test_assert(errno == EINVAL);

    params.cq_entries = 8;
    fd = syscall(SYS_io_uring_setup, 1, &params);
    test_assert((fd > 0) && (params.cq_entries == 8));

    ret = syscall(SYS_io_uring_register, fd, -1, NULL, 0);  /* invalid opcode */
    test_assert((ret == -1) && (errno == EINVAL));

    ret = syscall(SYS_io_uring_register, fd, IORING_REGISTER_PROBE, NULL,
        probe_ops);
    test_assert((ret == -1) && (errno == EFAULT));

    probe = malloc(sizeof(*probe) + sizeof(probe->ops[0]) * probe_ops);
    test_assert(probe);
    ret = syscall(SYS_io_uring_register, fd, IORING_REGISTER_PROBE, probe,
        probe_ops);
    test_assert((ret == 0) && (probe->last_op >= probe_ops - 1));
    test_assert(probe->ops_len <= probe_ops);
    for (int i = 0; i < probe->ops_len; i++) {
        switch (probe->ops[i].op) {
        case IORING_OP_NOP:
        case IORING_OP_READV:
        case IORING_OP_WRITEV:
        case IORING_OP_READ_FIXED:
        case IORING_OP_WRITE_FIXED:
        case IORING_OP_POLL_ADD:
        case IORING_OP_POLL_REMOVE:
        case IORING_OP_TIMEOUT:
        case IORING_OP_TIMEOUT_REMOVE:
        case IORING_OP_CLOSE:
        case IORING_OP_FILES_UPDATE:
        case IORING_OP_READ:
        case IORING_OP_WRITE:
            test_assert(probe->ops[i].flags & IO_URING_OP_SUPPORTED);
            break;
        default:
            break;
        }
    }

    ptr = mmap(0, params.sq_off.array, PROT_READ | PROT_WRITE,
        MAP_SHARED | MAP_POPULATE, fd, -1ULL);  /* invalid offset */
    test_assert((ptr == MAP_FAILED) && (errno == EINVAL));

    ptr = mmap(0, -1ULL, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE, fd,
        IORING_OFF_SQ_RING);  /* invalid length */
    test_assert((ptr == MAP_FAILED) && (errno == EINVAL));

    test_assert(close(fd) == 0);

    /* Close file descriptor without having mapped any memory. */
    iour.fd = syscall(SYS_io_uring_setup, 1, &iour.params);
    test_assert(iour.fd > 0);
    test_assert(close(iour.fd) == 0);

    /* Reference io_uring fd from another io_uring, and trigger io_uring context
     * release from invocation of io_uring_enter() on the other io_uring
     * context. */
    test_assert(iour_init(&iour, 1) == 0);
    test_assert(iour.fd > 0);
    fd = syscall(SYS_io_uring_setup, 1, &params);
    test_assert(fd > 0);
    iour_setup_poll_add(&iour, fd, POLLIN, 0);
    test_assert(iour_submit(&iour, 1, 0) == 1);
    test_assert(close(fd) == 0);    /* fdesc refcount is still not zero **/
    iour_setup_poll_remove(&iour, 0, 0);
    test_assert(iour_submit(&iour, 1, 2) == 1);    /* fdesc refcount now zero */
    test_assert(iour_exit(&iour) == 0);

    /* Cancel ongoing poll and timeout requests when closing io_uring file
     * descriptor. */
    test_assert(iour_init(&iour, 2) == 0);
    test_assert(iour.fd > 0);
    fd = syscall(SYS_io_uring_setup, 1, &params);
    test_assert(fd > 0);
    iour_setup_poll_add(&iour, fd, POLLIN, 0);
    ts.tv_sec = 1;
    ts.tv_nsec = 0;
    iour_setup_timeout(&iour, &ts, 0, 0, 0);
    test_assert(iour_submit(&iour, 2, 0) == 2);
    test_assert(iour_exit(&iour) == 0);
    test_assert(close(fd) == 0);

    test_assert(iour_init(&iour, 1) == 0);
    test_assert(iour.fd > 0);
    iour_setup_sqe(&iour, -1, 0, 0, 0, 0, 0);    /* invalid opcode */
    test_assert(iour_submit(&iour, 1, 1) == 1);
    cqe = iour_get_cqe(&iour);
    test_assert(cqe && (cqe->user_data == 0) && (cqe->res == -EINVAL));

    test_assert(iour_submit(&iour, 1, 0) == 0); /* no SQEs available */

    /* CQ overflow */
    for (int i = 0; i <= iour.params.cq_entries; i++) {
        iour_setup_nop(&iour, 0);
        test_assert(iour_submit(&iour, 1, 1) == 1);
    }
    test_assert(*(uint32_t *)(iour.rings + iour.params.cq_off.overflow) == 1);

    test_assert(iour_exit(&iour) == 0);
    test_assert(iour_init(&iour, 1) == 0);
    test_assert(iour.fd > 0);

    /* Invalid SQE index */
    iour.sq_array[*iour.sq_tail] = iour.params.sq_entries;
    iour_setup_nop(&iour, 0);
    test_assert(iour_submit(&iour, 1, 0) == 0);
    test_assert(*(uint32_t *)(iour.rings + iour.params.sq_off.dropped) == 1);

    /* Invalid flags */
    iour_setup_nop(&iour, 0);
    ret = syscall(SYS_io_uring_enter, iour.fd, 1, 1, -1U, NULL);
    test_assert((ret == -1) && (errno == EINVAL));

    test_assert(iour_exit(&iour) == 0);

    /* Try to use the stdin file descriptor as an io_uring. */
    ret = syscall(SYS_io_uring_enter, 0, 0, 0, 0, NULL);
    test_assert((ret == -1) && (errno == EOPNOTSUPP));
}

static void iour_test_readwrite(void)
{
    int fd;
    uint8_t read_buf[BUF_SIZE], write_buf[BUF_SIZE];
    struct iour iour;
    struct io_uring_cqe *cqe;

    memset(&iour.params, 0, sizeof(iour.params));
    test_assert(iour_init(&iour, 1) == 0);

    fd = open("file_rw", O_RDWR | O_CREAT, S_IRWXU);
    test_assert(fd > 0);

    test_assert(iour_submit(&iour, 0, 0) == 0);

    iour_setup_write(&iour, fd, NULL, BUF_SIZE, 0, 123);
    test_assert(iour_submit(&iour, 1, 1) == 1);
    cqe = iour_get_cqe(&iour);
    test_assert(cqe && (cqe->res == -EFAULT) && (cqe->user_data == 123));

    iour_setup_sqe(&iour, -1, fd, (uint64_t)write_buf, BUF_SIZE, 0, 456);
    test_assert(iour_submit(&iour, 1, 1) == 1);
    cqe = iour_get_cqe(&iour);
    test_assert(cqe && (cqe->res == -EINVAL) && (cqe->user_data == 456));

    iour_setup_write(&iour, -fd, write_buf, BUF_SIZE, 0, 789);
    test_assert(iour_submit(&iour, 1, 1) == 1);
    cqe = iour_get_cqe(&iour);
    test_assert(cqe && (cqe->res == -EBADF) && (cqe->user_data == 789));

    for (int i = 0; i < BUF_SIZE; i++)
        write_buf[i] = i & 0xFF;
    iour_setup_write(&iour, fd, write_buf, BUF_SIZE, 0, (uint64_t)read_buf);
    test_assert(iour_submit(&iour, 1, 1) == 1);
    cqe = iour_get_cqe(&iour);
    test_assert(cqe && (cqe->res == BUF_SIZE));
    test_assert(cqe->user_data == (uint64_t)read_buf);

    iour_setup_read(&iour, fd, read_buf, BUF_SIZE, 0, (uint64_t)write_buf);
    test_assert(iour_submit(&iour, 1, 1) == 1);
    cqe = iour_get_cqe(&iour);
    test_assert(cqe && (cqe->res == BUF_SIZE));
    test_assert(cqe->user_data == (uint64_t)write_buf);
    for (int i = 0; i < BUF_SIZE; i++)
        test_assert(read_buf[i] == (i & 0xFF));

    test_assert(iour_exit(&iour) == 0);

    /* Close file descriptor without waiting for CQE. */
    test_assert(iour_init(&iour, 1) == 0);
    iour_setup_read(&iour, fd, read_buf, BUF_SIZE, 0, 0);
    test_assert(iour_submit(&iour, 1, 0) == 1);
    test_assert(iour_exit(&iour) == 0);

    test_assert(close(fd) == 0);
}

static void iour_test_eventfd(void)
{
    int fd;
    struct iour iour;
    int ret;
    int efd;
    uint64_t efd_val;
    struct io_uring_cqe *cqe;
    fd_set select_fd;
    struct timeval timeout;

    fd = open("file_efd", O_RDWR | O_CREAT, S_IRWXU);
    test_assert(fd > 0);

    memset(&iour.params, 0, sizeof(iour.params));
    test_assert(iour_init(&iour, 1) == 0);

    ret = syscall(SYS_io_uring_register, iour.fd, IORING_REGISTER_EVENTFD, NULL,
        1); /* invalid pointer */
    test_assert((ret == -1) && (errno == EFAULT));
    ret = syscall(SYS_io_uring_register, iour.fd, IORING_REGISTER_EVENTFD, &efd,
        0); /* invalid number of file descriptors */
    test_assert((ret == -1) && (errno == EINVAL));
    efd = -1; /* invalid file descriptor */
    ret = syscall(SYS_io_uring_register, iour.fd, IORING_REGISTER_EVENTFD, &efd,
        1);
    test_assert((ret == -1) && (errno == EBADF));
    efd = 0; /* non-eventfd file descriptor */
    ret = syscall(SYS_io_uring_register, iour.fd, IORING_REGISTER_EVENTFD, &efd,
        1);
    test_assert((ret == -1) && (errno == EINVAL));

    efd = eventfd(0, 0);
    test_assert(efd > 0);
    ret = syscall(SYS_io_uring_register, iour.fd, IORING_REGISTER_EVENTFD, &efd,
        1);
    test_assert(ret == 0);
    ret = syscall(SYS_io_uring_register, iour.fd, IORING_REGISTER_EVENTFD, &efd,
        1);
    test_assert((ret == -1) && (errno == EBUSY));

    iour_setup_write(&iour, fd, (uint8_t *)"test", strlen("test"), 0, 0);
    test_assert(iour_submit(&iour, 1, 0) == 1);
    test_assert(read(efd, &efd_val, sizeof(efd_val)) == sizeof(efd_val));
    test_assert(efd_val == 1);

    /* The CQE should now be available. */
    cqe = iour_get_cqe(&iour);
    test_assert(cqe && (cqe->res == strlen("test")));

    ret = syscall(SYS_io_uring_register, iour.fd, IORING_UNREGISTER_EVENTFD,
        NULL, 0);
    test_assert(ret == 0);
    ret = syscall(SYS_io_uring_register, iour.fd, IORING_UNREGISTER_EVENTFD,
        NULL, 0);
    test_assert((ret == -1) && (errno == ENXIO));

    ret = syscall(SYS_io_uring_register, iour.fd, IORING_REGISTER_EVENTFD_ASYNC,
        &efd, 1);
    test_assert(ret == 0);

    iour_setup_nop(&iour, 0);   /* this operation completes inline */
    test_assert(iour_submit(&iour, 1, 1) == 1);
    FD_ZERO(&select_fd);
    FD_SET(efd, &select_fd);
    timeout.tv_sec = 0;
    timeout.tv_usec = 0;
    test_assert(select(efd + 1, &select_fd, NULL, NULL, &timeout) == 0);

    /* Write operations complete asynchronously. */
    iour_setup_write(&iour, fd, (uint8_t *)"test", strlen("test"), 0, 0);
    test_assert(iour_submit(&iour, 1, 1) == 1);
    FD_ZERO(&select_fd);
    FD_SET(efd, &select_fd);
    test_assert(select(efd + 1, &select_fd, NULL, NULL, &timeout) == 1);
    test_assert(FD_ISSET(efd, &select_fd));

    test_assert(close(efd) == 0);
    test_assert(iour_exit(&iour) == 0);
    test_assert(close(fd) == 0);
}

static void iour_test_multiple(void)
{
    int fd;
    struct iour iour;
    uint8_t read_buf[BUF_SIZE], write_buf[BUF_SIZE];
    const int chunk_len = 8;
    const int chunk_count = BUF_SIZE / chunk_len;
    struct io_uring_cqe *cqe;

    fd = open("file_mult", O_RDWR | O_CREAT, S_IRWXU);
    test_assert(fd > 0);

    memset(&iour.params, 0, sizeof(iour.params));
    test_assert(iour_init(&iour, chunk_count) == 0);

    for (int i = 0; i < BUF_SIZE; i++) {
        write_buf[i] = i;
    }
    for (int i = 0; i < chunk_count; i++)
        iour_setup_write(&iour, fd, write_buf + i * chunk_len, chunk_len,
            i * chunk_len, (uint64_t)write_buf);
    test_assert(iour_submit(&iour, chunk_count, chunk_count) == chunk_count);
    for (int i = 0; i < chunk_count; i++) {
        cqe = iour_get_cqe(&iour);
        test_assert(cqe && (cqe->res == chunk_len));
        test_assert(cqe->user_data == (uint64_t)write_buf);
        iour_setup_read(&iour, fd, read_buf + i * chunk_len, chunk_len,
                        i * chunk_len, (uint64_t)read_buf);
    }
    test_assert(iour_submit(&iour, chunk_count, chunk_count) == chunk_count);
    for (int i = 0; i < chunk_count; i++) {
        cqe = iour_get_cqe(&iour);
        test_assert(cqe && (cqe->res == chunk_len));
        test_assert(cqe->user_data == (uint64_t)read_buf);
    }
    for (int i = 0; i < BUF_SIZE; i++) {
        test_assert(read_buf[i] == (i & 0xFF));
    }

    test_assert(lseek(fd, 0, SEEK_CUR) == 0);
    iour_setup_read(&iour, fd, read_buf, chunk_len, -1, 0);
    test_assert(iour_submit(&iour, 1, 1) == 1);
    test_assert(lseek(fd, 0, SEEK_CUR) == chunk_len);

    test_assert(iour_exit(&iour) == 0);
    test_assert(close(fd) == 0);
}

static void iour_test_iovec(void)
{
    int fd;
    struct iour iour;
    uint8_t read_buf[BUF_SIZE], write_buf[BUF_SIZE];
    const int chunk_len = 8;
    const int chunk_count = BUF_SIZE / chunk_len;
    struct iovec iov[chunk_count];
    struct io_uring_cqe *cqe;

    fd = open("file_iov", O_RDWR | O_CREAT, S_IRWXU);
    test_assert(fd > 0);

    memset(&iour.params, 0, sizeof(iour.params));
    test_assert(iour_init(&iour, 1) == 0);

    iov[0].iov_base = NULL;
    iov[0].iov_len = chunk_len;
    iour_setup_writev(&iour, fd, iov, 1, 0, 0);
    test_assert(iour_submit(&iour, 1, 1) == 1);
    cqe = iour_get_cqe(&iour);
    test_assert(cqe && (cqe->res == -EFAULT));

    for (int i = 0; i < BUF_SIZE; i++)
        write_buf[i] = i;
    for (int i = 0; i < chunk_count; i++) {
        iov[i].iov_base = write_buf + i * chunk_len;
        iov[i].iov_len = chunk_len;
    }
    iour_setup_writev(&iour, fd, iov, chunk_count, -1, 0);
    test_assert(iour_submit(&iour, 1, 1) == 1);
    cqe = iour_get_cqe(&iour);
    test_assert(cqe && (cqe->res == BUF_SIZE));
    test_assert(lseek(fd, 0, SEEK_CUR) == BUF_SIZE);

    /* Set file offset to arbitrary value and check that it has not changed
     * after the read operation. */
    test_assert(lseek(fd, BUF_SIZE / 2, SEEK_SET) == BUF_SIZE / 2);
    for (int i = 0; i < chunk_count; i++)
        iov[i].iov_base = read_buf + i * chunk_len;
    iour_setup_readv(&iour, fd, iov, chunk_count, 0, 0);
    test_assert(iour_submit(&iour, 1, 1) == 1);
    cqe = iour_get_cqe(&iour);
    test_assert(cqe && (cqe->res == BUF_SIZE));
    for (int i = 0; i < BUF_SIZE; i++)
        test_assert(read_buf[i] == (i & 0xFF));
    test_assert(lseek(fd, 0, SEEK_CUR) == BUF_SIZE / 2);

    test_assert(iour_exit(&iour) == 0);
    test_assert(close(fd) == 0);
}

static void iour_test_rw_fixed(void)
{
    int fd;
    struct iour iour;
    uint8_t read_buf[BUF_SIZE], write_buf[BUF_SIZE];
    struct iovec iov[2];
    int ret;
    struct io_uring_cqe *cqe;

    fd = open("file_rw_fixed", O_RDWR | O_CREAT, S_IRWXU);
    test_assert(fd > 0);

    memset(&iour.params, 0, sizeof(iour.params));
    test_assert(iour_init(&iour, 1) == 0);

    iour_setup_rw_fixed(&iour, fd, 0, true, write_buf, sizeof(write_buf), 0, 0);
    test_assert(iour_submit(&iour, 1, 1) == 1);
    cqe = iour_get_cqe(&iour);
    test_assert(cqe && (cqe->res == -EFAULT));

    ret = syscall(SYS_io_uring_register, iour.fd, IORING_REGISTER_BUFFERS, NULL,
        1);
    test_assert((ret == -1) && (errno == EFAULT));

    iov[0].iov_base = write_buf;
    iov[0].iov_len = BUF_SIZE;
    iov[1].iov_base = read_buf;
    iov[1].iov_len = BUF_SIZE;
    ret = syscall(SYS_io_uring_register, iour.fd, IORING_REGISTER_BUFFERS, iov,
        0);
    test_assert((ret == -1) && (errno == EINVAL));
    ret = syscall(SYS_io_uring_register, iour.fd, IORING_REGISTER_BUFFERS, iov,
        2);
    test_assert(ret == 0);
    ret = syscall(SYS_io_uring_register, iour.fd, IORING_REGISTER_BUFFERS, iov,
        2);
    test_assert((ret == -1) && (errno == EBUSY));

    iour_setup_rw_fixed(&iour, fd, 2, true, write_buf, sizeof(write_buf), 0, 0);
    test_assert(iour_submit(&iour, 1, 1) == 1);
    cqe = iour_get_cqe(&iour);
    test_assert(cqe && (cqe->res == -EINVAL));  /* invalid buffer index */

    /* Mismatch between buffer index and buffer pointer */
    iour_setup_rw_fixed(&iour, fd, 0, true, read_buf, sizeof(read_buf), 0, 0);
    test_assert(iour_submit(&iour, 1, 1) == 1);
    cqe = iour_get_cqe(&iour);
    test_assert(cqe && (cqe->res == -EFAULT));

    iour_setup_rw_fixed(&iour, fd, 0, true, write_buf, sizeof(write_buf) + 1, 0,
                        0);
    test_assert(iour_submit(&iour, 1, 1) == 1);
    cqe = iour_get_cqe(&iour);
    test_assert(cqe && (cqe->res == -EFAULT));  /* invalid buffer length */

    for (int i = 0; i < BUF_SIZE; i++)
        write_buf[i] = i;
    iour_setup_rw_fixed(&iour, fd, 0, true, write_buf, sizeof(write_buf), 0, 0);
    test_assert(iour_submit(&iour, 1, 1) == 1);
    cqe = iour_get_cqe(&iour);
    test_assert(cqe && (cqe->res == BUF_SIZE));

    iour_setup_rw_fixed(&iour, fd, 1, false, read_buf, sizeof(read_buf), 0, 0);
    test_assert(iour_submit(&iour, 1, 1) == 1);
    cqe = iour_get_cqe(&iour);
    test_assert(cqe && (cqe->res == BUF_SIZE));
    for (int i = 0; i < BUF_SIZE; i++)
        test_assert(read_buf[i] == (i & 0xFF));

    ret = syscall(SYS_io_uring_register, iour.fd, IORING_UNREGISTER_BUFFERS,
        NULL, 0);
    test_assert(ret == 0);
    ret = syscall(SYS_io_uring_register, iour.fd, IORING_UNREGISTER_BUFFERS,
        NULL, 0);
    test_assert((ret == -1) && (errno == ENXIO));

    test_assert(iour_exit(&iour) == 0);
    test_assert(close(fd) == 0);
}

static void iour_test_poll(void)
{
    struct iour iour;
    int pipe_fds[2];
    uint8_t pipe_buf[8];
    struct io_uring_cqe *cqe;

    memset(&iour.params, 0, sizeof(iour.params));
    test_assert(iour_init(&iour, 2) == 0);

    test_assert(pipe(pipe_fds) == 0);

    iour_setup_poll_add(&iour, pipe_fds[1], POLLOUT, 0);
    test_assert(iour_submit(&iour, 1, 1) == 1);
    cqe = iour_get_cqe(&iour);
    test_assert(cqe && (cqe->res == POLLOUT));

    iour_setup_poll_add(&iour, pipe_fds[0], POLLIN, 0);
    test_assert(iour_submit(&iour, 1, 0) == 1);
    test_assert(iour_get_cqe(&iour) == NULL);

    test_assert(write(pipe_fds[1], pipe_buf, sizeof(pipe_buf)) ==
            sizeof(pipe_buf));
    cqe = iour_get_cqe(&iour);
    test_assert(cqe && (cqe->res == POLLIN));
    test_assert(read(pipe_fds[0], pipe_buf, sizeof(pipe_buf)) ==
            sizeof(pipe_buf));

    iour_setup_poll_add(&iour, pipe_fds[0], POLLIN, 0);
    iour_setup_poll_remove(&iour, 0, 0);
    test_assert(iour_submit(&iour, 2, 2) == 2);
    cqe = iour_get_cqe(&iour);
    test_assert(cqe && (cqe->res == -ECANCELED));
    cqe = iour_get_cqe(&iour);
    test_assert(cqe && (cqe->res == 0));

    iour_setup_poll_remove(&iour, 0xdeadbeef, 0);
    test_assert(iour_submit(&iour, 1, 1) == 1);
    cqe = iour_get_cqe(&iour);
    test_assert(cqe && (cqe->res == -ENOENT));

    test_assert(iour_exit(&iour) == 0);
    test_assert(close(pipe_fds[0]) == 0);
    test_assert(close(pipe_fds[1]) == 0);
}

static void iour_test_timeout(void)
{
    struct iour iour;
    struct timespec ts1, ts2;
    const uint64_t t1_userdata = 1;
    const uint64_t t2_userdata = 2;
    struct io_uring_cqe *cqe;

    memset(&iour.params, 0, sizeof(iour.params));
    test_assert(iour_init(&iour, 2) == 0);

    iour_setup_timeout(&iour, NULL, 0, 0, 0);
    test_assert(iour_submit(&iour, 1, 1) == 1);
    cqe = iour_get_cqe(&iour);
    test_assert(cqe && (cqe->user_data == 0) && (cqe->res == -EFAULT));

    ts1.tv_sec = 1000000;
    ts1.tv_nsec = 0;
    iour_setup_timeout(&iour, &ts1, 1, 0, t1_userdata);
    iour_setup_nop(&iour, 0);
    test_assert(iour_submit(&iour, 2, 2) == 2);
    cqe = iour_get_cqe(&iour);
    test_assert(cqe && (cqe->user_data == 0) && (cqe->res == 0));
    cqe = iour_get_cqe(&iour);
    test_assert(cqe && (cqe->user_data == t1_userdata) && (cqe->res == 0));

    test_assert(clock_gettime(CLOCK_MONOTONIC, &ts1) == 0);
    ts2.tv_sec = ts1.tv_sec;
    ts2.tv_nsec = ts1.tv_nsec + 1000000;
    if (ts2.tv_nsec >= 1000000000) {
        ts2.tv_sec++;
        ts2.tv_nsec -= 1000000000;
    }
    iour_setup_timeout(&iour, &ts2, 0, IORING_TIMEOUT_ABS, t2_userdata);
    test_assert(iour_submit(&iour, 1, 1) == 1);
    cqe = iour_get_cqe(&iour);
    test_assert(cqe && (cqe->user_data == t2_userdata) && (cqe->res == -ETIME));

    ts1.tv_sec = 1000000;
    ts1.tv_nsec = 0;
    iour_setup_timeout(&iour, &ts1, 0, 0, t1_userdata);
    iour_setup_timeout_remove(&iour, t1_userdata, 0);
    test_assert(iour_submit(&iour, 2, 2) == 2);
    cqe = iour_get_cqe(&iour);
    test_assert(cqe && (cqe->user_data == t1_userdata) &&
                (cqe->res == -ECANCELED));
    cqe = iour_get_cqe(&iour);
    test_assert(cqe && (cqe->user_data == 0) && (cqe->res == 0));

    iour_setup_timeout_remove(&iour, 0xdeadbeef, 0);
    test_assert(iour_submit(&iour, 1, 1) == 1);
    cqe = iour_get_cqe(&iour);
    test_assert(cqe && (cqe->user_data == 0) && (cqe->res == -ENOENT));

    ts1.tv_sec = 0;
    ts1.tv_nsec = 1000000;
    iour_setup_timeout(&iour, &ts1, 0, 0, t1_userdata);
    ts2.tv_sec = 1;
    ts2.tv_nsec = 0;
    iour_setup_timeout(&iour, &ts2, 0, 0, t2_userdata);
    test_assert(iour_submit(&iour, 2, 2) == 2);
    /* The first timeout wakes up this thread even if fewer than `min_complete`
     * operations have completed. */
    cqe = iour_get_cqe(&iour);
    test_assert(cqe);
    test_assert((cqe->user_data == t1_userdata) && (cqe->res == -ETIME));
    test_assert(iour_get_cqe(&iour) == NULL);

    test_assert(iour_exit(&iour) == 0);
}

static void iour_test_close(void)
{
    struct iour iour;
    int fd, fd1;
    const uint64_t close_userdata = 1;
    struct io_uring_cqe *cqe;

    memset(&iour.params, 0, sizeof(iour.params));
    test_assert(iour_init(&iour, 1) == 0);

    fd = open("file_close", O_RDWR | O_CREAT, S_IRWXU);
    test_assert(fd > 0);
    iour_setup_close(&iour, fd, close_userdata);
    test_assert(iour_submit(&iour, 1, 1) == 1);
    cqe = iour_get_cqe(&iour);
    test_assert(cqe && (cqe->user_data == close_userdata) && (cqe->res == 0));
    test_assert((close(fd) == -1) && (errno == EBADF));

    /* Close fd without de-allocating file resources (because of duplicated fd).
     */
    fd = open("file_close", O_RDWR | O_CREAT, S_IRWXU);
    test_assert(fd > 0);
    fd1 = dup(fd);
    test_assert(fd1 > 0);
    iour_setup_close(&iour, fd, close_userdata);
    test_assert(iour_submit(&iour, 1, 1) == 1);
    cqe = iour_get_cqe(&iour);
    test_assert(cqe && (cqe->user_data == close_userdata) && (cqe->res == 0));
    test_assert(close(fd1) == 0);

    /* Close invalid fd. */
    iour_setup_close(&iour, fd, close_userdata);
    test_assert(iour_submit(&iour, 1, 1) == 1);
    cqe = iour_get_cqe(&iour);
    test_assert(cqe);
    test_assert((cqe->user_data == close_userdata) && (cqe->res == -EBADF));

    /* Close fd of io_uring context. */
    iour_setup_close(&iour, iour.fd, close_userdata);
    test_assert(iour_submit(&iour, 1, 1) == 1);
    cqe = iour_get_cqe(&iour);
    test_assert(cqe);
    test_assert((cqe->user_data == close_userdata) && (cqe->res == -EBADF));

    test_assert(iour_exit(&iour) == 0);
}

static void iour_test_sig(void)
{
    struct iour iour;
    sigset_t old, new;
    int ret;
    struct io_uring_cqe *cqe;

    memset(&iour.params, 0, sizeof(iour.params));
    test_assert(iour_init(&iour, 1) == 0);

    test_assert(sigprocmask(SIG_SETMASK, NULL, &old) == 0);
    memcpy(&new, &old, sizeof(sigset_t));
    test_assert(sigaddset(&new, SIGUSR1) == 0);
    test_assert(memcmp(&new, &old, sizeof(sigset_t)) != 0);

    iour_setup_nop(&iour, 0);
    ret = syscall(SYS_io_uring_enter, iour.fd, 1, 0, 0, -1L);
    test_assert((ret == -1) && (errno == EFAULT)); /* invalid sig pointer */
    ret = syscall(SYS_io_uring_enter, iour.fd, 1, 1, IORING_ENTER_GETEVENTS,
        &new);
    test_assert(ret == 1);
    test_assert(sigprocmask(SIG_SETMASK, NULL, &new) == 0);
    test_assert(memcmp(&new, &old, sizeof(sigset_t)) == 0);

    cqe = iour_get_cqe(&iour);
    test_assert(cqe && (cqe->user_data == 0) && (cqe->res == 0));

    test_assert(iour_exit(&iour) == 0);
}

static void iour_test_register_files(void)
{
    struct iour iour;
    int fds[3];
    int ret;
    struct io_uring_cqe *cqe;
    struct io_uring_files_update update;

    memset(&iour.params, 0, sizeof(iour.params));
    test_assert(iour_init(&iour, 1) == 0);

    ret = syscall(SYS_io_uring_register, iour.fd, IORING_REGISTER_FILES, NULL,
        3); /* invalid file descriptor array pointer */
    test_assert((ret == -1) && (errno == EFAULT));

    ret = syscall(SYS_io_uring_register, iour.fd, IORING_REGISTER_FILES, fds,
        0); /* invalid number of file descriptors */
    test_assert((ret == -1) && (errno == EINVAL));

    fds[0] = 0;
    fds[1] = 1;
    fds[2] = -2;    /* invalid file descriptor */
    ret = syscall(SYS_io_uring_register, iour.fd, IORING_REGISTER_FILES, fds,
        3);
    test_assert((ret == -1) && (errno == EBADF));

    fds[2] = 2;
    ret = syscall(SYS_io_uring_register, iour.fd, IORING_REGISTER_FILES, fds,
        3);
    test_assert(ret == 0);
    ret = syscall(SYS_io_uring_register, iour.fd, IORING_REGISTER_FILES, fds,
        3);
    test_assert((ret == -1) && (errno == EBUSY));

    iour_setup_poll_fixed_file(&iour, 1, POLLOUT, 0);
    test_assert(iour_submit(&iour, 1, 1) == 1);
    cqe = iour_get_cqe(&iour);
    test_assert(cqe && (cqe->user_data == 0) && (cqe->res == POLLOUT));

    ret = syscall(SYS_io_uring_register, iour.fd, IORING_REGISTER_FILES_UPDATE,
        NULL, 1);   /* invalid pointer */
    test_assert((ret == -1) && (errno == EFAULT));

    iour_setup_files_update(&iour, fds, 0, 0, 0);
    test_assert(iour_submit(&iour, 1, 1) == 1);
    cqe = iour_get_cqe(&iour);
    test_assert(cqe && (cqe->user_data == 0) && (cqe->res == -EINVAL));

    iour_setup_files_update(&iour, NULL, 1, 0, 0);
    test_assert(iour_submit(&iour, 1, 1) == 1);
    cqe = iour_get_cqe(&iour);
    test_assert(cqe && (cqe->user_data == 0) && (cqe->res == -EFAULT));

    iour_setup_files_update(&iour, fds, 3, 1, 0);   /* invalid length/offset */
    test_assert(iour_submit(&iour, 1, 1) == 1);
    cqe = iour_get_cqe(&iour);
    test_assert(cqe && (cqe->user_data == 0) && (cqe->res == -EINVAL));

    fds[0] = 0xdeadbeef;    /* invalid fd */
    iour_setup_files_update(&iour, fds, 3, 0, 0);
    test_assert(iour_submit(&iour, 1, 1) == 1);
    cqe = iour_get_cqe(&iour);
    test_assert(cqe && (cqe->user_data == 0) && (cqe->res == -EBADF));

    fds[0] = 0;
    fds[1] = -1;    /* unregister fd */
    fds[2] = 0xdeadbeef;    /* invalid fd */
    update.offset = 0;
    update.fds = fds;
    ret = syscall(SYS_io_uring_register, iour.fd, IORING_REGISTER_FILES_UPDATE,
        &update, 3);
    test_assert(ret == 2);
    iour_setup_poll_fixed_file(&iour, 1, POLLOUT, 0);
    test_assert(iour_submit(&iour, 1, 1) == 1);
    cqe = iour_get_cqe(&iour);
    test_assert(cqe && (cqe->user_data == 0) && (cqe->res == -EBADF));

    fds[1] = 1;
    fds[2] = 2;
    iour_setup_files_update(&iour, fds, 3, 0, 0);
    test_assert(iour_submit(&iour, 1, 1) == 1);
    cqe = iour_get_cqe(&iour);
    test_assert(cqe && (cqe->user_data == 0) && (cqe->res == 3));
    iour_setup_poll_fixed_file(&iour, 1, POLLOUT, 0);
    test_assert(iour_submit(&iour, 1, 1) == 1);
    cqe = iour_get_cqe(&iour);
    test_assert(cqe && (cqe->user_data == 0) && (cqe->res == POLLOUT));

    ret = syscall(SYS_io_uring_register, iour.fd, IORING_UNREGISTER_FILES, NULL,
        0);
    test_assert(ret == 0);
    ret = syscall(SYS_io_uring_register, iour.fd, IORING_UNREGISTER_FILES, NULL,
        0);
    test_assert((ret == -1) && (errno == ENXIO));
    test_assert(iour_exit(&iour) == 0);
}

int main(int argc, char **argv)
{
    setbuf(stdout, NULL);

    iour_test_basic();
    iour_test_readwrite();
    iour_test_eventfd();
    iour_test_multiple();
    iour_test_iovec();
    iour_test_rw_fixed();
    iour_test_poll();
    iour_test_timeout();
    iour_test_close();
    iour_test_sig();
    iour_test_register_files();
    printf("IO uring test OK\n");
    return EXIT_SUCCESS;
}
