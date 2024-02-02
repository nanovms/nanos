#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <string.h>
#include <sys/inotify.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

#include "../test_utils.h"

#define INOTIFY_TEST_DIR1   "tmp1"
#define INOTIFY_TEST_DIR2   "tmp2"
#define INOTIFY_TEST_FILE   "foo"
#define INOTIFY_TEST_FILE1  "foo1"
#define INOTIFY_TEST_FILE2  "foo2"
#define INOTIFY_TEST_LINK   "link"
#define INOTIFY_TEST_SOCKET "socket"

static void *inotify_thread(void *arg)
{
    DIR *dir;
    int fd;
    struct sockaddr_un addr;
    uint8_t buf[8];

    /* INOTIFY_TEST_DIR1 */
    dir = opendir(INOTIFY_TEST_DIR1);   /* IN_OPEN */
    readdir(dir);   /* IN_ACCESS */
    closedir(dir);  /* IN_CLOSE_NOWRITE */
    test_assert(mkdir(INOTIFY_TEST_DIR1 "/" INOTIFY_TEST_DIR1, S_IRWXU) == 0);  /* IN_CREATE */
    rmdir(INOTIFY_TEST_DIR1 "/" INOTIFY_TEST_DIR1); /* IN_DELETE */
    test_assert(symlink(".", INOTIFY_TEST_DIR1 "/" INOTIFY_TEST_LINK) == 0);    /* IN_CREATE */
    unlink(INOTIFY_TEST_DIR1 "/" INOTIFY_TEST_LINK);    /* IN_DELETE */
    fd = socket(AF_UNIX, SOCK_DGRAM, 0);
    addr.sun_family = AF_UNIX;
    strcpy(addr.sun_path, INOTIFY_TEST_DIR1 "/" INOTIFY_TEST_SOCKET);
    test_assert(bind(fd, (struct sockaddr *)&addr, sizeof(addr)) == 0); /* IN_CREATE */
    close(fd);
    unlink(INOTIFY_TEST_DIR1 "/" INOTIFY_TEST_SOCKET);  /* IN_DELETE */

    /* INOTIFY_TEST_DIR2 */
    /* IN_CREATE + IN_OPEN */
    fd = open(INOTIFY_TEST_DIR2 "/" INOTIFY_TEST_FILE1, O_CREAT | O_RDWR, S_IRUSR | S_IWUSR);
    close(fd);  /* IN_CLOSE_WRITE */
    fd = open(INOTIFY_TEST_DIR2 "/" INOTIFY_TEST_FILE1, O_RDWR);    /* IN_OPEN */
    test_assert(write(fd, buf, sizeof(buf)) == sizeof(buf));    /* IN_MODIFY */

    test_assert(rename(INOTIFY_TEST_DIR2 "/" INOTIFY_TEST_FILE1,
                       INOTIFY_TEST_DIR1 "/" INOTIFY_TEST_FILE2) == 0);

    /* INOTIFY_TEST_DIR1 */
    close(fd);  /* IN_CLOSE_WRITE */
    unlink(INOTIFY_TEST_DIR1 "/" INOTIFY_TEST_FILE2);   /* IN_DELETE */

    /* INOTIFY_TEST_FILE */
    fd = open(INOTIFY_TEST_FILE, O_RDWR);   /* IN_OPEN */
    test_assert(write(fd, buf, sizeof(buf)) == sizeof(buf));    /* IN_MODIFY */
    test_assert(lseek(fd, 0, SEEK_SET) == 0);
    test_assert(read(fd, buf, 0) == 0); /* no event */
    test_assert(read(fd, buf, sizeof(buf)) == sizeof(buf)); /* IN_ACCESS */
    test_assert(ftruncate(fd, 0) == 0); /* IN_MODIFY */
    /* IN_MOVE_SELF */
    test_assert(rename(INOTIFY_TEST_FILE, INOTIFY_TEST_FILE INOTIFY_TEST_FILE) == 0);
    close(fd);  /* IN_CLOSE_WRITE */
    /* IN_MOVE_SELF */
    test_assert(rename(INOTIFY_TEST_FILE INOTIFY_TEST_FILE, INOTIFY_TEST_FILE) == 0);

    return NULL;
}

static int inotify_events_check(const char *buf, ssize_t len,
                                const struct inotify_event *expected, const char **names, int num)
{
    const struct inotify_event *ev;
    const char *ptr;
    int count = 0;

    for (ptr = buf; ptr < buf + len; count++, ptr += sizeof(struct inotify_event) + ev->len) {
        ev = (const struct inotify_event *)ptr;
        test_assert(count < num);
        test_assert(ev->wd == expected[count].wd);
        test_assert(ev->mask == expected[count].mask);
        test_assert(ev->cookie == expected[count].cookie);
        if (expected[count].len == 0) {
            test_assert(ev->len == 0);
        } else {
            test_assert(ev->len > strlen(names[count]));
            test_assert(!strcmp(ev->name, names[count]));
        }
    }
    return count;
}

static void inotify_assert_event(int fd, int wd, uint32_t mask)
{
    struct inotify_event ev;

    test_assert(read(fd, &ev, sizeof(ev)) == sizeof(ev));
    test_assert((ev.wd == wd) && (ev.mask == mask));
    test_assert((ev.cookie == 0) && (ev.len == 0));
}

/* Remove watch and receive IN_IGNORED event. */
static void inotify_test_rm(int fd, int wd)
{
    test_assert(inotify_rm_watch(fd, wd) == 0);
    inotify_assert_event(fd, wd, IN_IGNORED);
}

static void inotify_test_basic(int flags, struct inotify_event *expected, const char **names,
                               int event_num)
{
    int fd;
    int nbytes;
    char name_too_long[NAME_MAX + 2];
    int wd[4];
    uint32_t event_mask = IN_ACCESS | IN_CREATE | IN_OPEN | IN_CLOSE | IN_DELETE | IN_MODIFY |
                          IN_MOVE_SELF;
    pthread_t th;
    struct pollfd pfd;
    char buf[512] __attribute__ ((aligned(__alignof__(struct inotify_event))));
    ssize_t len;
    int i, count = 0;

    fd = inotify_init1(flags);
    test_assert(fd >= 0);
    test_assert((ioctl(fd, FIONREAD, NULL) == -1) && (errno == EFAULT));
    test_assert((ioctl(fd, FIONREAD, &nbytes) == 0) && (nbytes == 0));
    pfd.fd = fd;
    pfd.events = POLLIN;

    /* Invalid file descriptor */
    test_assert((inotify_add_watch(-1, INOTIFY_TEST_DIR1, IN_ACCESS) == -1) && (errno == EBADF));
    test_assert(inotify_add_watch(fileno(stdin), INOTIFY_TEST_DIR1, IN_ACCESS) == -1);
    test_assert(errno == EINVAL);

    /* Invalid path name */
    test_assert((inotify_add_watch(fd, NULL, IN_ACCESS) == -1) && (errno == EFAULT));
    test_assert((inotify_add_watch(fd, "abc", IN_ACCESS) == -1) && (errno == ENOENT));
    memset(name_too_long, '-', sizeof(name_too_long) - 1);
    name_too_long[sizeof(name_too_long) - 1] = '\0';
    test_assert((inotify_add_watch(fd, name_too_long, IN_ACCESS) == -1) && (errno == ENAMETOOLONG));

    /* Invalid event mask */
    test_assert((inotify_add_watch(fd, INOTIFY_TEST_DIR1, 0) == -1) && (errno == EINVAL));

    wd[0] = inotify_add_watch(fd, INOTIFY_TEST_DIR1, event_mask);
    test_assert(wd[0] >= 0);
    wd[1] = inotify_add_watch(fd, INOTIFY_TEST_DIR2, IN_ACCESS);
    test_assert(wd[1] >= 0);

    /* Modify existing watch. */
    test_assert(inotify_add_watch(fd, INOTIFY_TEST_DIR2, event_mask) == wd[1]);

    test_assert(inotify_add_watch(fd, INOTIFY_TEST_FILE, event_mask | IN_ONLYDIR) == -1);
    test_assert(errno == ENOTDIR);
    wd[2] = inotify_add_watch(fd, INOTIFY_TEST_FILE, event_mask);
    test_assert(wd[2] >= 0);

    /* Modify existing watch. */
    test_assert(inotify_add_watch(fd, INOTIFY_TEST_LINK, event_mask & ~IN_MOVE_SELF) == wd[2]);
    test_assert(inotify_add_watch(fd, INOTIFY_TEST_LINK, IN_MOVE_SELF | IN_MASK_ADD) == wd[2]);

    wd[3] = inotify_add_watch(fd, INOTIFY_TEST_LINK, event_mask | IN_DONT_FOLLOW);
    test_assert(wd[3] != wd[2]);
    inotify_test_rm(fd, wd[3]);

    for (i = 0; i < 9; i++)
        expected[count++].wd = wd[0];
    for (i = 0; i < 5; i++)
        expected[count++].wd = wd[1];
    for (i = 0; i < 2; i++)
        expected[count++].wd = wd[0];
    for (i = 0; i < 7; i++)
        expected[count++].wd = wd[2];
    if (flags & IN_NONBLOCK)
        test_assert((read(fd, buf, sizeof(buf)) == -1) && (errno == EAGAIN));
    test_assert(pthread_create(&th, NULL, inotify_thread, NULL) == 0);
    count = 0;
    while (count < event_num) {
        if (flags & IN_NONBLOCK) {
            test_assert((poll(&pfd, 1, -1) == 1) && (pfd.revents == POLLIN));
            test_assert(ioctl(fd, FIONREAD, &nbytes) == 0);
            test_assert(nbytes >= sizeof(struct inotify_event));
        }

        /* Invalid buffer length */
        test_assert((read(fd, buf, 0) == -1) && (errno == EINVAL));

        len = read(fd, buf, sizeof(buf));
        test_assert(len >= sizeof(struct inotify_event));
        count += inotify_events_check(buf, len, expected + count, names + count, event_num - count);
    }
    pthread_join(th, NULL);

    /* Invalid watch descriptor */
    test_assert((inotify_rm_watch(fd, -1) == -1) && (errno == EINVAL));

    /* Remove watches, re-execute filesystem operations and verify that no events are generated. */
    inotify_test_rm(fd, wd[0]);
    inotify_test_rm(fd, wd[1]);
    inotify_test_rm(fd, wd[2]);
    test_assert(pthread_create(&th, NULL, inotify_thread, NULL) == 0);
    pthread_join(th, NULL);
    test_assert(poll(&pfd, 1, 0) == 0);

    test_assert(close(fd) == 0);
}

static void inotify_test_move(void)
{
    int fd;
    int wd;
    char buf[64];
    ssize_t len;
    void *ptr;
    struct inotify_event *ev;
    uint32_t cookie;

    fd = creat("file1", S_IRUSR | S_IWUSR);
    test_assert(fd >= 0);
    close(fd);

    fd = inotify_init();
    test_assert(fd >= 0);
    wd = inotify_add_watch(fd, ".", IN_MOVE);
    test_assert(wd >= 0);
    test_assert(rename("file1", "file2") == 0);
    len = read(fd, buf, sizeof(buf));
    ptr = buf;
    ev = ptr;
    test_assert(len >= sizeof(*ev) + ev->len);
    test_assert((ev->wd == wd) && (ev->mask == IN_MOVED_FROM));
    cookie = ev->cookie;
    ptr += sizeof(*ev);
    test_assert((ev->len > 0) && !strcmp(ptr, "file1"));
    len -= sizeof(*ev) + ev->len;
    if (len == 0) {
        len = read(fd, buf, sizeof(buf));
        ptr = buf;
    } else {
        ptr += ev->len;
    }
    ev = ptr;
    test_assert(len == sizeof(*ev) + ev->len);
    test_assert((ev->wd == wd) && (ev->mask == IN_MOVED_TO) && (ev->cookie == cookie));
    test_assert((ev->len > 0) && !strcmp(ptr + sizeof(*ev), "file2"));

    unlink("file2");
    test_assert(close(fd) == 0);
}

static void inotify_test_delete(void)
{
    int fd;
    int wd;

    fd = creat("file1", S_IRUSR | S_IWUSR);
    test_assert(fd >= 0);
    close(fd);

    fd = inotify_init();
    test_assert(fd >= 0);
    wd = inotify_add_watch(fd, "file1", IN_DELETE_SELF);
    test_assert(wd >= 0);
    test_assert(unlink("file1") == 0);
    inotify_assert_event(fd, wd, IN_DELETE_SELF);
    inotify_assert_event(fd, wd, IN_IGNORED);
    test_assert(close(fd) == 0);
}

static void inotify_test_oneshot(void)
{
    int fd;
    int wd;

    fd = creat("file1", S_IRUSR | S_IWUSR);
    test_assert(fd >= 0);
    close(fd);

    fd = inotify_init();
    test_assert(fd >= 0);
    wd = inotify_add_watch(fd, "file1", IN_ALL_EVENTS | IN_ONESHOT);
    test_assert(wd >= 0);
    /* IN_MOVE_SELF event, plus IN_IGNORED because of IN_ONESHOT */
    test_assert(rename("file1", "file2") == 0);
    test_assert(unlink("file2") == 0);  /* no event, because of IN_ONESHOT */
    inotify_assert_event(fd, wd, IN_MOVE_SELF);
    inotify_assert_event(fd, wd, IN_IGNORED);
    test_assert((inotify_rm_watch(fd, wd) == -1) && (errno == EINVAL));
    test_assert(close(fd) == 0);
}

static void inotify_test_overflow(void)
{
    int fd;
    int wd;
    const int iterations = 20000;

    fd = creat("file1", S_IRUSR | S_IWUSR);
    test_assert(fd >= 0);
    close(fd);

    fd = inotify_init();
    test_assert(fd >= 0);
    wd = inotify_add_watch(fd, "file1", IN_ALL_EVENTS);
    test_assert(wd >= 0);
    for (int i = 0; i < iterations; i++) {
        int fd = open("file1", O_RDONLY);

        close(fd);
    }
    for (int i = 0; i < 2 * iterations; i++) {  /* 2 events (open and close) per iteration */
        struct inotify_event ev;

        test_assert(read(fd, &ev, sizeof(ev)) == sizeof(ev));
        test_assert((ev.cookie == 0) && (ev.len == 0));
        if (ev.wd == wd) {
            test_assert((ev.mask == IN_OPEN) || (ev.mask == IN_CLOSE_NOWRITE));
        } else {
            test_assert((ev.wd == -1) && (ev.mask == IN_Q_OVERFLOW));
            break;
        }
    }
    test_assert(unlink("file1") == 0);
    test_assert(close(fd) == 0);
}

/* Verify that events are not read from the inotify file descriptor if they are not included in the
 * event mask of the watch. */
static void inotify_test_noevents(void)
{
    int fd;
    DIR *dir;
    int wd;
    struct inotify_event ev;

    fd = inotify_init1(O_NONBLOCK);
    test_assert(fd >= 0);
    wd = inotify_add_watch(fd, INOTIFY_TEST_DIR1, IN_ALL_EVENTS & ~IN_OPEN);
    test_assert(wd >= 0);
    dir = opendir(INOTIFY_TEST_DIR1);
    test_assert(dir != NULL);
    test_assert((read(fd, &ev, sizeof(ev)) == -1) && (errno == EAGAIN));
    close(fd);

    fd = inotify_init1(O_NONBLOCK);
    test_assert(fd >= 0);
    wd = inotify_add_watch(fd, INOTIFY_TEST_DIR1, IN_ALL_EVENTS & ~IN_ACCESS);
    test_assert(wd >= 0);
    readdir(dir);
    test_assert((read(fd, &ev, sizeof(ev)) == -1) && (errno == EAGAIN));
    close(fd);

    fd = inotify_init1(O_NONBLOCK);
    test_assert(fd >= 0);
    wd = inotify_add_watch(fd, INOTIFY_TEST_DIR1, IN_ALL_EVENTS & ~IN_CLOSE_NOWRITE);
    test_assert(wd >= 0);
    closedir(dir);
    test_assert((read(fd, &ev, sizeof(ev)) == -1) && (errno == EAGAIN));
    close(fd);
}

int main(int argc, char* argv[])
{
    int fd;
    const int event_num = 23;
    struct inotify_event expected[event_num];
    const char *names[event_num];
    int i = 0;

    test_assert((inotify_init1(~0) == -1) && (errno == EINVAL));    /* invalid flags */

    test_assert(mkdir(INOTIFY_TEST_DIR1, S_IRWXU) == 0);
    test_assert(mkdir(INOTIFY_TEST_DIR2, S_IRWXU) == 0);
    fd = creat(INOTIFY_TEST_FILE, S_IRUSR | S_IWUSR);
    test_assert(fd >= 0);
    close(fd);
    test_assert(symlink(INOTIFY_TEST_FILE, INOTIFY_TEST_LINK) == 0);

    /* INOTIFY_TEST_DIR1 */
    for (int j = 0; j < 3; j++)
        names[i + j] = "";
    expected[i++].mask = IN_OPEN | IN_ISDIR;
    expected[i++].mask = IN_ACCESS | IN_ISDIR;
    expected[i++].mask = IN_CLOSE_NOWRITE | IN_ISDIR;
    for (int j = 0; j < 2; j++)
        names[i + j] = INOTIFY_TEST_DIR1;
    expected[i++].mask = IN_CREATE | IN_ISDIR;
    expected[i++].mask = IN_DELETE | IN_ISDIR;
    for (int j = 0; j < 2; j++)
        names[i + j] = INOTIFY_TEST_LINK;
    expected[i++].mask = IN_CREATE;
    expected[i++].mask = IN_DELETE;
    for (int j = 0; j < 2; j++)
        names[i + j] = INOTIFY_TEST_SOCKET;
    expected[i++].mask = IN_CREATE;
    expected[i++].mask = IN_DELETE;

    /* INOTIFY_TEST_DIR2 */
    for (int j = 0; j < 5; j++)
        names[i + j] = INOTIFY_TEST_FILE1;
    expected[i++].mask = IN_CREATE;
    expected[i++].mask = IN_OPEN;
    expected[i++].mask = IN_CLOSE_WRITE;
    expected[i++].mask = IN_OPEN;
    expected[i++].mask = IN_MODIFY;

    /* INOTIFY_TEST_DIR1 */
    for (int j = 0; j < 2; j++)
        names[i + j] = INOTIFY_TEST_FILE2;
    expected[i++].mask = IN_CLOSE_WRITE;
    expected[i++].mask = IN_DELETE;

    /* INOTIFY_TEST_FILE */
    for (int j = 0; j < 7; j++)
        names[i + j] = "";
    expected[i++].mask = IN_OPEN;
    expected[i++].mask = IN_MODIFY;
    expected[i++].mask = IN_ACCESS;
    expected[i++].mask = IN_MODIFY;
    expected[i++].mask = IN_MOVE_SELF;
    expected[i++].mask = IN_CLOSE_WRITE;
    expected[i++].mask = IN_MOVE_SELF;

    for (i = 0; i < event_num; i++) {
        expected[i].cookie = 0;
        expected[i].len = strlen(names[i]);
    }
    inotify_test_basic(0, expected, names, event_num);
    inotify_test_basic(IN_NONBLOCK, expected, names, event_num);
    inotify_test_move();
    inotify_test_delete();
    inotify_test_oneshot();
    inotify_test_overflow();
    inotify_test_noevents();

    printf("inotify test OK\n");
    unlink(INOTIFY_TEST_LINK);
    unlink(INOTIFY_TEST_FILE);
    rmdir(INOTIFY_TEST_DIR1);
    rmdir(INOTIFY_TEST_DIR2);
    return 0;
}
