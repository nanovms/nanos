#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/vfs.h>
#include <assert.h>
#include <errno.h>

#define BIGDATA "/bigfile"
#define NEWFILE "/newfile"

int write_blocks(int fd, int nb)
{
    uint8_t buf[512];
    int b;
    for (b = 0; b < nb; b++) {
        uint64_t *p = (uint64_t *)buf;
        while (p < (uint64_t *)(buf + sizeof(buf)))
            *p++ = b;
        if (write(fd, buf, sizeof(buf)) <= 0) {
            printf("failed writing at block %d err '%s'\n", b, strerror(errno));
            assert(errno == ENOSPC);
            break;
        }
        if (pread(fd, buf, sizeof(buf), 512 * b) != sizeof(buf)) {
            printf("failed to read written block %d err '%s'\n", b, strerror(errno));
            break;
        }
        p = (uint64_t *)buf;
        while (p < (uint64_t *)(buf + sizeof(buf))) {
            if (*p++ != b) {
                printf("block %d does not match expected pattern in validation\n", b);
                return b;
            }
        }
    }
    return b;
}

int check_blocks(int fd, int nb)
{
    uint8_t buf[512];
    int b;
    for (b = 0; b < nb; b++) {
        if (read(fd, buf, sizeof(buf)) <= 0) {
            printf("failed reading at block %d err '%s'\n", b, strerror(errno));
            break;
        }
        uint64_t *p = (uint64_t *)buf;
        while (p < (uint64_t *)(buf + sizeof(buf))) {
            if (*p++ != b) {
                printf("block %d does not match expected pattern\n", b);
                return b;
            }
        }
    }
    return b;
}

int main(int argc, char **argv)
{
    struct statfs statbuf;
    int fd;

    setbuf(stdout, NULL);
    assert(statfs(argv[0], &statbuf) == 0);
    uint64_t bfree = statbuf.f_bfree;
    uint64_t btotal = statbuf.f_blocks;
    printf("total bytes: %lu free bytes: %lu\n", btotal * 512, bfree * 512);
    /* create big file test */
    fd = open(BIGDATA, O_CREAT|O_RDWR, 0644);
    assert(fd >= 0);
    uint64_t bwritten = write_blocks(fd, bfree);
    assert(statfs(argv[0], &statbuf) == 0);
    assert(bfree - bwritten < bfree/10);
    close(fd);
    /* check that still can't write to a new file */
    fd = open(NEWFILE, O_CREAT|O_RDWR, 0644);
    if (fd >= 0) {
        assert(write_blocks(fd, 32) == 0);
        close(fd);
    }
    /* verify big file */
    fd = open(BIGDATA, O_RDWR);
    assert(fd >= 0);
    assert(check_blocks(fd, bwritten) == bwritten);
    close(fd);
    assert(statfs(argv[0], &statbuf) == 0);
    assert(statbuf.f_bfree < bfree/10);
    assert(statbuf.f_blocks == btotal);
    printf("after creating big file: total bytes: %lu free bytes: %lu\n", statbuf.f_blocks * 512, statbuf.f_bfree * 512);
    assert(remove(BIGDATA) == 0);
    assert(statfs(argv[0], &statbuf) == 0);
    assert((bfree - statbuf.f_bfree) < bfree/10);
    printf("after delete big file: total bytes: %lu free bytes: %lu\n", statbuf.f_blocks * 512, statbuf.f_bfree * 512);

    /* check that we can now write to a new file */
    fd = open(NEWFILE, O_CREAT|O_RDWR, 0644);
    assert(fd >= 0);
    assert(write_blocks(fd, 32) == 32);
    close(fd);
    assert(open(BIGDATA, O_RDWR) < 0);
    printf("filesystem full test successful\n");
    return 0;
}
