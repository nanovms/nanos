#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/vfs.h>
#include <assert.h>
#include <errno.h>
#include <config.h>

#define BIGDATA "bigfile"
#define NEWFILE "newfile"
#define SECTOR_SIZE 512
#define NUM_WRITE_RETRIES 2
/* this could be up to log ext size */
#define MAX_FREE_BYTES (512 * 1024)

int write_blocks(int fd, int nb, int bs)
{
    assert(bs && (bs & (SECTOR_SIZE-1)) == 0);
    uint8_t *buf = malloc(bs);
    assert(buf);
    int b, bw, br;

    for (b = 0; b < nb; b++) {
        uint64_t *p = (uint64_t *)buf;
        int retries;
        while (p < (uint64_t *)(buf + bs))
            *p++ = b;
        /* retry because sometimes additional space is released after final write */
        retries = 0;
        while ((bw = pwrite(fd, buf, bs, bs * b)) <= 0 && retries < NUM_WRITE_RETRIES) {
            assert(errno == ENOSPC);
            retries++;
            usleep(1000000 * TFS_LOG_FLUSH_DELAY_SECONDS);
        }
        if (bw <= 0) {
            printf("failed writing at block %d err '%s'\n", b, strerror(errno));
            goto out;
        }
        assert(bw % SECTOR_SIZE == 0);
        if ((br = pread(fd, buf, bs, bs * b)) != bw) {
            printf("failed to read written block %d rv %d err '%s'\n", b, br, strerror(errno));
            b = -1;
            break;
        }
        p = (uint64_t *)buf;
        while (p < (uint64_t *)(buf + bs)) {
            if (*p++ != b) {
                printf("block %d does not match expected pattern in validation\n", b);
                b = -1;
                goto out;
            }
        }
    }
out:
    free(buf);
    return b;
}

int check_blocks(int fd, int nb, int bs)
{
    assert(bs && (bs & (SECTOR_SIZE-1)) == 0);
    uint8_t *buf = malloc(bs);
    assert(buf);
    int b;

    for (b = 0; b < nb; b++) {
        if (read(fd, buf, bs) <= 0) {
            printf("failed reading at block %d err '%s'\n", b, strerror(errno));
            break;
        }
        uint64_t *p = (uint64_t *)buf;
        while (p < (uint64_t *)(buf + bs)) {
            if (*p++ != b) {
                printf("block %d does not match expected pattern\n", b);
                goto out;
            }
        }
    }
out:
    free(buf);
    return b;
}

int main(int argc, char **argv)
{
    struct statfs statbuf;
    int fd;

    assert(statfs(argv[0], &statbuf) == 0);
    uint64_t bfree = statbuf.f_bfree;
    uint64_t btotal = statbuf.f_blocks;
    assert(statbuf.f_bsize >= SECTOR_SIZE);
    int BLOCKSIZE = statbuf.f_bsize;
    printf("total bytes: %lu free bytes: %lu blocksize: %d\n", btotal * statbuf.f_bsize, bfree * statbuf.f_bsize, BLOCKSIZE);

    /* create big file test */
    fd = open(BIGDATA, O_CREAT|O_RDWR, 0644);
    assert(fd >= 0);
    int64_t bwritten = write_blocks(fd, bfree, BLOCKSIZE);
    assert(bwritten >= 0);
    assert(statfs(argv[0], &statbuf) == 0);
    printf("written blocks: %lu\ncalculated free blocks: %lu\nactual free blocks %lu\nmetadata blocks allocated: %lu\n",
        bwritten, bfree - bwritten, statbuf.f_bfree, bfree - bwritten - statbuf.f_bfree);
    assert(statbuf.f_bfree < MAX_FREE_BYTES/BLOCKSIZE);
    close(fd);

    /* check that still can't write to a new file */
    fd = open(NEWFILE, O_CREAT|O_RDWR, 0644);
    if (fd >= 0) {
        assert(write_blocks(fd, 32, BLOCKSIZE) <= statbuf.f_bfree);
        close(fd);
    }
    /* verify big file */
    fd = open(BIGDATA, O_RDWR);
    assert(fd >= 0);
    assert(check_blocks(fd, bwritten, BLOCKSIZE) == bwritten);
    close(fd);
    assert(statfs(argv[0], &statbuf) == 0);
    printf("after verifying big file: total bytes: %lu free bytes: %lu\n", statbuf.f_blocks * statbuf.f_bsize, statbuf.f_bfree * statbuf.f_bsize);
    assert(statbuf.f_blocks == btotal);

    /* remove big file and verify free space */
    assert(remove(BIGDATA) == 0);
    /* Checking free space immediately may not reflect removed file */
    sync();
    usleep(1000*1000);
    assert(statfs(argv[0], &statbuf) == 0);
    printf("after delete big file: total bytes: %lu free bytes: %lu\n", statbuf.f_blocks * statbuf.f_bsize, statbuf.f_bfree * statbuf.f_bsize);
    assert((bfree - statbuf.f_bfree) < bfree/10);

    /* check that we can now write to a new file */
    fd = open(NEWFILE, O_CREAT|O_RDWR, 0644);
    assert(fd >= 0);
    printf("write %lu blocks to new file\n", bwritten);
    uint64_t new_bwritten = write_blocks(fd, bwritten, BLOCKSIZE);
    printf("wrote %lu blocks\n", new_bwritten);
    /* space for two new logs could be allocated since the first write */
    assert(new_bwritten >= bwritten - 2 * MAX_FREE_BYTES/BLOCKSIZE);
    close(fd);
    assert(remove(NEWFILE) == 0);
    assert(open(BIGDATA, O_RDWR) < 0);
    printf("filesystem full test successful\n");
    return 0;
}
