#define GNU_SOURCE
#include <dirent.h>     /* Defines DT_* constants */
#include <fcntl.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/sendfile.h>
#include <errno.h>
#include <string.h>

#include "../test_utils.h"

#define BUF_LEN 10

#define SENDFILE_COUNT  8

//#define SENDFILE_DEBUG
#ifdef SENDFILE_DEBUG
#define sf_dbg(fmt, args...)	printf("[%s]" fmt , __func__, ##args)
#else
#define sf_dbg(fmt, args...)
#endif

#define sf_err(fmt, args...)	fprintf(stderr, "[%s] !ERROR! " fmt , __func__, ##args)

#define sf_err_goto(label, fmt, ...) do {   \
 fprintf(stderr, "[%s] !ERROR! " fmt , __func__, ##__VA_ARGS__); \
 goto label; \
} while (0)


int main(int argc, char *argv[])
{
    int ret;
    int i, j;
    int fd_in;
    int fd_out;
    char buf[BUF_LEN];
    char cmp_buf[BUF_LEN];

    fd_in = open("infile", O_WRONLY);
    if (fd_in < 0)
        sf_err_goto(err_fdin, "open write-only: %s\n", strerror(errno));
    fd_out = open("outfile", O_RDWR);
    if (fd_out < 0)
        sf_err_goto(err_fdout, "open outfile: %s\n", strerror(errno));
    ret = sendfile(fd_out, fd_in, NULL, BUF_LEN);
    if (ret != -1)
        sf_err_goto(err_fop, "could sendfile() %d bytes from write-only file\n",
            ret);
    else if (errno != EBADF)
        sf_err_goto(err_fdout, "[line %d] unexpected error: %s\n",  __LINE__,
            strerror(errno));
    if (close(fd_out) < 0)
        sf_err_goto(err_fdout, "close outfile: %s\n", strerror(errno));
    if (close(fd_in) < 0)
        sf_err_goto(err_fdin, "close infile: %s\n", strerror(errno));

    fd_in = open("infile", O_RDWR);
    if (fd_in < 0)
        sf_err_goto(err_fdin, "open infile: %s\n", strerror(errno));
    fd_out = open("outfile", O_RDONLY);
    if (fd_out < 0)
        sf_err_goto(err_fdout, "open read-only: %s\n", strerror(errno));
    ret = sendfile(fd_out, fd_in, NULL, BUF_LEN);
    if (ret != -1)
        sf_err_goto(err_fop, "could sendfile() %d bytes to read-only file\n",
            ret);
    else if (errno != EBADF)
        sf_err_goto(err_fdout, "[line %d] unexpected error: %s\n",  __LINE__,
            strerror(errno));
    if (close(fd_out) < 0)
        sf_err_goto(err_fdout, "close outfile: %s\n", strerror(errno));
    if (close(fd_in) < 0)
        sf_err_goto(err_fdin, "close infile: %s\n", strerror(errno));

    fd_in = open("infile", O_RDWR);
    if (fd_in == -1)
        sf_err_goto(err_fdin, "error %d opeing sendfile_test\n", errno);

    fd_out = open("outfile", O_RDWR);
    if (fd_out == -1) 
        sf_err_goto(err_fdout, "error %d opeing sendfile_test_out\n", errno);

    ret = sendfile(-1, fd_in, NULL, BUF_LEN);
    if ((ret != -1) || (errno != EBADF))
        sf_err_goto(err_fop, "sendfile returned %d (errno %d) with invalid output fd\n",
            ret, errno);

    sf_dbg("IN fd %d OUT fd %d\n", fd_in, fd_out);
    lseek(fd_out, 0, SEEK_SET);
    sf_dbg("Previous contents:\n");
    for (j = 0; j < SENDFILE_COUNT; j++) {
        if (read(fd_out, cmp_buf, sizeof(cmp_buf)) != sizeof(cmp_buf))
            sf_err_goto(err_fop, "Error in reading out file\n");
        for (i = 0; i < sizeof(cmp_buf); i++)
            sf_dbg("outfile[%d] = 0x%02x\n", j * BUF_LEN + i, cmp_buf[i]);
    }

    lseek(fd_in, 0, SEEK_SET);
    sf_dbg("Replaced with:\n");
    for (j = 0; j < SENDFILE_COUNT; j++) {
        ret = read(fd_in, buf, sizeof(buf));
        if (ret != sizeof(buf))
            sf_err_goto(err_fop, "Error reading. read %d of %d\n", ret, BUF_LEN);
        for (i = 0; i < sizeof(buf); i++)
            sf_dbg("infile[%d] = 0x%02x\n", j * BUF_LEN + i, buf[i]);
    }

    if (memcmp(buf, cmp_buf, sizeof(buf)) == 0)
        sf_err_goto(err_fop, "Initial contents similar. replace output file.\n");

    lseek(fd_out, 0, SEEK_SET);
    lseek(fd_in, 0, SEEK_SET);
    for (j = 0; j < SENDFILE_COUNT; j++) {
        ret = sendfile(fd_out, fd_in, NULL, BUF_LEN);
        if (ret != BUF_LEN)
            sf_err_goto(err_fop, "sendfile error %d. wrote %d of %d\n", errno, ret, BUF_LEN);
    }
    	
    printf("sendfile() success. validating contents\n");
    lseek(fd_in, 0, SEEK_SET);
    lseek(fd_out, 0,  SEEK_SET);
    sf_dbg("New file contents:\n");
    for (j = 0; j < SENDFILE_COUNT; j++) {
        ret = read(fd_in, buf, sizeof(buf));
        if (ret != sizeof(buf))
            sf_err_goto(err_fop, "Error reading from IN, read %d of %d\n", ret, BUF_LEN);
        ret = read(fd_out, cmp_buf, sizeof(cmp_buf));
        if (ret != sizeof(buf))
            sf_err_goto(err_fop, "Error reading from OUT, read %d of %d\n", ret, BUF_LEN);
        for (i = 0; i < sizeof(cmp_buf); i++)
            sf_dbg("buf[%d] = 0x%02x\n", j * BUF_LEN + i, cmp_buf[i]);
        if (memcmp(buf, cmp_buf, sizeof(buf)) != 0)
            sf_err_goto(err_fop, "sendfile() failed!!\n");
    }

    lseek(fd_in, 0, SEEK_SET);
    ret = sendfile(fd_out, fd_in, FAULT_ADDR, BUF_LEN);
    if ((ret != -1) || (errno != EFAULT))
        sf_err_goto(err_fop, "sendfile with faulting offset test failed (%d, %d)\n", ret, errno);

    close(fd_out);
    close(fd_in);

    printf("!!!Success!!!\n");
    exit (0);

err_fop:
    close(fd_out);
err_fdout:
    close(fd_in);
err_fdin:

    exit(1);
}


