/* sendfile test for pipe() 
 * 1) open infile from the filesystem
 * 2) Create a pipe
 * 3) Use sendfile to read some bytes from infile to the write end of the pipe
 * 4) Read the read end of the pipe and compare contents
 */

#define GNU_SOURCE
#include <dirent.h>     /* Defines DT_* constants */
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include <errno.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <runtime.h>
#include "sendfile_test.h"

#define BUF_LEN 10

#define SENDFILE_DEBUG
#ifdef SENDFILE_DEBUG
#define sf_dbg(fmt, args...)	fprintf(stderr, "[%s]" fmt , __func__, ##args)
#else
#define sf_dbg(fmt, args...)
#endif

#define sf_err(fmt, args...)	fprintf(stderr, "[%s] !ERROR! " fmt , __func__, ##args)

#define sf_err_goto(label, fmt, ...) do {   \
 fprintf(stderr, "[%s] !ERROR! " fmt , __func__, ##__VA_ARGS__); \
 goto label; \
} while (0)


int __pipe(int filedes[2])
{
    return syscall(SYS_pipe, filedes);
}

const char *pipe_read(int filedes[2], int len)
{
    int nbytes;
    heap h = init_process_runtime();
    buffer in = allocate_buffer(h, len);

    while ((nbytes = read(filedes[0], buffer_ref(in, buffer_length(in)), len))) {
        buffer_produce(in, nbytes);
    }
    buffer_write_byte(in, (u8)'\0');
    buffer_clear(in);

    return (const char *)buffer_ref(in, 0);
}

int sendfile_pipe()
{
    int ret = 1;
    int res;
    int i;
    int fd_in;
    int pi[2];
    char buf[BUF_LEN];
    const char *pipe_res;

    ret = __pipe(pi);
    if (ret < 0)
        return (1);
    fd_in = open("infile", O_RDWR);
    if (fd_in == -1)
        sf_err_goto(err_fdin, "error %d opeing sendfile_test\n", errno);
    lseek(fd_in, 0, SEEK_SET);
    ret = read(fd_in, buf, BUF_LEN);
    if (ret != BUF_LEN)
        sf_err_goto(err_fop, "read %d of %d\n", ret, BUF_LEN);

    sf_dbg("pipe0 %d, pipe1 %d, fd %d\n", pi[0], pi[1], fd_in);
    res = sendfile(pi[1], fd_in, NULL, BUF_LEN);
    if (res != BUF_LEN)
	    sf_err_goto(err_fop, "sendfile error %d. wrote %d of %d\n", errno, res, BUF_LEN);
    
    pipe_res = pipe_read(pi, BUF_LEN);
    sf_dbg("pipe res[%d] %s\n", strlen(pipe_res), pipe_res);
    if (pipe_res != res)
        sf_err_goto(err_fop, "lengths differ");

    if (strncmp(pipe_res, buf, BUF_LEN) != 0) 
        sf_err_goto(err_fop, "data_differ");

    sf_dbg("!!!%s Success!!!\n", __func__);

    ret = 0;

err_fop:
    close(fd_in);
err_fdin:
    close(pi[0]);
    close(pi[1]);

    return(ret);
}
