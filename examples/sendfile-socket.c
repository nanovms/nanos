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

int sendfile_sock()
{
    int ret;
    int i;
    int fd_in;
    int sock_fd;
    char buf[BUF_LEN];
    char cmp_buf[BUF_LEN];
    socklen_t sock_len = sizeof(struct sockaddr_in);

    sock_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock_fd < 0)
        sf_err_goto(err_sockfd, "error %d in socket()\n", errno);
    fd_in = open("infile", O_RDWR);
    if (fd_in == -1)
        sf_err_goto(err_fdin, "error %d opeing sendfile_test\n", errno);

    lseek(fd_in, 0, SEEK_SET);
    ret = sendfile(sock_fd, fd_in, NULL, BUF_LEN);
    if (ret != BUF_LEN)
	    sf_err_goto(err_fop, "sendfile error %d. wrote %d of %d\n", errno, ret, BUF_LEN);

    sf_dbg("sendfile ret %d:\n", ret);
//    int rlen = read(sock_fd, cmp_buf, BUF_LEN);
//    sf_dbg("Read %d:\n", rlen);
//    for (i = 0; i < rlen; i++)
//        sf_dbg("%c", cmp_buf[i]);
    sf_dbg("\n");
    	
    close(fd_in);

    printf("!!!Success!!!\n");
    return (0);

err_fop:
err_fdout:
    close(fd_in);
err_fdin:
    close(sock_fd);
err_sockfd:

    return(1);
}


