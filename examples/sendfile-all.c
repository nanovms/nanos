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

int sendfile(int inf, int outf, char *offs, size_t count)
{
    return syscall(SYS_sendfile, inf, outf, offs, count);
}

int main()
{
    int ret = 0;
     
    sf_dbg("\n\n[%d]Sendfile Pipe:\n", ret);
    ret = sendfile_pipe();
    sf_dbg("\n\n[%d]Sendfile Socket:\n", ret);
    ret = sendfile_sock();
    sf_dbg("\n\nSendfile File:\n");
    ret = sendfile_file();
 

    exit(0);
}


