/* test for basic ftrace functionality */

#define _GNU_SOURCE
#include <time.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <errno.h>
#include <sched.h>
#include <signal.h>
#include <assert.h>

#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/prctl.h>

#include "../test_utils.h"

#define TRACE_DIR "/sys/kernel/debug/tracing"
#define FTRACE_CURRENT          TRACE_DIR "/current_tracer"
#define FTRACE_AVAILABLE        TRACE_DIR "/available_tracers"
#define FTRACE_TRACE            TRACE_DIR "/trace"
#define FTRACE_TRACING_ON       TRACE_DIR "/tracing_on"
#define FTRACE_TRACE_PIPE       TRACE_DIR "/trace_pipe"

#define BUF_SIZE 128

static void
open_and_read_max(const char  * fname,
                  unsigned long max_reads)
{
    char buf[BUF_SIZE];
    ssize_t bytes;
    int fd;
    unsigned long reads = 0;

    fd = open(fname, O_RDONLY);
    if (fd < 0) {
        test_perror("open %s", fname);
    }

    do {
        bytes = read(fd, buf, BUF_SIZE-1);
        if (bytes < 0) {
            if (errno == EINTR)
                continue;

            test_perror("read %s", fname);
        }

        buf[bytes] = '\0';
        if (bytes > 0)
            printf("%s", buf);
    } while (bytes > 0 && ++reads < max_reads);

    close(fd);
}

#define open_and_read(fname) open_and_read_max(fname, (1ULL << 30))

static void
open_and_write(const char * fname, const char * str)
{
    ssize_t bytes;
    int fd;

    fd = open(fname, O_RDWR);
    if (fd < 0) {
        test_perror("open %s", fname);
    }

    bytes = write(fd, str, strlen(str));
    if (bytes < 0) {
        test_error("write to %s", fname);
    }

    close(fd);
}

#if 0
static void
alrm(int signo) {}

static int
register_alarm(unsigned long sec)
{
    alarm(sec);

    return 0;
}

static int
register_timeout(unsigned long sec)
{
    struct sigaction sa;
    int ret;

    memset(&sa, 0, sizeof(struct sigaction));
    sa.sa_handler = alrm;
    sigemptyset(&sa.sa_mask);

    ret = sigaction(SIGALRM, &sa, NULL); 
    if (ret != 0) {
        test_perror("sigaction");
    }

    return register_alarm(sec);
}
#endif

int main(int argc, char * argv[])
{
    prctl(PR_SET_NAME, "ftrace_test");

    printf("available tracers: ");
    open_and_read(FTRACE_AVAILABLE);

    printf("current tracer: ");
    open_and_read(FTRACE_CURRENT);

    open_and_write(FTRACE_CURRENT, "function");
    open_and_write(FTRACE_TRACING_ON, "1");

    printf(">>>> trace data:\n");
    open_and_read(FTRACE_TRACE);
    printf("<<<< end trace data\n");
    printf("\n\n");

    open_and_write(FTRACE_CURRENT, "function_graph");

    printf(">>>> trace_pipe data:\n");
    open_and_read_max(FTRACE_TRACE_PIPE, 100);

    printf("\n<<<< end trace_pipe data:\n");

    printf("ftrace test passed\n");
    exit(EXIT_SUCCESS);
}
