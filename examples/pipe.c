#define _GNU_SOURCE
#include <stdio.h>
#include <unistd.h>
#include <runtime.h>
#include <sys/syscall.h>
#include <errno.h>

#define EXIT_SUCCESS 0

#define handle_error(msg) \
       do { perror(msg); exit(EXIT_FAILURE); } while (0)

// no good place to put this
table parse_arguments(heap h, int argc, char **argv);

int
__pipe(int fildes[2])
{
    return syscall(SYS_pipe, fildes);
}

int main(int argc, char **argv)
{
    int fd[2] = {0,0};
    const int BSIZE = 1000;
    ssize_t nbytes;
    int status;
    int i;

    char *test_string = "This is a pipe test string!";

    heap h = init_process_runtime();
    tuple t = parse_arguments(h, argc, argv);

    buffer in = allocate_buffer(h,BSIZE);
    buffer out = allocate_buffer(h,BSIZE);

    status = __pipe(fd);
    if (status == -1 )
        perror("pipe");

    printf("PIPE-CREATE - SUCCESS, fds %d %d\n", fd[0], fd[1]);

//#include <stdio.h>
//#include <string.h>
//#include <unistd.h>
//#include <fcntl.h>
//#include <sys/types.h>
//#include <sys/wait.h>

    nbytes = write(fd[1], test_string, runtime_strlen(test_string));
    if (nbytes == -1)
        perror("write");
    //fcntl(fd[0], F_SETFL, O_NONBLOCK);

    while ((nbytes = read(fd[0], buffer_ref(in, buffer_length(in)), 5)) > 0) {
        buffer_produce(in, nbytes);
    }
    buffer_write_byte(in, (u8)'\0');
    buffer_clear(in);

    if (runtime_strcmp(test_string, (const char *)buffer_ref(in, 0))) {
        printf("PIPE-RD/WR - ERROR - test message corrupted, expected %s and got %s\n",
            test_string, 
            (char *)buffer_ref(in, 0));
    } else
        printf("PIPE-RD/WR - SUCCESS - test message received\n");

    for (i = 0; i < 10; ++i) {
        nbytes = write(fd[1], buffer_ref(in,0), BSIZE);
        while ((nbytes = read(fd[0], buffer_ref(in, buffer_length(in)), BSIZE)) > 0) {
            buffer_produce(in, nbytes);
        }
        buffer_clear(in);
    }
    printf("PIPE-RD/WR-LARGE - SUCCESS\n");

    close(fd[0]);
    close(fd[1]);
    return(EXIT_SUCCESS);
}
