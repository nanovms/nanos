#define _GNU_SOURCE
#include <stdio.h>
#include <unistd.h>
#include <runtime.h>
#include <sys/syscall.h>
#include <errno.h>

#define EXIT_SUCCESS 0

#define handle_error(msg) \
       do { perror(msg); exit(EXIT_FAILURE); } while (0)

int
__pipe(int fildes[2])
{
    return syscall(SYS_pipe, fildes);
}

int main(int argc, char **argvp)
{
    int fd[2] = {0,0};
    const int BSIZE = 100;
    char buf[BSIZE];
    ssize_t nbytes;
    int status;

    status = __pipe(fd);
    if (status == -1 )
        perror("pipe");

    printf("Successfully issued  pipe syscall %d %d\n", fd[0], fd[1]);

//#include <stdio.h>
//#include <string.h>
//#include <unistd.h>
//#include <fcntl.h>
//#include <sys/types.h>
//#include <sys/wait.h>

    nbytes = write(fd[1], "yo", runtime_strlen("yo"));
    if (nbytes == -1)
        perror("write");
    //fcntl(fd[0], F_SETFL, O_NONBLOCK);

    while ((nbytes = read(fd[0], buf, 5)) > 0) {
        //write(1, buf, nbytes);
        // for now until we have a better way
        buf[nbytes] = '\0';
        printf("%s\n", buf);
    }

    close(fd[0]);
    close(fd[1]);
    return(EXIT_SUCCESS);
}
