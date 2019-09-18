#include <runtime.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#define DEFAULT_PORT 5309
#define BUFLEN 1500

void fail(char * s)
{
    rprintf("%s failed: %s (errno %d)\n", s, strerror(errno), errno);
    exit(EXIT_FAILURE);
}

table parse_arguments(heap h, int argc, char **argv);

int main(int argc, char ** argv)
{
    heap h = init_process_runtime();
    tuple t = parse_arguments(h, argc, argv);
    u16 lport = DEFAULT_PORT;
    value v = table_find(t, sym(port));
    char buf[BUFLEN];

    u64 result;
    if (v && u64_from_value(v, &result)) {
	lport = result;
    }
    rprintf("using local port %d\n", lport);

    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0)
	fail("socket");

    struct sockaddr_in lsin;
    lsin.sin_family = AF_INET;
    lsin.sin_port = htons(lport);
    lsin.sin_addr.s_addr = htonl(INADDR_ANY);

    if (bind(fd, (struct sockaddr *)&lsin, sizeof(lsin)) < 0)
	fail("bind");

    struct sockaddr_in rsin;
    socklen_t rsin_len = sizeof(rsin);
    const char * tstr = "terminate";
    do {
	int rlen = recvfrom(fd, buf, BUFLEN, 0, (struct sockaddr *)&rsin, &rsin_len);
	if (rlen < 0)
	    fail("recvfrom");
	if (rlen == 0)
	    continue;

	int slen = sendto(fd, buf, rlen, 0, (struct sockaddr *)&rsin, rsin_len);
	// XXX retry on EINTR / EAGAIN
	if (slen < 0)
	    fail("sendto");

	int tlen = strlen(tstr);
	if (rlen >= tlen && strncmp(tstr, buf, tlen) == 0) {
	    rprintf("success\n");
	    close(fd);
	    exit(EXIT_SUCCESS);
	}
    } while(1);

    return 0;
}
