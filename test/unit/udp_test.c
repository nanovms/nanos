#include <runtime.h>
#include <ip.h>

#include <errno.h>
#include <string.h>

// XXX lame - please fix
//#include <stdlib.h>
void exit(int status);
#define EXIT_FAILURE 1
#define EXIT_SUCCESS 0

#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#define DEFAULT_LOCAL_PORT 9035
#define DEFAULT_LOCAL_ITERATIONS 100
#define BUFLEN 1500
#define MSGSIZE 512

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
    value unassoc = table_find(t, sym(unassociated));
    if (!unassoc)
        halt("specify target as <ip addr>:<port>\n");
    boolean terminate = table_find(t, sym(terminate)) != 0;

    char sbuf[BUFLEN], rbuf[BUFLEN];

    buffer target = vector_pop(vector_from_tuple(h, unassoc));
    u32 daddr;
    u16 dport;
    parse_v4_address_and_port(target, &daddr, &dport);

    u16 lport = DEFAULT_LOCAL_PORT;
    value v = table_find(t, sym(localport));
    if (v)
	lport = (u16)u64_from_value(v);

    int iterations = DEFAULT_LOCAL_ITERATIONS;
    v = table_find(t, sym(iterations));
    if (v)
	iterations = (int)u64_from_value(v);

    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0)
	fail("socket");

    struct sockaddr_in lsin;
    lsin.sin_family = AF_INET;
    lsin.sin_port = htons(lport);
    lsin.sin_addr.s_addr = htonl(INADDR_ANY);

    if (bind(fd, (struct sockaddr *)&lsin, sizeof(lsin)) < 0)
	fail("bind");

    struct sockaddr_in dsin;
    dsin.sin_family = AF_INET;
    dsin.sin_port = htons(dport);
    dsin.sin_addr.s_addr = htonl(daddr);

    if (connect(fd, (struct sockaddr *)&dsin, sizeof(dsin)) < 0)
	fail("connect");

    struct sockaddr_in rsin;
    socklen_t rsin_len;
    for (int i = 0; i < iterations; i++) {
	memset(sbuf, i % 256, MSGSIZE);
	if (i == iterations - 1 && terminate)
	    strcpy(sbuf, "terminate");

	int slen = sendto(fd, sbuf, MSGSIZE, 0, (struct sockaddr *)&dsin, sizeof(dsin));
	// XXX retry on EINTR / EAGAIN
	if (slen < 0)
	    fail("sendto");

	int rlen = recvfrom(fd, rbuf, BUFLEN, 0, (struct sockaddr *)&rsin, &rsin_len);
	if (rlen < 0)
	    fail("recvfrom");
	// XXX retry

	if (rlen != MSGSIZE)
	    fail("length mismatch");

	if (memcmp(sbuf, rbuf, MSGSIZE))
	    fail("payload mismatch");
    }

    rprintf("success\n");
    exit(EXIT_SUCCESS);
}
