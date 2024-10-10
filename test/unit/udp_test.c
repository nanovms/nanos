#include <runtime.h>
#include <ip.h>

#include <errno.h>
#include <string.h>

#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#include "../test_utils.h"

#define DEFAULT_LOCAL_PORT 9035
#define DEFAULT_LOCAL_ITERATIONS 100
#define BUFLEN 1500
#define MSGSIZE 512

int main(int argc, char ** argv)
{
    heap h = init_process_runtime();
    tuple t = parse_arguments(h, argc, argv);
    vector unassoc = get_vector(t, sym(unassociated));
    if (!unassoc)
        halt("specify target as <ip addr>:<port>\n");
    boolean terminate = get(t, sym(terminate)) != 0;

    char sbuf[BUFLEN], rbuf[BUFLEN];

    buffer target = vector_pop(unassoc);
    u32 daddr;
    u16 dport;
    if (!parse_v4_address_and_port(target, &daddr, &dport))
        test_error("failed to parse address and port");

    u16 lport = DEFAULT_LOCAL_PORT;
    u64 result;
    if (get_u64(t, sym(localport), &result))
        lport = result;

    int iterations = DEFAULT_LOCAL_ITERATIONS;
    if (get_u64(t, sym(iterations), &result))
        iterations = result;

    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0)
        test_perror("socket");

    struct sockaddr_in lsin;
    lsin.sin_family = AF_INET;
    lsin.sin_port = htons(lport);
    lsin.sin_addr.s_addr = htonl(INADDR_ANY);

    if (bind(fd, (struct sockaddr *)&lsin, sizeof(lsin)) < 0)
        test_perror("bind");

    struct sockaddr_in dsin;
    dsin.sin_family = AF_INET;
    dsin.sin_port = htons(dport);
    dsin.sin_addr.s_addr = htonl(daddr);

    if (connect(fd, (struct sockaddr *)&dsin, sizeof(dsin)) < 0)
        test_perror("connect");

    struct sockaddr_in rsin;
    socklen_t rsin_len;
    for (int i = 0; i < iterations; i++) {
	memset(sbuf, i % 256, MSGSIZE);
	if (i == iterations - 1 && terminate)
	    strcpy(sbuf, "terminate");

	int slen = sendto(fd, sbuf, MSGSIZE, 0, (struct sockaddr *)&dsin, sizeof(dsin));
	// XXX retry on EINTR / EAGAIN
	if (slen < 0)
	    test_perror("sendto");

	int rlen = recvfrom(fd, rbuf, BUFLEN, 0, (struct sockaddr *)&rsin, &rsin_len);
	if (rlen < 0)
	    test_perror("recvfrom");
	// XXX retry

	if (rlen != MSGSIZE)
	    test_error("length mismatch");

	if (memcmp(sbuf, rbuf, MSGSIZE))
	    test_error("payload mismatch");
    }

    rprintf("success\n");
    exit(EXIT_SUCCESS);
}
