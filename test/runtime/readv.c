#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <string.h>
#include <sys/uio.h>

#define PRINT_B(iov) \
	for(int i = 0; i < 4; i++) \
		printf("'%c'", ((char*)iov.iov_base)[i]); \
	printf("\n");

int main()
{
	struct iovec iovs[3];
	char onev[4], twov[4], threev[4];
	iovs[0].iov_base = onev;
	iovs[1].iov_base = twov;
	iovs[2].iov_base = threev;
	iovs[0].iov_len = iovs[1].iov_len = iovs[2].iov_len = 4;

	int fd = open("hello", O_RDWR);
	if (fd < 0) {
		perror("open");
		exit(EXIT_FAILURE);
	}

	int rv = readv(fd, iovs, 3);
	if(rv < 0) {
		printf("\nread unsuccessful");
		exit(EXIT_FAILURE);
	}

	if ((strncmp("one ", iovs[0].iov_base, 4) != 0) ||
	    (strncmp("six ", iovs[1].iov_base, 4) != 0) ||
	    (strncmp("four", iovs[2].iov_base, 4) != 0)) {
		printf("readv failed");
		exit(EXIT_FAILURE);
	}

	printf("read %d bytes\n", rv);
	PRINT_B(iovs[0]);
	PRINT_B(iovs[1]);
	PRINT_B(iovs[2]);
	return EXIT_SUCCESS;
}
