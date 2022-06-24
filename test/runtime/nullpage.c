#include <stdio.h>
#include <string.h>

int
main()
{
	printf("started\n");

	char *p = 0;
	memcpy(p, "\xcd\x03", 2);

	printf("before\n");
	((void(*)())p)();
	printf("after\n");

	return 0;
}
