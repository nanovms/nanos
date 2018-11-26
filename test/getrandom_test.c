#define INT_MAX 0x7fffffff
#include <getrandom.h>
void main()
{
	int length=257;
	char *buffer=(char*)malloc(length*sizeof(char));
	unsigned int flags=2;
	int totBytesfilled=getrandom(buffer,length,flags);
	printf("%d\n",totBytesfilled);

	if(totBytesfilled<0)
	{
		printf("Error occured with filling the buffer with random bytes\n");
	}

	return;
	
}