#include <getrandom.h>
#include <errno.h>

//declare a static variable for seeding the rand() function
static unsigned int seed;

//custom random-number generator using the model of linear congruential generators-->n(x+1) = n(x) * A + C modulo M
int rand (void) 
{
	seed = (seed * 1103515245U + 12345U) & 0x7fffffffU;
    return (int)seed;
}

/*Function: fills the buffer with bufLength random values and returns the number of random values filled
  buf: buffer to be filled
  bufLength: length of the buffer
  flags: comparable to GRND_NONBLOCK(has a value of 1) and GRND_RANDOM (has a value of 2)flags in actual linux function
  
	Logic:	-if buffer is NULL, returns -1
			-as per the actual implementation, proper values of flags range from 0 to 3, though implementation is clearly 
			 defined only for values 1--GRND_NONBLOCK and 2--GRND_RANDOM.
			-So for 1, it doesnt block and populates the entire buffer with random values
			-for 2, max value is 256; so for bufLength>256, values populated are zero and the function returns 256
*/
int getrandom(void *buf,int bufLength,unsigned int flags)
{
	if(!buf)
		return EFAULT;
	
	//in case of undefined flag values
	if(bufLength <= 0 || (flags & ~(GRND_RANDOM | GRND_NONBLOCK)))
		return EINVAL; 
	
	//for unique values at program start
	seed = getpid();
	int count=0;
	runtime_memset(buf,0,bufLength);
	for(int i=0;i<bufLength;i++)
	{
		*(char*)(buf+i)=rand()%MAX_ENTROPY_POOL;
		//printf("%c\n",*(char*)(buf+i));
		count++;
		if(flags==GRND_RANDOM && i==(MAX_RANDOM_ENTROPY_COUNT-1))
			break;
	}
	return count;
}


