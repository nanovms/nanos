//definitions as per man page of getrandom(2)
#define MAX_ENTROPY_POOL 4096
#define GRND_NONBLOCK 1
#define GRND_RANDOM 2
#define MAX_RANDOM_ENTROPY_COUNT 256

//declare a static variable for seeding the rand() function
static unsigned int seed = 1;

//useful to seed the value with a fresh value everytime the program runs
void srand (int newseed) {
    seed = (unsigned)newseed & 0x7fffffffU;
	

}

//custom random-number generator using the model of linear congruential generators-->n(x+1) = n(x) * A + C modulo M
int rand (void) {
	
    seed = (seed * 1103515245U + 12345U) & 0x7fffffffU;
    return (int)seed;
}

//sets the memory with the specified integer value; equivalent function of memset()
void *setMemory(void *ptr, int value, int length)
{
	char *p;
	int m;

	p = ptr;
	m = length;
	while (--m >= 0)
		*p++ = value;

	return ptr;
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
	//if buffer is NULL, then return -1 as the value
	if(!buf)
		return -1;
	//initially set the complete buffer to zero, so even if GRND_RANDOM is set, the remaining buffer is filled with zeroes
	setMemory(buf,0,bufLength);
	
	//returns 0 in case of undefined flag values
	if(flags<0 || flags>3)
	{		
		return 0; 
	}
	int count=0;
	
	//to get random values everytime we run the program, use a new seed to start;choose either current system time or the pid() for a fresh value
	srand(getpid());
	
	//fill the buffer with random values
	for(int i=0;i<bufLength;i++)
	{
		*(int*)(buf+i)=rand()%MAX_ENTROPY_POOL;
		//uncomment to see the buffer values
		//printf("%u\n",*(int*)(buf+i));
		count++;
		if(flags==GRND_RANDOM && i==(MAX_RANDOM_ENTROPY_COUNT-1))
			break;
	}
	return count;
	
}

//main function to test the getrandom function
void main()
{
	//buffer length
	int length=257;
	
	//dynamically allocate memory before passing it to the function; could be of any type, char* for byte and int* for integers..
	int *buffer=(int*)malloc(length*sizeof(int));
	
	//acceptables values rabge from 0 to 3; if 2, maximum random values returned will be 256
	unsigned int flags=2;
	
	//call function and print the number of random bytes filled
	int totBytesfilled=getrandom(buffer,length,flags);
	printf("%d\n",totBytesfilled);
	
	return;
	
}

