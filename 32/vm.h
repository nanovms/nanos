typedef u64 address;


#define PAGELOG 12
#define PAGESIZE (1<<PAGELOG)
#define PAGEMASK ((1ull<<PAGELOG)-1)


void map(address virtual, address physical, int length);
