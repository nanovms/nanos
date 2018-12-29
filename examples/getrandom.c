#define _GNU_SOURCE
#include <stdio.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <linux/random.h>
#include <errno.h>
#include <math.h>

#define BUF_LEN 128

static int hash[256];

 void *malloc(size_t size);
       void free(void *ptr);


int
__getrandom(void *buf, int i, int f)
{
    return syscall(SYS_getrandom, buf, i, f);
}

int main(int argc, char **argvp)
{
    int r, i, j;
    char *buffer = malloc(BUF_LEN);
    if (!buffer) {
        printf("failed to allocate a buffer\n");
        return 1;
    }

    r = __getrandom(buffer, BUF_LEN, 0);
    if (r != 128) {
        printf("didn't get enough bytes: r = %d, errno = %d\n", r, errno);
        return 2;
    }

    /* Estimate Shannon entropy by:
     *
     * 1) calculate probabilities for each value
     * 2) calculate the log2 of each probability
     * 3) negative sum them up 
     */
    for (i = 0; i < BUF_LEN; i ++)
        hash[(unsigned char) buffer[i]] ++;

    /* now P(i) = hash[i] / BUF_LEN */

    double entropy = 0;
    for (i = 0; i < 256; i ++) {
        double pi = ((double) hash[i]) / BUF_LEN;
        if (pi < (double) 0.000001) {
            pi = (double) 0.000001;
        }

        double log2pi = (double)log(pi) / (double)log(2);
        entropy += (double)pi * (double)log2pi;
    }

    entropy *= (double) -1;
    printf("Shannon Entropy of getrandom(2) is %f bits per byte\n", entropy);
    return 0;
}
