/* XXX TODO CVE-2018-3639 - SSBD 

https://bugs.chromium.org/p/project-zero/issues/detail?id=1528
https://developer.arm.com/support/arm-security-updates/speculative-processor-vulnerability
https://developer.arm.com/cache-speculation-vulnerability-firmware-specification
*/

#define FRAME_X0       0
#define FRAME_X1       1
#define FRAME_X2       2
#define FRAME_X3       3
#define FRAME_X4       4
#define FRAME_X5       5
#define FRAME_X6       6
#define FRAME_X7       7
#define FRAME_X8       8
#define FRAME_X9       9 
#define FRAME_X10      10
#define FRAME_X11      11
#define FRAME_X12      12
#define FRAME_X13      13
#define FRAME_X14      14
#define FRAME_X15      15
#define FRAME_X16      16
#define FRAME_X17      17
#define FRAME_X18      18
#define FRAME_X19      19
#define FRAME_X20      20
#define FRAME_X21      21
#define FRAME_X22      22
#define FRAME_X23      23
#define FRAME_X24      24
#define FRAME_X25      25
#define FRAME_X26      26
#define FRAME_X27      27
#define FRAME_X28      28
#define FRAME_X29      29       /* frame */
#define FRAME_X30      30       /* LR */
#define FRAME_SP       31
#define FRAME_SPSR_ESR 32
#define FRAME_ELR      33

#define FRAME_N_GPREG  32

/* SSBD? */

#define FRAME_VECTOR        34
#define FRAME_FAULT_HANDLER 35
#define FRAME_STACK_TOP     36
#define FRAME_RUN           37  /*dont like this construction */
#define FRAME_IS_SYSCALL    38
#define FRAME_QUEUE         39
#define FRAME_FULL          40
#define FRAME_THREAD        41
#define FRAME_HEAP          42
#define FRAME_MAX           43

