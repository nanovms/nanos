#define FRAME_RAX 0
#define FRAME_RBX 1
#define FRAME_RCX 2
#define FRAME_RDX 3
#define FRAME_RSI 4
#define FRAME_RDI 5
#define FRAME_RBP 6
#define FRAME_RSP 7
#define FRAME_R8  8
#define FRAME_R9  9 
#define FRAME_R10 10
#define FRAME_R11 11
#define FRAME_R12 12
#define FRAME_R13 13
#define FRAME_R14 14
#define FRAME_R15 15

#define FRAME_RIP 16
#define FRAME_FLAGS 17
#define FRAME_SS 18
#define FRAME_CS 19
#define FRAME_DS 20
#define FRAME_ES 21
#define FRAME_FSBASE 22
#define FRAME_GSBASE 23

#define FRAME_VECTOR 24

#define FRAME_ERROR_PF_P   0x01    /* prot violation */
#define FRAME_ERROR_PF_RW  0x02    /* write access */
#define FRAME_ERROR_PF_US  0x04    /* user access */
#define FRAME_ERROR_PF_RSV 0x08    /* pte reserved set */
#define FRAME_ERROR_PF_ID  0x10    /* instruction fetch */

#define FRAME_ERROR_CODE 25
#define FRAME_FAULT_HANDLER 26
#define FRAME_STACK_TOP 27
#define FRAME_STACK_BOTTOM 28 /* ??*/
#define FRAME_SAVED_FRAME 29

#define FRAME_CR2 30
#define FRAME_RUN 31 /*dont like this construction */
#define FRAME_IS_SYSCALL 32 
#define FRAME_QUEUE 33
#define FRAME_FULL 34 
#define FRAME_THREAD 35
#define FRAME_HEAP 36
#define FRAME_MAX 37
#define FRAME_EXTENDED_SAVE 40

