/* XXX TODO CVE-2018-3639 - SSBD 

https://bugs.chromium.org/p/project-zero/issues/detail?id=1528
https://developer.arm.com/support/arm-security-updates/speculative-processor-vulnerability
https://developer.arm.com/cache-speculation-vulnerability-firmware-specification
*/

/* don't change the order of these without updating frame save/return double word accesses */
#define FRAME_X0            0
#define FRAME_X1            1
#define FRAME_X2            2
#define FRAME_X3            3
#define FRAME_X4            4
#define FRAME_X5            5
#define FRAME_X6            6
#define FRAME_X7            7
#define FRAME_X8            8
#define FRAME_X9            9
#define FRAME_X10           10
#define FRAME_X11           11
#define FRAME_X12           12
#define FRAME_X13           13
#define FRAME_X14           14
#define FRAME_X15           15
#define FRAME_X16           16
#define FRAME_X17           17
#define FRAME_X18           18
#define FRAME_X19           19
#define FRAME_X20           20
#define FRAME_X21           21
#define FRAME_X22           22
#define FRAME_X23           23
#define FRAME_X24           24
#define FRAME_X25           25
#define FRAME_X26           26
#define FRAME_X27           27
#define FRAME_X28           28
#define FRAME_X29           29  /* frame */
#define FRAME_X30           30  /* LR */
#define FRAME_SP            31
#define FRAME_N_GPREG       32
#define FRAME_ESR_SPSR      32
#define FRAME_ELR           33  /* pc */
#define FRAME_TPIDR_EL0     34  /* tls */
#define FRAME_N_PSTATE      35

#define FRAME_VECTOR        35
#define FRAME_FAULT_ADDRESS 36
#define FRAME_STACK_TOP     37
#define FRAME_EL            38
#define FRAME_FULL          39
#define FRAME_SAVED_X0      40
#define FRAME_TXCTX_FLAGS   41
#define FRAME_TXCTX_TPIDR_EL0_SAVED 1
#define FRAME_TXCTX_FPSIMD_SAVED    2
#define FRAME_EXTENDED      42
#define FRAME_SIZE          43

#define FRAME_Q0            0
#define FRAME_Q1            2
#define FRAME_Q2            4
#define FRAME_Q3            6
#define FRAME_Q4            8
#define FRAME_Q5            10
#define FRAME_Q6            12
#define FRAME_Q7            14
#define FRAME_Q8            16
#define FRAME_Q9            18
#define FRAME_Q10           20
#define FRAME_Q11           22
#define FRAME_Q12           24
#define FRAME_Q13           26
#define FRAME_Q14           28
#define FRAME_Q15           30
#define FRAME_Q16           32
#define FRAME_Q17           34
#define FRAME_Q18           36
#define FRAME_Q19           38
#define FRAME_Q20           40
#define FRAME_Q21           42
#define FRAME_Q22           44
#define FRAME_Q23           46
#define FRAME_Q24           48
#define FRAME_Q25           50
#define FRAME_Q26           52
#define FRAME_Q27           54
#define FRAME_Q28           56
#define FRAME_Q29           58
#define FRAME_Q30           60
#define FRAME_Q31           62
#define FRAME_FPSR          64
#define FRAME_FPCR          65
#define FRAME_EXTENDED_MAX  66
