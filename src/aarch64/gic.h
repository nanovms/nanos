#define ICC_PMR_EL1     "S3_0_C4_C6_0"
#define ICC_IAR0_EL1    "S3_0_C12_C8_0"
#define ICC_EOIR0_EL1   "S3_0_C12_C8_1"
#define ICC_HPPIR0_EL1  "S3_0_C12_C8_2"
#define ICC_BPR0_EL1    "S3_0_C12_C8_3"
//#define ICC_AP0R<n>_EL1 32 4-7 RW, <n> = Op2 -4
//#define ICC_AP1R<n>_EL1 32 9 0-3 RW, <n> = Op2
#define ICC_DIR_EL1     "S3_0_C12_C11_1"
#define ICC_RPR_EL1     "S3_0_C12_C11_3"
#define ICC_SGI1R_EL1   "S3_0_C12_C11_5"
#define ICC_ASGI1R_EL1  "S3_0_C12_C11_6"
#define ICC_SGI0R_EL1   "S3_0_C12_C11_7"
#define ICC_IAR1_EL1    "S3_0_C12_C12_0"
#define ICC_EOIR1_EL1   "S3_0_C12_C12_1"
#define ICC_HPPIR1_EL1  "S3_0_C12_C12_2"
#define ICC_BPR1_EL1    "S3_0_C12_C12_3"
#define ICC_CTLR_EL1    "S3_0_C12_C12_4"
#define ICC_SRE_EL1     "S3_0_C12_C12_5"
#define ICC_IGRPEN0_EL1 "S3_0_C12_C12_6"
#define ICC_IGRPEN1_EL1 "S3_0_C12_C12_7"
#define ICC_SRE_EL2     "S3_4_C12_C9_5"
#define ICC_CTLR_EL3    "S3_6_C12_C12_4"
#define ICC_SRE_EL3     "S3_6_C12_C12_5"
#define ICC_IGRPEN1_EL3 "S3_6_C12_C12_7"

void gic_eoi(int irq);
void init_gic(void);
