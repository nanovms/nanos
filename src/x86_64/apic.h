/* ICR flags */
#define ICR_TYPE_FIXED        0x00000000
#define ICR_TYPE_SMI          0x00000200
#define ICR_TYPE_NMI          0x00000400
#define ICR_TYPE_INIT         0x00000500
#define ICR_TYPE_STARTUP      0x00000600
#define ICR_PHYSICAL          0x00000000
#define ICR_LOGICAL           0x00000800
#define ICR_DELIVS            0x00001000
#define ICR_DEASSERT          0x00000000
#define ICR_ASSERT            0x00004000
#define ICR_TRIGGER_EDGE      0x00000000
#define ICR_TRIGGER_LEVEL     0x00008000
#define ICR_DEST_SELF         0x00040000
#define ICR_DEST_ALL          0x00080000
#define ICR_DEST_ALL_EXC_SELF 0x000C0000

#define TARGET_EXCLUSIVE_BROADCAST 0xfffffffful
#define IA32_APIC_BASE_MSR 0x1b

void lapic_eoi(void);
void init_apic(kernel_heaps kh);
void lapic_set_tsc_deadline_mode(u32 v);
clock_timer init_lapic_timer(void);
void apic_ipi(u32 target, u64 icr);
u32 apic_id();
void enable_apic();
