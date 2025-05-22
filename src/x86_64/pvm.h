/* Pagetable-based Virtual Machine hypervisor */

#ifndef PVM_H_
#define PVM_H_

struct pvm_vcpu {
    u64 event_flags;
    u32 event_errcode;
    u32 event_vector;
    u64 cr2;
    u64 reserved0[5];
    u16 user_cs, user_ss;
    u32 reserved1;
    u64 reserved2;
    u64 user_gsbase;
    u32 eflags;
    u32 pkru;
    u64 rip;
    u64 rsp;
    u64 rcx;
    u64 r11;
};

boolean pvm_detect(void);
range pvm_get_addr_range(void);
void pvm_setup(kernel_heaps kh);

void pvm_cpuid(u32 leaf, u32 subleaf, u32 *v);
void pvm_syscall_entry(void);
void pvm_frame_return(context_frame f) __attribute__((noreturn));
void pvm_event_return(context_frame f) __attribute__((noreturn));

extern boolean pvm_detected;

#endif
