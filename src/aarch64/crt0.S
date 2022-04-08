#define __ASSEMBLY__
#include <frame.h>
#include <kernel_machine.h>
        
.macro  frame_save el ex
        /* In the kernel, x18 always points to cpuinfo. */

        .if \el == 0
        str     x18, [sp, #-16] // stash user x18 and restore cpuinfo
        mrs     x18, tpidr_el1
        .endif

        str     x17, [sp, #-8]
        ldr     x17, [x18]      // current_context / frame
        stp     x0, x1, [x17, #(FRAME_X0 * 8)]
        stp     x2, x3, [x17, #(FRAME_X2 * 8)]
        stp     x4, x5, [x17, #(FRAME_X4 * 8)]
        stp     x6, x7, [x17, #(FRAME_X6 * 8)]
        stp     x8, x9, [x17, #(FRAME_X8 * 8)]
        stp     x10, x11, [x17, #(FRAME_X10 * 8)]
        stp     x12, x13, [x17, #(FRAME_X12 * 8)]
        stp     x14, x15, [x17, #(FRAME_X14 * 8)]
        ldr     x0, [sp, #-8]
        stp     x16, x0, [x17, #(FRAME_X16 * 8)]
        .if \el == 0
        ldr     x1, [sp, #-16]
        stp     x1, x19, [x17, #(FRAME_X18 * 8)]
        .else
        stp     x18, x19, [x17, #(FRAME_X18 * 8)]
        .endif
        stp     x20, x21, [x17, #(FRAME_X20 * 8)]
        stp     x22, x23, [x17, #(FRAME_X22 * 8)]
        stp     x24, x25, [x17, #(FRAME_X24 * 8)]
        stp     x26, x27, [x17, #(FRAME_X26 * 8)]
        stp     x28, x29, [x17, #(FRAME_X28 * 8)]
        .if \el == 0
        mrs     x1, sp_el0
        .else
        mov     x1, sp
        .endif
        mov     x0, #\el
        stp     x30, x1, [x17, #(FRAME_X30 * 8)]
        str     x0, [x17, #(FRAME_EL * 8)]

        .if \ex == 1
        mrs     x0, spsr_el1
        mrs     x1, esr_el1
        mrs     x2, elr_el1
        mrs     x3, far_el1
        .else
        mrs     x0, nzcv    /* processor state */
        /* dummy ELR to not return from exception when restoring the frame */
        mov     x2, #0x0
        .endif

        add     x17, x17, #256
        .if \ex == 1
        stp     w0, w1, [x17, #((FRAME_ESR_SPSR - 32) * 8)]
        str     x3, [x17, #((FRAME_FAULT_ADDRESS - 32) * 8)]
        .else
        str     w0, [x17, #((FRAME_ESR_SPSR - 32) * 8)]
        .endif
        str     x2, [x17, #((FRAME_ELR - 32) * 8)]
        .endm

        .text

.globl aarch64_cpu_init
aarch64_cpu_init:
        // allow debug and serror interrupts, disable irq and firq
        mov     x0, #0xc0
        msr     daif, x0

        // no trap on simd       
        mrs     x0, cpacr_el1
        orr     x0, x0, (CPACR_EL1_FPEN_NO_TRAP << CPACR_EL1_FPEN_SHIFT)
        msr     cpacr_el1, x0

        // temporary stack
        mov     x0, (PHYSMEM_BASE + INIT_IDENTITY_SIZE)
        mov     sp, x0

        ret

// entry from kernel loader
.globl _start
_start:
        bl      aarch64_cpu_init
        b       start

// exception entries
entry_sync_el1h:
        frame_save 1 1
        b       synchronous_handler

entry_irq_el1h:
        frame_save 1 1
        b       irq_handler

entry_serror_el1h:
        frame_save 1 1
        b       serror_handler
        
entry_sync_el0: 
        frame_save 0 1
        b       synchronous_handler

entry_irq_el0:
        frame_save 0 1
        b       irq_handler

entry_serror_el0:
        frame_save 0 1
        b       serror_handler

entry_invalid_el0:
        frame_save 0 1
        b       invalid_handler

entry_invalid_el1:
        frame_save 1 1
        b       invalid_handler

// universal frame return
.globl frame_return
frame_return:
        mov     x1, #0x0        // clear frame full condition
        str     x1, [x0, #(FRAME_FULL * 8)]

        ldp     x30, x1, [x0, #(FRAME_X30 * 8)]
        ldp     x4, x5, [x0, #(FRAME_X4 * 8)]
        ldp     x6, x7, [x0, #(FRAME_X6 * 8)]
        ldp     x8, x9, [x0, #(FRAME_X8 * 8)]
        ldp     x10, x11, [x0, #(FRAME_X10 * 8)]
        ldp     x12, x13, [x0, #(FRAME_X12 * 8)]
        ldp     x14, x15, [x0, #(FRAME_X14 * 8)]
        ldp     x16, x17, [x0, #(FRAME_X16 * 8)]
        ldr     x19, [x0, #(FRAME_X19 * 8)]
        ldp     x20, x21, [x0, #(FRAME_X20 * 8)]
        ldp     x22, x23, [x0, #(FRAME_X22 * 8)]
        ldp     x24, x25, [x0, #(FRAME_X24 * 8)]
        ldp     x26, x27, [x0, #(FRAME_X26 * 8)]
        ldp     x28, x29, [x0, #(FRAME_X28 * 8)]
        ldp     x2, x3, [x0, #(FRAME_ESR_SPSR * 8)]
        cmp     x3, #0x0
        b.eq    3f

        /* return from exception */
        mov     w2, w2          // mask off esr
        msr     spsr_el1, x2
        msr     elr_el1, x3
        tbnz    x2, #2, 1f
        /* user return: restore x18 and place stack */
        ldr     x18, [x0, #(FRAME_X18 * 8)]
        msr     sp_el0, x1
        b       2f
        /* kernel return */
1:      mov     sp, x1
2:      ldp     x2, x3, [x0, #(FRAME_X2 * 8)]
        ldp     x0, x1, [x0, #(FRAME_X0 * 8)]
        eret

        /* resume context */
3:      msr     nzcv, x2
        mov     sp, x1
        ldp     x2, x3, [x0, #(FRAME_X2 * 8)]
        ldp     x0, x1, [x0, #(FRAME_X0 * 8)]
        ret

.globl context_suspend
context_suspend:
        frame_save 1 0
        ldr     x0, [x18]
        b context_suspend_finish

        .globl arm_hvc
arm_hvc:
        // incomplete, just enough to issue power off
        hvc     #0
        ret

.macro  vector  path
        .align 7
        b entry_\path
        .endm

// vector table
        .align 11
        .globl exception_vectors
exception_vectors:
        // EL1t
        vector  invalid_el1
        vector  invalid_el1
        vector  invalid_el1
        vector  invalid_el1

        // EL1h
        vector  sync_el1h
        vector  irq_el1h
        vector  invalid_el1
        vector  serror_el1h

        // EL0 - 64-bit
        vector  sync_el0
        vector  irq_el0
        vector  invalid_el0
        vector  serror_el0

        // EL0
        vector  invalid_el0
        vector  invalid_el0
        vector  invalid_el0
        vector  invalid_el0
        
/* fp / simd */

.globl frame_save_fpsimd
frame_save_fpsimd:
        ldr     x0, [x0, #(FRAME_EXTENDED * 8)]
        stp     q0, q1, [x0, #(0 * 16)]
        stp     q2, q3, [x0, #(2 * 16)]
        stp     q4, q5, [x0, #(4 * 16)]
        stp     q6, q7, [x0, #(6 * 16)]
        stp     q8, q9, [x0, #(8 * 16)]
        stp     q10, q11, [x0, #(10 * 16)]
        stp     q12, q13, [x0, #(12 * 16)]
        stp     q14, q15, [x0, #(14 * 16)]
        stp     q16, q17, [x0, #(16 * 16)]
        stp     q18, q19, [x0, #(18 * 16)]
        stp     q20, q21, [x0, #(20 * 16)]
        stp     q22, q23, [x0, #(22 * 16)]
        stp     q24, q25, [x0, #(24 * 16)]
        stp     q26, q27, [x0, #(26 * 16)]
        stp     q28, q29, [x0, #(28 * 16)]
        stp     q30, q31, [x0, #(30 * 16)]
        mrs     x1, fpsr
        mrs     x2, fpcr
        add     x0, x0, #(32 * 16)
        stp     x1, x2, [x0]
1:      ret

.globl frame_restore_fpsimd
frame_restore_fpsimd:
        ldr     x0, [x0, #(FRAME_EXTENDED * 8)]
        ldp     q0, q1, [x0, #(0 * 16)]
        ldp     q2, q3, [x0, #(2 * 16)]
        ldp     q4, q5, [x0, #(4 * 16)]
        ldp     q6, q7, [x0, #(6 * 16)]
        ldp     q8, q9, [x0, #(8 * 16)]
        ldp     q10, q11, [x0, #(10 * 16)]
        ldp     q12, q13, [x0, #(12 * 16)]
        ldp     q14, q15, [x0, #(14 * 16)]
        ldp     q16, q17, [x0, #(16 * 16)]
        ldp     q18, q19, [x0, #(18 * 16)]
        ldp     q20, q21, [x0, #(20 * 16)]
        ldp     q22, q23, [x0, #(22 * 16)]
        ldp     q24, q25, [x0, #(24 * 16)]
        ldp     q26, q27, [x0, #(26 * 16)]
        ldp     q28, q29, [x0, #(28 * 16)]
        ldp     q30, q31, [x0, #(30 * 16)]
        add     x0, x0, #(32 * 16)
        ldr     x1, [x0]
        msr     fpsr, x1

        /* first check if fpcr changed to avoid context synchronization */
        mrs     x2, fpcr
        ldr     x1, [x0, #8]
        cmp     x1, x2
        b.eq    1f
        msr     fpcr, x1
1:
        ret

        .globl angel_shutdown
        .globl angel_shutdown_trap
angel_shutdown:
        str     x0, [sp, #8]
        mov     x1, #0x26         /* 0x20026 ADP_Stopped_ApplicationExit */
        movk    x1, #0x2, lsl #16
        str     x1, [sp, #0]
        mov     x1, sp
        mov     w0, #0x18
angel_shutdown_trap:
        hlt     0xf000
