/* qemu virt/aarch64 */
#include <frame.h>
        
.macro  frame_save el
        /* In the kernel, x18 always points to cpuinfo. */

        .if \el == 0
        str     x18, [sp, #-16] // stash user x18 and restore cpuinfo
        mrs     x18, tpidr_el1
        .endif

//        str	x17, [sp, #-8]
        mrs     x18, tpidr_el1  // XXX temp
        nop
        nop
        nop
        ldr     x17, [x18]      // running_frame
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
        stp     x30, x1, [x17, #(FRAME_X30 * 8)]

        mrs     x0, spsr_el1
        mrs     x1, esr_el1
        mrs     x2, elr_el1

        // yet frame return doesn't exceed rel range?
        add	x17, x17, #256
        stp     w0, w1, [x17, #((FRAME_SPSR_ESR - 32) * 8)]
        str     x2, [x17, #((FRAME_ELR - 32) * 8)]
        .endm

        .text
// entry from kernel loader
.globl _start
_start:
        // no trap on simd       
        mrs     x0, cpacr_el1
        orr     x0, x0, #0x300000
        msr     cpacr_el1, x0

        // set vector table base
//        ldr     x1, =exception_vectors
//        msr     vbar_el1, x1

        // temporary stack
        mov     x0, #0x41000000
	mov	sp, x0
	b	start

// exception entries
entry_sync_el1h:
        frame_save 1
        b synchronous_handler

entry_irq_el1h:
        frame_save 1
        b irq_handler

entry_serror_el1h:
        frame_save 1
        b serror_handler
        
entry_sync_el0: 
        frame_save 0
        b synchronous_handler

entry_irq_el0:
        frame_save 0
        b irq_handler

entry_serror_el0:
        frame_save 0
        b serror_handler

entry_invalid_el0:
        frame_save 0
        b invalid_handler

entry_invalid_el1:
        frame_save 1
        b invalid_handler

// universal frame return
.globl frame_return
frame_return:
        str     x0, [x18]       // set running_frame
        // XXX clear FRAME_FULL

        msr     daifset, #2     // disable irqs

        ldp     x2, x3, [x0, #(FRAME_SPSR_ESR * 8)]
        mov     w2, w2          // mask off esr
        msr     spsr_el1, x2
        msr     elr_el1, x3
        ldp     x2, x3, [x0, #(FRAME_X2 * 8)]
        ldp     x4, x5, [x0, #(FRAME_X4 * 8)]
        ldp     x6, x7, [x0, #(FRAME_X6 * 8)]
        ldp     x8, x9, [x0, #(FRAME_X8 * 8)]
        ldp     x10, x11, [x0, #(FRAME_X10 * 8)]
        ldp     x12, x13, [x0, #(FRAME_X12 * 8)]
        ldp     x14, x15, [x0, #(FRAME_X14 * 8)]
        ldp     x16, x17, [x0, #(FRAME_X16 * 8)]
        tbnz    x2, #4, 1f      // only restore x18 for user return
        ldr     x18, [x0, #(FRAME_X18 * 8)]
1:      ldr     x19, [x0, #(FRAME_X19 * 8)]
        ldp     x20, x21, [x0, #(FRAME_X20 * 8)]
        ldp     x22, x23, [x0, #(FRAME_X22 * 8)]
        ldp     x24, x25, [x0, #(FRAME_X24 * 8)]
        ldp     x26, x27, [x0, #(FRAME_X26 * 8)]
        ldp     x28, x29, [x0, #(FRAME_X28 * 8)]
        ldp     x30, x1, [x0, #(FRAME_X30 * 8)]
        mov     sp, x1
        ldp     x0, x1, [x0, #(FRAME_X0 * 8)]
        eret

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
        
