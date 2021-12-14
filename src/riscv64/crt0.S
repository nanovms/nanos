#define __ASSEMBLY__
#include <frame.h>
#include <kernel_machine.h>
#define U64_FROM_BIT(x) (1ull<<(x))

KERNEL_INDEX_OFF = (((KERNEL_BASE>>30)&0x1ff) * 8)

ROOT_PT_ADDR = KERNEL_PHYS - 0x1000
KERN_PT_ADDR = KERNEL_PHYS - 0x2000

.globl _start
_start:
        // XXX does bios clear bss for us?
        // clear bss
        la t0, bss_start
        la t1, bss_end
blp:    sd x0, (t0)
        addi t0, t0, 8
        blt t0, t1, blp

        // set up a temporary page table (Sv39)
        li s0, ROOT_PT_ADDR
        // identity map first 3 gigs
        li t0, (0<<28) | 0xef
        sd t0, 0(s0)
        li t0, (1<<28) | 0xef
        sd t0, 8(s0)
        li t0, (2<<28) | 0xef
        sd t0, 16(s0)

        // map the kernel va gig
        li t0, KERN_PT_ADDR
        srli t0, t0, 2
        ori t0, t0, 1
        li t1, KERNEL_INDEX_OFF
        add t1, t1, s0
        sd t0, 0(t1)
        li s0, KERN_PT_ADDR
        li t0, KERNEL_PHYS >> 2
        li t2, (KERNEL_PHYS+((2<<20)*512))>>2
        li t3, (2<<20)>>2
mlp:    ori t1, t0, 0xef
        sd t1, 0(s0)
        add t0, t0, t3
        addi s0, s0, 8
        blt t0, t2, mlp
        // load the root page into satp
        srli s0, s0, 12
        li t0, 0x8 << 60    // Sv39
        or s0, s0, t0
        csrw satp, s0
        sfence.vma
        li sp, KERN_PT_ADDR // stack just below the temp pagetable
        lui t0, %hi(start)
        addi t0, t0, %lo(start)
        jr t0

.balign 4
.globl trap_handler
trap_handler:
        csrrw tp, sscratch, tp  // swap scratch (cpuinfo) with tp
        sd sp, 8(tp)            // sp(x2) -> ci->scratch
        addi sp, tp, 16+TRAP_STACK_WORDS*8 // sp = cpuinfo->tstack+TRAP_STACK_WORDS*8
        sd t0, -8(sp)           // t0 -> stack
        ld t0, 0(tp)            // t0 <- ci->running_frame
        sd x1, FRAME_X1*8(t0)   
        ld x1, 8(tp)            // x1 <- ci->scratch (old sp)
        sd x1, FRAME_X2*8(t0)   // save old sp
        sd x3, FRAME_X3*8(t0)
        csrrw x1, sscratch, tp  // swap cpuinfo and old tp back in sscratch
        sd x1, FRAME_X4*8(t0)   // save old tp
        ld x1, -8(sp)           // x1 <- stack (old t0)
        sd x1, FRAME_X5*8(t0)   // save t0
        sd x6, FRAME_X6*8(t0)
        sd x7, FRAME_X7*8(t0)
        sd x8, FRAME_X8*8(t0)
        sd x9, FRAME_X9*8(t0)
        sd x10, FRAME_X10*8(t0)
        sd x11, FRAME_X11*8(t0)
        sd x12, FRAME_X12*8(t0)
        sd x13, FRAME_X13*8(t0)
        sd x14, FRAME_X14*8(t0)
        sd x15, FRAME_X15*8(t0)
        sd x16, FRAME_X16*8(t0)
        sd x17, FRAME_X17*8(t0)
        sd x18, FRAME_X18*8(t0)
        sd x19, FRAME_X19*8(t0)
        sd x20, FRAME_X20*8(t0)
        sd x21, FRAME_X21*8(t0)
        sd x22, FRAME_X22*8(t0)
        sd x23, FRAME_X23*8(t0)
        sd x24, FRAME_X24*8(t0)
        sd x25, FRAME_X25*8(t0)
        sd x26, FRAME_X26*8(t0)
        sd x27, FRAME_X27*8(t0)
        sd x28, FRAME_X28*8(t0)
        sd x29, FRAME_X29*8(t0)
        sd x30, FRAME_X30*8(t0)
        sd x31, FRAME_X31*8(t0)
        csrr s0, sstatus
        srli t1, s0, STATUS_BIT_SD
        beqz t1, 1f             // FS or XS is dirty and we only use FS for now
        fsd f0, FRAME_F0*8(t0)
        fsd f1, FRAME_F1*8(t0)
        fsd f2, FRAME_F2*8(t0)
        fsd f3, FRAME_F3*8(t0)
        fsd f4, FRAME_F4*8(t0)
        fsd f5, FRAME_F5*8(t0)
        fsd f6, FRAME_F6*8(t0)
        fsd f7, FRAME_F7*8(t0)
        fsd f8, FRAME_F8*8(t0)
        fsd f9, FRAME_F9*8(t0)
        fsd f10, FRAME_F10*8(t0)
        fsd f11, FRAME_F11*8(t0)
        fsd f12, FRAME_F12*8(t0)
        fsd f13, FRAME_F13*8(t0)
        fsd f14, FRAME_F14*8(t0)
        fsd f15, FRAME_F15*8(t0)
        fsd f16, FRAME_F16*8(t0)
        fsd f17, FRAME_F17*8(t0)
        fsd f18, FRAME_F18*8(t0)
        fsd f19, FRAME_F19*8(t0)
        fsd f20, FRAME_F20*8(t0)
        fsd f21, FRAME_F21*8(t0)
        fsd f22, FRAME_F22*8(t0)
        fsd f23, FRAME_F23*8(t0)
        fsd f24, FRAME_F24*8(t0)
        fsd f25, FRAME_F25*8(t0)
        fsd f26, FRAME_F26*8(t0)
        fsd f27, FRAME_F27*8(t0)
        fsd f28, FRAME_F28*8(t0)
        fsd f29, FRAME_F29*8(t0)
        fsd f30, FRAME_F30*8(t0)
        fsd f31, FRAME_F31*8(t0)
        frcsr t1
        sd t1, FRAME_FCSR*8(t0)
1:      csrr t1, sepc
        sd t1, FRAME_PC*8(t0)
        csrr t1, stval
        sd t1, FRAME_FAULT_ADDRESS*8(t0)
        li t2, STATUS_SPP|STATUS_SPIE
        and t1, s0, t2
        li t2, FS_CLEAN<<STATUS_BIT_FS // always mark FS_CLEAN
        or t1, t1, t2
        sd t1, FRAME_STATUS*8(t0)
        csrr t1, scause
        sd t1, FRAME_CAUSE*8(t0)
        srli t1, t1, 63
        bnez t1, trap_interrupt
        j trap_exception

.globl frame_return
frame_return:
        // set running frame
        csrr t0, sscratch
        sd a0, 0(t0)
        // clear frame full
        sd zero, FRAME_FULL*8(a0)
        ld t0, FRAME_PC*8(a0)
        csrw sepc, t0
        csrr t0, sstatus
        li t1, ~(STATUS_SPP|STATUS_SIE|(FS_MASK<<STATUS_BIT_FS))
        and t0, t0, t1
        ld t1, FRAME_STATUS*8(a0)
        or t0, t0, t1
        // if user, restore fp state. XXX how to do this lazily?
        andi t1, t1, STATUS_SPP
        bnez t1, 2f
        fld f0, FRAME_F0*8(a0)
        fld f1, FRAME_F1*8(a0)
        fld f2, FRAME_F2*8(a0)
        fld f3, FRAME_F3*8(a0)
        fld f4, FRAME_F4*8(a0)
        fld f5, FRAME_F5*8(a0)
        fld f6, FRAME_F6*8(a0)
        fld f7, FRAME_F7*8(a0)
        fld f8, FRAME_F8*8(a0)
        fld f9, FRAME_F9*8(a0)
        fld f10, FRAME_F10*8(a0)
        fld f11, FRAME_F11*8(a0)
        fld f12, FRAME_F12*8(a0)
        fld f13, FRAME_F13*8(a0)
        fld f14, FRAME_F14*8(a0)
        fld f15, FRAME_F15*8(a0)
        fld f16, FRAME_F16*8(a0)
        fld f17, FRAME_F17*8(a0)
        fld f18, FRAME_F18*8(a0)
        fld f19, FRAME_F19*8(a0)
        fld f20, FRAME_F20*8(a0)
        fld f21, FRAME_F21*8(a0)
        fld f22, FRAME_F22*8(a0)
        fld f23, FRAME_F23*8(a0)
        fld f24, FRAME_F24*8(a0)
        fld f25, FRAME_F25*8(a0)
        fld f26, FRAME_F26*8(a0)
        fld f27, FRAME_F27*8(a0)
        fld f28, FRAME_F28*8(a0)
        fld f29, FRAME_F29*8(a0)
        fld f30, FRAME_F30*8(a0)
        fld f31, FRAME_F31*8(a0)
        ld t1, FRAME_FCSR*8(a0)
        fscsr t1
2:      csrw sstatus, t0
        ld x1, FRAME_X1*8(a0)
        ld x2, FRAME_X2*8(a0)
        ld x3, FRAME_X3*8(a0)
        ld x4, FRAME_X4*8(a0)
        ld x5, FRAME_X5*8(a0)
        ld x6, FRAME_X6*8(a0)
        ld x7, FRAME_X7*8(a0)
        ld x8, FRAME_X8*8(a0)
        ld x9, FRAME_X9*8(a0)
        // x10 is a0
        ld x11, FRAME_X11*8(a0)
        ld x12, FRAME_X12*8(a0)
        ld x13, FRAME_X13*8(a0)
        ld x14, FRAME_X14*8(a0)
        ld x15, FRAME_X15*8(a0)
        ld x16, FRAME_X16*8(a0)
        ld x17, FRAME_X17*8(a0)
        ld x18, FRAME_X18*8(a0)
        ld x19, FRAME_X19*8(a0)
        ld x20, FRAME_X20*8(a0)
        ld x21, FRAME_X21*8(a0)
        ld x22, FRAME_X22*8(a0)
        ld x23, FRAME_X23*8(a0)
        ld x24, FRAME_X24*8(a0)
        ld x25, FRAME_X25*8(a0)
        ld x26, FRAME_X26*8(a0)
        ld x27, FRAME_X27*8(a0)
        ld x28, FRAME_X28*8(a0)
        ld x29, FRAME_X29*8(a0)
        ld x30, FRAME_X30*8(a0)
        ld x31, FRAME_X31*8(a0)
        ld a0, FRAME_X10*8(a0) 
        sret

