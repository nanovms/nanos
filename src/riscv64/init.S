#define __ASSEMBLY__
#include <kernel_machine.h>

ROOT_PT_ADDR = KERNEL_PHYS - 0x1000

.macro  start_setup
        // disable interrupts and FPU
        csrw CSR_IE, zero
        csrw CSR_IP, zero
        li t0, SR_FS
        csrc CSR_STATUS, t0
.endm

.globl _start
_start:
        start_setup

        // stack just below the temp pagetable
        li sp, ROOT_PT_ADDR

        mv s0, a0  // boot hartid
        mv s1, a1  // dtb
        li a0, 0
        li a1, 0
        la a2, _DYNAMIC
        la a3, _DYNSYM
        call elf_dyn_relocate
        mv a0, s0
        mv a1, s1

        // XXX does bios clear bss for us?
        // clear bss
        la t0, bss_start
        la t1, bss_end
blp:    sd x0, (t0)
        addi t0, t0, 8
        blt t0, t1, blp

        // set up a temporary page table (Sv39)
        li s0, ROOT_PT_ADDR
        // identity map 512G
        mv t1, s0
        li t2, 0
        li t3, 512
ilp:    slli t0, t2, 28
        ori t0, t0, 0xef
        sd t0, (t1)
        addi t2, t2, 1
        addi t1, t1, 8
        blt t2, t3, ilp

        // load the root page into satp
        srli s0, s0, 12
        li t0, 0x8 << 60    // Sv39
        or s0, s0, t0
        csrw satp, s0
        sfence.vma

        // save boot hartid
        la t0, boot_hartid
        sd a0, 0(t0)

        la t0, start
        jr t0

install_tablebase:
        la t0, tablebase
        ld t0, 0(t0)
        srli t0, t0, 12
        li s0, 0x9 << 60    // Sv48
        or t0, t0, s0
        csrw satp, t0
        sfence.vma

        // relocate pc on return
        la t0, kas_kern_offset
        ld t0, 0(t0)
        add ra, ra, t0
        ret

.globl secondary_core_start_from_sbi
secondary_core_start_from_sbi:
        start_setup
        li t0, 0x1 << 18    // SUM
        csrs sstatus, t0
        call install_tablebase
        la t0, ap_start
        mv sp, a1
        jr t0   // hartid in a0
