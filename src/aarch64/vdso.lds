OUTPUT_FORMAT("elf64-littleaarch64")

SECTIONS
{
    . = SIZEOF_HEADERS;
    .hash : { *(.hash) } : text
    .gnu.hash : { *(.gnu.hash) } : text
    .dynsym : { *(.dynsym) } : text
    .dynstr : { *(.dynstr) } : text
    .dynamic : { *(.dynamic) } : dynamic : text

    .gnu.version : { *(.gnu.version) } : text
    .gnu.version_d : { *(.gnu.version_d) } : text
    .gnu.version_r : { *(.gnu.version_r) } : text

    .plt : { *(.plt) } : text
    .got : { *(.got) } : text
    .got.plt : { *(.got.plt) } : text

    /* The presence of eh_frame_hdr in vdso - and presumably incomplete CFI
       directives - was leading libgcc to spin endlessly when unwinding after
       a sigcancel_handler. The nuances of this process are murky (see the
       link below), but by eliminating the eh_frame_hdr in vdso we can force
       libgcc to use a fallback path that detects the signal frame and
       restores registers from the sigcontext. According to the comments
       referenced below, debuggers typically also contain methods to unwind
       out of signal handlers.

       If the lack of CFI is ever an issue, this header may be restored - but
       only if the necessary CFI directives are enclosed to allow proper
       unwinding out of the signal trampoline.

       ref: https://github.com/torvalds/linux/commit/87676cfca14171fc4c99d96ae2f3e87780488ac4

       .eh_frame_hdr : { *(.eh_frame_hdr) } : eh_frame_hdr : text
     */

    .eh_frame : { *(.eh_frame) } : text
    .text : { *(.text*) } : text

    /* 2 vvar pages follow the text:
     *   i. 1 for variables in the vva
     *  ii. 1 for the pvclock page
     */
    vvar_page = ALIGN(4096);
    __vdso_vdso_dat = vvar_page + 128;
    pvclock_page = vvar_page + 4096;
}

/*
 * We specify the program headers to ensure that there is only a single
 * PT_LOAD segment
 * - put ELF header + program headers in text
 */
PHDRS
{
    text PT_LOAD FILEHDR PHDRS FLAGS(5); /*rd+exec*/
    dynamic PT_DYNAMIC FLAGS(4); /*rdonly*/
    /*note PT_NOTE FLAGS(4);*/
    /* eh_frame_hdr PT_GNU_EH_FRAME FLAGS(4); [see comment in SECTIONS above] */
}

/* Pretend like we are Linux 2.6 */
VERSION
{
    LINUX_2.6 {
        global:
            rt_sigreturn;
            __vdso_rt_sigreturn;
            gettimeofday;
            __vdso_gettimeofday;
            clock_gettime;
            __vdso_clock_gettime;
            getcpu;
            __vdso_getcpu;
            time;
            __vdso_time;
        local:
            *;
    };
}

VDSO_sigtramp = __vdso_rt_sigreturn;
