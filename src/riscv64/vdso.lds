OUTPUT_FORMAT("elf64-littleriscv")

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

    .eh_frame_hdr : { *(.eh_frame_hdr) } : eh_frame_hdr : text
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
    eh_frame_hdr PT_GNU_EH_FRAME FLAGS(4);
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

