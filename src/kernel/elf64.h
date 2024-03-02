/*-
 * Copyright (c) 1996-1998 John D. Polstra.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $FreeBSD: head/sys/sys/elf64.h 186667 2009-01-01 02:08:56Z obrien $
 */

#ifndef _SYS_ELF64_H_
#define _SYS_ELF64_H_ 1

/*
 * ELF definitions common to all 64-bit architectures.
 */

typedef u64	Elf64_Addr;
typedef u16	Elf64_Half;
typedef u64	Elf64_Off;
typedef s64     Elf64_Sxword;
typedef u32	Elf64_Word;
typedef u64	Elf64_Lword;
typedef u64	Elf64_Xword;

#define EI_NIDENT 16/* Size of e_ident array. */

typedef struct {
    u32 n_namesz;/* Length of name. */
    u32 n_descsz;/* Length of descriptor. */
    u32 n_type;/* Type of this note. */
} Elf_Note;

/*
 * Types of dynamic symbol hash table bucket and chain elements.
 *
 * This is inconsistent among 64 bit architectures, so a machine dependent
 * typedef is required.
 */

typedef Elf64_Word	Elf64_Hashelt;

/* Non-standard class-dependent datatype used for abstraction. */
typedef Elf64_Xword	Elf64_Size;
typedef Elf64_Sxword	Elf64_Ssize;

/*
 * ELF header.
 */
#define EI_MAG0     0           /* e_ident[] indexes */
#define EI_MAG1     1
#define EI_MAG2     2
#define EI_MAG3     3
#define EI_CLASS    4
#define EI_DATA     5
#define EI_VERSION  6
#define EI_OSABI    7
#define EI_PAD      8

#define ELFMAG0     0x7f        /* EI_MAG */
#define ELFMAG1     'E'
#define ELFMAG2     'L'
#define ELFMAG3     'F'

#define ELFCLASS64      2       /* EI_CLASS */

#define ELFDATA2LSB     1       /* EI_DATA */

#define EV_CURRENT      1       /* e_version, EI_VERSION */

#define ELFOSABI_NONE   0       /* EI_OSABI */
#define ELFOSABI_LINUX  3

#define ET_NONE     0           /* e_type */
#define ET_REL      1
#define ET_EXEC     2
#define ET_DYN      3
#define ET_CORE     4

#define EM_X86_64   62      /* e_machine */
#define EM_AARCH64  183
#define EM_RISCV    243

typedef struct {
	unsigned char	e_ident[EI_NIDENT];	/* File identification. */
	Elf64_Half	e_type;		/* File type. */
	Elf64_Half	e_machine;	/* Machine architecture. */
	Elf64_Word	e_version;	/* ELF format version. */
	Elf64_Addr	e_entry;	/* Entry point. */
	Elf64_Off	e_phoff;	/* Program header file offset. */
	Elf64_Off	e_shoff;	/* Section header file offset. */
	Elf64_Word	e_flags;	/* Architecture-specific flags. */
	Elf64_Half	e_ehsize;	/* Size of ELF header in bytes. */
	Elf64_Half	e_phentsize;	/* Size of program header entry. */
	Elf64_Half	e_phnum;	/* Number of program header entries. */
	Elf64_Half	e_shentsize;	/* Size of section header entry. */
	Elf64_Half	e_shnum;	/* Number of section header entries. */
	Elf64_Half	e_shstrndx;	/* Section name strings section. */
} Elf64_Ehdr;

/*
 * Program header.
 */

#define PT_LOAD 1
#define PT_INTERP 3
#define PT_NOTE 4


/* Values for p_flags. */
#define PF_X 0x1 /* Executable. */
#define PF_W 0x2 /* Writable. */
#define PF_R 0x4 /* Readable. */
#define PF_MASKOS 0x0ff00000 /* Operating system-specific. */
#define PF_MASKPROC 0xf0000000 /* Processor-specific. */

typedef struct {
	Elf64_Word	p_type;		/* Entry type. */
	Elf64_Word	p_flags;	/* Access permission flags. */
	Elf64_Off	p_offset;	/* File offset of contents. */
	Elf64_Addr	p_vaddr;	/* Virtual address in memory image. */
	Elf64_Addr	p_paddr;	/* Physical address (not used). */
	Elf64_Xword	p_filesz;	/* Size of contents in file. */
	Elf64_Xword	p_memsz;	/* Size of contents in memory. */
	Elf64_Xword	p_align;	/* Alignment in memory and file. */
} Elf64_Phdr;

typedef struct {
    Elf64_Word sh_name; /* Section name */
    Elf64_Word sh_type; /* Section type */
    Elf64_Xword sh_flags; /* Section attributes */
    Elf64_Addr sh_addr; /* Virtual address in memory */
    Elf64_Off sh_offset; /* Offset in file */
    Elf64_Xword sh_size; /* Size of section */
    Elf64_Word sh_link; /* Link to other section */
    Elf64_Word sh_info; /* Miscellaneous information */
    Elf64_Xword sh_addralign; /* Address alignment boundary */
    Elf64_Xword sh_entsize; /* Size of entries, if section has table */
} Elf64_Shdr;

/* Symbol type - ELFNN_ST_TYPE - st_info
   from elf_common.h */
#define STT_NOTYPE 0		/* Unspecified type. */
#define STT_OBJECT 1		/* Data object. */
#define STT_FUNC 2		/* Function. */
#define STT_SECTION 3		/* Section. */
#define STT_FILE 4		/* Source file. */
#define STT_COMMON 5		/* Uninitialized common block. */
#define STT_TLS 6		/* TLS object. */
#define STT_NUM 7
#define STT_LOOS 10	        /* Reserved range for operating system */
#define STT_GNU_IFUNC 10
#define STT_HIOS 12	        /*   specific semantics. */
#define STT_LOPROC 13	        /* Start of processor reserved range. */
#define STT_SPARC_REGISTER 13	/* SPARC register information. */
#define STT_HIPROC 15		/* End of processor reserved range. */

typedef struct {
    Elf64_Word st_name; /* Symbol name */
    unsigned char st_info; /* Type and Binding attributes */
    unsigned char st_other; /* Reserved */
    Elf64_Half st_shndx; /* Section table index */
    Elf64_Addr st_value; /* Symbol value */
    Elf64_Xword st_size; /* Size of object (e.g., common) */
} Elf64_Sym;

/* Macros for accessing the fields of st_info. */
#define ELF64_ST_BIND(info) ((info) >> 4)
#define ELF64_ST_TYPE(info) ((info) & 0xf)

/* Macro for constructing st_info from field values. */
#define ELF64_ST_INFO(bind, type) (((bind) << 4) + ((type) & 0xf))

/* Macro for accessing the fields of st_other. */
#define ELF64_ST_VISIBILITY(oth) ((oth) & 0x3)

typedef struct {
    Elf64_Addr r_offset;
    Elf64_Xword r_info;
} Elf64_Rel;

typedef struct {
    Elf64_Addr r_offset;
    Elf64_Xword r_info;
    Elf64_Sxword r_addend;
} Elf64_Rela;

/* Macros for accessing r_info. */
#define ELF64_R_SYM(i)  ((i) >> 32)
#define ELF64_R_TYPE(i) ((i) & 0xffffffff)

typedef struct {
    Elf64_Sxword d_tag;
    union {
        Elf64_Xword d_val;
        Elf64_Addr d_ptr;
    } d_un;
} Elf64_Dyn;

/* d_tag (dynamic entry type) values */
#define DT_NULL     0
#define DT_NEEDED   1
#define DT_PLTRELSZ 2
#define DT_PLTGOT   3
#define DT_HASH     4
#define DT_STRTAB   5
#define DT_SYMTAB   6
#define DT_RELA     7
#define DT_RELASZ   8
#define DT_RELAENT  9
#define DT_JMPREL   23
#define DT_RELACOUNT    0x6ffffff9

#define SHT_PROGBITS 1
#define SHT_SYMTAB 2/* symbol table section */
#define SHT_STRTAB 3/* string table section */
#define SHT_RELA   4
#define SHT_DYNAMIC 6
#define SHT_NOBITS  8
#define SHT_DYNSYM  11

/* A minimum amount of file data to read to get the program headers

   glibc uses a rule-of-thumb of 832 bytes for 64-bit executables: 64 bytes
   for the ELF header, 56 bytes per program header (figure max of 10), plus a
   208 byte margin for "program notes." However, we observe that reading a 4K
   page will usually get us the program interpreter path as well as section
   headers (should we need them for finding symbol and string tables).
*/
#define ELF_PROGRAM_LOAD_MIN_SIZE PAGESIZE

#define foreach_phdr(__e, __p)\
    for (int __i = 0; __i< __e->e_phnum; __i++)\
        for (Elf64_Phdr *__p = (void *)__e + __e->e_phoff + (__i * __e->e_phentsize); __p ; __p = 0) \

#define foreach_shdr(__e, __s) \
    for (int __i = 0; __i< __e->e_shnum; __i++) \
        for (Elf64_Shdr *__s = (void *)__e + __e->e_shoff + (__i * __e->e_shentsize); __s ; __s = 0) \

/* returns virtual address to access map (e.g. vaddr or identity in stage2) */
closure_type(elf_map_handler, boolean, u64 vaddr, u64 offset, u64 data_size, u64 bss_size,
             pageflags flags);
closure_type(elf_loader, void, u64 offset, u64 length, void *dest, status_handler sh);
closure_type(elf_sym_handler, void, sstring name, u64 a, u64 len, u8 info);
closure_type(elf_sym_resolver, void *, sstring name);
sstring elf_string(buffer elf, Elf64_Shdr *string_section, u64 offset);
void elf_symbols(buffer elf, elf_sym_handler each);
boolean elf_dyn_parse(buffer elf, Elf64_Shdr **symtab, Elf64_Shdr **strtab, Elf64_Rela **reltab,
                      int *relcount);
boolean elf_dyn_link(buffer elf, void *load_addr, elf_sym_resolver resolver);
void elf_dyn_relocate(u64 base, u64 offset, Elf64_Dyn *dyn, Elf64_Sym *syms);
boolean elf_plt_get(buffer elf, u64 *addr, u64 *offset, u64 *size);
void walk_elf(buffer elf, range_handler rh);
void *load_elf(buffer elf, u64 load_offset, elf_map_handler mapper);
void load_elf_to_physical(heap h, elf_loader loader, u64 *entry, status_handler sh);

/* Architecture-specific */
closure_type(elf_sym_relocator, boolean, Elf64_Rela *rel);
void elf_apply_relocate_add(buffer elf, Elf64_Shdr *s, u64 offset);
boolean elf_apply_relocate_syms(buffer elf, Elf64_Rela *reltab, int relcount,
                                elf_sym_relocator relocator);
void arch_elf_relocate(Elf64_Rela *rel, u64 relsz, Elf64_Sym *syms, u64 base, u64 offset);

static inline void elf_apply_relocs(buffer elf, u64 offset)
{
    Elf64_Ehdr *e = (Elf64_Ehdr *)buffer_ref(elf, 0);

    foreach_shdr(e, s) {
        if (s->sh_type == SHT_RELA)
            elf_apply_relocate_add(elf, s, offset);
    }
}

#endif /* !_SYS_ELF64_H_ */
