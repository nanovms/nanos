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


/* Values for p_flags. */
#define PF_X0x1 /* Executable. */
#define PF_W0x2 /* Writable. */
#define PF_R0x4 /* Readable. */
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

#define SHT_SYMTAB 2/* symbol table section */
#define SHT_STRTAB 3/* string table section */

#endif /* !_SYS_ELF64_H_ */
