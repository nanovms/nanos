#include <unix_internal.h>
#include <filesystem.h>
#include <elf64.h>

#define CORE_PATH "/coredumps/core"

//#define COREDUMP_DEBUG
#ifdef COREDUMP_DEBUG
#define core_debug(x, ...) do {tprintf(sym(coredump), 0, x, ##__VA_ARGS__);} while(0)
#else
#define core_debug(x, ...)
#endif

/* ET_CORE note types */
#define NT_PRSTATUS     1
#define NT_PRFPREG      2
#define NT_PRPSINFO     3
#define NT_TASKSTRUCT   4
#define NT_AUXV         6
#define NT_X86_XSTATE   0x202
#define NT_SIGINFO      0x53494749
#define NT_FILE         0x46494c45

#define ELF_PRARGSZ     (80)        /* Number of chars for args */

struct elf_prpsinfo {
    u8      pr_state;               /* numeric process state */
    u8      pr_sname;               /* char for pr_state */
    u8      pr_zomb;                /* zombie */
    u8      pr_nice;                /* nice val */
    u64     pr_flag;        /* flags */
    u32     pr_uid, pr_gid;
    u32     pr_pid, pr_ppid, pr_pgrp, pr_sid;
    char    pr_fname[16];           /* filename of executable */
    char    pr_psargs[ELF_PRARGSZ]; /* initial part of arg list */
};

struct elf_siginfo {
    int si_signo;                   /* signal number */
    int si_code;                    /* extra code */
    int si_errno;                   /* errno */
};

struct elf_prstatus {
    struct elf_siginfo pr_info;     /* Info associated with signal */
    short pr_cursig;                /* Current signal */
    unsigned long pr_sigpend;       /* Set of pending signals */
    unsigned long pr_sighold;       /* Set of held signals */
    int pr_pid;
    int pr_ppid;
    int pr_pgrp;
    int pr_sid;
    struct timeval pr_utime;        /* User time */
    struct timeval pr_stime;        /* System time */
    struct timeval pr_cutime;       /* Cumulative user time */
    struct timeval pr_cstime;       /* Cumulative system time */
    struct core_regs pr_reg;        /* Machine general purpose registers */
    int pr_fpvalid;                 /* True if math co-processor being used.  */
};

static u64 coredump_limit;

void coredump_set_limit(u64 s)
{
    core_debug("setting coredump limit to %ld\n", s);
    coredump_limit = s;
}

u64 coredump_get_limit(void)
{
    return coredump_limit;
}

static void add_to_sgl(sg_list sgl, void *b, u64 len)
{
    sg_buf sgb = sg_list_tail_add(sgl, len);
    assert(sgb != INVALID_ADDRESS);
    sgb->buf = b;
    sgb->offset = 0;
    sgb->refcount = 0;
    sgb->size = len;
}

/* touch every page to page it in */
static void pagein(range q)
{
    for (u64 p = q.start; p < q.end; p += PAGESIZE) {
        volatile u64 x = *(u64 *)pointer_from_u64(p);
        (void)x;
    }
}

static u64 vmflags_to_pflags(u64 vmflags)
{
    u64 f = 0;
    if (vmflags & VMAP_FLAG_EXEC)
        f |= PF_X;
    if (vmflags & VMAP_FLAG_WRITABLE)
        f |= PF_W;
    if (vmflags & VMAP_FLAG_READABLE)
        f |= PF_R;
    return f;
}

static void *add_note(buffer b, char *name, int type, u64 length)
{
    int nlen = runtime_strlen(name) + 1;
    int hlen = pad(sizeof(Elf_Note) + nlen, 4);
    u64 dlen = pad(length, 4);
    if (buffer_extend(b, hlen + dlen) == false)
        return 0;
    Elf_Note *n = buffer_ref(b, buffer_length(b));
    n->n_descsz=length;
    n->n_namesz = nlen;
    n->n_type = type;
    runtime_memcpy((void *)(n + 1), name, nlen);
    buffer_produce(b, hlen);
    void *r = buffer_ref(b, buffer_length(b));
    buffer_produce(b, dlen);
    return r;
}

static boolean add_thread_status(buffer b, thread t, struct siginfo *si)
{
    struct elf_prstatus *prs = add_note(b, "CORE", NT_PRSTATUS, sizeof(struct elf_prstatus));
    runtime_memset((void *)prs, 0, sizeof(*prs));
    prs->pr_info.si_signo = si->si_signo;
    prs->pr_info.si_code = si->si_code;
    prs->pr_info.si_errno = si->si_errno;
    prs->pr_sigpend = t->signals.pending;
    prs->pr_sighold = t->signal_mask;
    prs->pr_cursig = si->si_signo;
    prs->pr_pid = t->tid;
    prs->pr_ppid = t->p->pid;
    prs->pr_pgrp = t->p->pid;
    prs->pr_sid = t->p->pid;

    reg_copy_out(&prs->pr_reg, t);

    void *fp = add_note(b, "CORE", NT_PRFPREG, fpreg_size());
    fpreg_copy_out(fp, t);

#ifdef __x86_64__
#define XCR0_OFFSET 464     /* points into sw_reserved of fxregs_state */
    extern u8 use_xsave;
    if (use_xsave) {
        u8 *xs = add_note(b, "LINUX", NT_X86_XSTATE, extended_frame_size);
        runtime_memcpy(xs, pointer_from_u64(thread_frame(t)[FRAME_EXTENDED]),
            extended_frame_size);
        u32 v[2];
        xgetbv(0, &v[0], &v[1]);
        *(u64 *)(xs + XCR0_OFFSET) = (u64)v[0] | (((u64)v[1])<<32);
    }
#endif

    void *psi = add_note(b, "CORE", NT_SIGINFO, sizeof(struct siginfo));
    runtime_memcpy(psi, si, sizeof(*si));
    return true;
}

closure_function(3, 1, boolean, additional_threads_status,
                 buffer, b, thread, t, struct siginfo *, si,
                 rbnode, n)
{
    thread t = struct_from_field(n, thread, n);
    /* skip guilty thread as it's already been added */
    if (t == bound(t))
            return true;
    return add_thread_status(bound(b), t, bound(si));
}

closure_function(2, 1, void, dump_complete,
                 fsfile, f, status_handler, completion,
                 status, s)
{
    fsfile_release(bound(f));
    apply(bound(completion), s);
    closure_finish();
}

closure_function(8, 1, void, dump_write_complete,
                 fsfile, f, sg_io, write, sg_list, sg, Elf64_Phdr *, phdr, Elf64_Phdr *, phdr_end, buffer, b, status_handler, completion, u64, limit_remain,
                 status, s)
{
    u64 limit_remain = bound(limit_remain);
    sg_list sg = bound(sg);
    sg_list_release(sg);
    Elf64_Phdr *phdr = bound(phdr);
    core_debug("completed write of vmap at %p (limit remain %ld)\n", (phdr - 1)->p_vaddr, limit_remain);
    while (phdr < bound(phdr_end) && phdr->p_filesz == 0)
        phdr++;
    if (s != STATUS_OK || phdr >= bound(phdr_end) || limit_remain == 0) {
        if (s != STATUS_OK) {
            buffer b = get_string(s, sym(result));
            s = timm("result", "core dump write fail: %b", b);
        } else if (limit_remain == 0)
            s = timm("result", "core dump truncated; limit reached");
        deallocate_sg_list(bound(sg));
        deallocate_buffer(bound(b));
        core_debug("calling final completion\n");
        apply(bound(completion), s);
        fsfile_release(bound(f));
        closure_finish();
    } else {
        add_to_sgl(sg, pointer_from_u64(phdr->p_vaddr), phdr->p_memsz);
        u64 wlen = sg->count;
        if (limit_remain < wlen)
            wlen = limit_remain;
        bound(limit_remain) -= wlen;
        bound(phdr) = phdr + 1;
        apply(bound(write), sg, irangel(phdr->p_offset, wlen), (status_handler)closure_self());
    }
}

void coredump(thread t, struct siginfo *si, status_handler complete)
{
    core_debug("core dump for thread %p process %p\n", t, t->p);
    if (coredump_limit == 0) {
        core_debug("coredump_limit set to 0; no dump generated\n");
        apply(complete, timm("result", "no core generated: limit 0"));
        return;
    }
    u64 doff = 0;
    heap h = heap_general(get_kernel_heaps());
    process p = t->p;
    status s = STATUS_OK;

    fsfile f = fsfile_open_or_create(alloca_wrap_cstring(CORE_PATH), true);
    if (f == INVALID_ADDRESS) {
        core_debug("failed to open core file\n");
        s = timm("result", "no core generated: failed to open core file");
        goto error;
    }

    sg_io write = fsfile_get_writer(f);
    sg_list sg = allocate_sg_list();
    if (sg == INVALID_ADDRESS) {
        core_debug("failed to allocate sg\n");
        s = timm("result", "no core generated: failed to allocate sg");
        goto error;
    }
    vector v = allocate_vector(h, 32);
    if (v == INVALID_ADDRESS) {
        core_debug("failed to allocate vector\n");
        s = timm("result", "no core generated: failed to allocate vector");
        goto error;
    }
    rangemap_foreach(p->vmaps, n)
        vector_push(v, n);

    u64 hdr_size = sizeof(Elf64_Phdr) * (vector_length(v) + 1) + sizeof(Elf64_Ehdr);
    buffer bhdr = allocate_buffer(h, hdr_size);
    if (bhdr == INVALID_ADDRESS) {
        core_debug("failed to allocate header buffer\n");
        s = timm("result", "no core generated: failed to allocate header buffer");
        goto error;
    }
    buffer_produce(bhdr, hdr_size);
    doff = hdr_size;

    /* elf header */
    Elf64_Ehdr *ehdr = buffer_ref(bhdr, 0);
    runtime_memset((void *)ehdr, 0, sizeof(*ehdr));
    ehdr->e_ident[EI_MAG0] = ELFMAG0;
    ehdr->e_ident[EI_MAG1] = ELFMAG1;
    ehdr->e_ident[EI_MAG2] = ELFMAG2;
    ehdr->e_ident[EI_MAG3] = ELFMAG3;
    ehdr->e_ident[EI_CLASS] = ELFCLASS64;
    ehdr->e_ident[EI_DATA] = ELFDATA2LSB;
    ehdr->e_ident[EI_VERSION] = EV_CURRENT;
    ehdr->e_ident[EI_OSABI] = ELFOSABI_LINUX;
    ehdr->e_type = ET_CORE;
#ifdef __x86_64__
    ehdr->e_machine = EM_X86_64;
#endif
#ifdef __aarch64__
    ehdr->e_machine = EM_AARCH64;
#endif
#ifdef __riscv
    ehdr->e_machine = EM_RISCV;
#endif
    ehdr->e_version = EV_CURRENT;
    ehdr->e_ehsize = sizeof(Elf64_Ehdr);
    ehdr->e_phoff = sizeof(Elf64_Ehdr);
    ehdr->e_phentsize = sizeof(Elf64_Phdr);
    ehdr->e_phnum = 1 + vector_length(v);

    /* notes phdr */
    Elf64_Phdr *phdr = buffer_ref(bhdr, sizeof(Elf64_Ehdr));
    runtime_memset((void *)phdr, 0, sizeof (*phdr));
    phdr->p_type = PT_NOTE;
    phdr->p_offset = doff;

    struct elf_prpsinfo *psinfo = add_note(bhdr, "CORE", NT_PRPSINFO, sizeof(struct elf_prpsinfo));
    assert(psinfo);
    runtime_memset((void *)psinfo, 0, sizeof(*psinfo));
    psinfo->pr_state = 0;
    psinfo->pr_sname = 'R';
    psinfo->pr_nice = 0;
    psinfo->pr_gid = 0;
    psinfo->pr_uid = 0;
    psinfo->pr_pid = t->p->pid;
    psinfo->pr_ppid = t->p->pid;
    psinfo->pr_pgrp = t->p->pid;
    psinfo->pr_sid = t->p->pid; // XXX?

    u64 l = p->saved_args_end - p->saved_args_begin;
    if (l >= ELF_PRARGSZ)
        l = ELF_PRARGSZ - 1;
    runtime_memcpy(psinfo->pr_psargs, p->saved_args_begin, l);
    for (int i = 0; i < l; i++) {
        if (psinfo->pr_psargs[i] == 0)
            psinfo->pr_psargs[i] = ' ';
    }
    buffer pname = get(p->process_root, sym(program));
    if (buffer_length(pname) > 0) {
        int i = buffer_strrchr(pname, '/');
        if (i < 0)
            i = 0;
        l = MIN(buffer_length(pname) - i, sizeof(psinfo->pr_fname) - 1);
        runtime_memcpy(psinfo->pr_fname, buffer_ref(pname, i), l);
        psinfo->pr_fname[l] = 0;
    }

    struct aux *auxv = add_note(bhdr, "CORE", NT_AUXV, sizeof(t->p->saved_aux));
    runtime_memcpy(auxv, t->p->saved_aux, sizeof(t->p->saved_aux));

    /* TODO add NT_FILE note for filebacked mappings */

    /* Add signaled thread first so it is default thread in gdb */
    add_thread_status(bhdr, t, si);
    rbtree_traverse(t->p->threads, RB_INORDER, stack_closure(additional_threads_status, bhdr, t, si));

    /* Refetch phdr in case of realloc */
    phdr = buffer_ref(bhdr, sizeof(Elf64_Ehdr));
    phdr->p_filesz = phdr->p_memsz = buffer_length(bhdr) - doff;

    /* Align vmap dumps to pagesize */
    doff = pad(doff + phdr->p_filesz, PAGESIZE);

    /* Fill out phdrs for vmaps */
    vmap m;
    Elf64_Phdr *phdr_begin = ++phdr;
    vector_foreach(v, m) {
        core_debug("vmap %R flags %x allowed %x\n", m->node.r, m->flags, m->allowed_flags);
        phdr->p_type = PT_LOAD;
        phdr->p_vaddr = m->node.r.start;
        phdr->p_paddr = 0;
        phdr->p_memsz = range_span(m->node.r);
        phdr->p_flags = vmflags_to_pflags(m->flags);
        phdr->p_offset = doff;
        phdr->p_align = PAGESIZE;
        /* set filesz to 0 to skip copying segment into dump */
        if (m->flags & VMAP_MMAP_TYPE_FILEBACKED || m->flags == 0) {
            phdr->p_filesz = 0;
        } else {
            phdr->p_filesz = phdr->p_memsz;
            pagein(irangel(phdr->p_vaddr, phdr->p_memsz));
        }
        doff += phdr->p_filesz;
        ++phdr;
    }
    Elf64_Phdr *phdr_end = phdr;
    deallocate_vector(v);

    /* write dump header and first phdr */
    status_handler completion = closure(h, dump_complete, f, complete);
    add_to_sgl(sg, buffer_ref(bhdr, 0), buffer_length(bhdr));
    u64 limit_remain = coredump_limit;
    u64 wlen = sg->count;
    if (limit_remain < wlen)
        wlen = limit_remain;
    limit_remain -= wlen;
    apply(write, sg, irangel(0, wlen),
        closure(h, dump_write_complete, f, write, sg, phdr_begin, phdr_end, bhdr, completion, limit_remain));
    return;
error:
    apply(complete, s);
}
