#include <kernel.h>
#include <elf64.h>
#include <ltrace.h>

#define PLT_ENTRY_SIZE_DEFAULT  16

#ifdef LTRACE_DEBUG
#define ltrace_debug(x, ...) do {rprintf("ltrace: " x "\n", ##__VA_ARGS__);} while(0)
#else
#define ltrace_debug(x, ...)
#endif

#if defined(__x86_64__)

static const u8 swbkp_insn[] = {0xcc};

#define LTRACE_SWBKP_ADDR(f)    (frame_fault_pc(f) - sizeof(swbkp_insn))

static boolean ltrace_plt_parse(void *plt_entry, u64 addr, u64 *entry_size, u64 *sym_offset)
{
    const u8 jmpq[] = {0xff, 0x25};
    const u8 endbr64[] = {0xf3, 0x0f, 0x1e, 0xfa};
    const u8 bndjmp[] = {0xf2, 0xff, 0x25};
    const u8 pushq = 0x68;
    if (!runtime_memcmp(plt_entry, jmpq, sizeof(jmpq))) {
        /* first instruction: jmpq *0x11223344(%rip) */
        *sym_offset = *(s32 *)(plt_entry + 2) + addr + 6;
        /* if the second instruction is pushq, than this entry is used for lazy binding */
        *entry_size = (*(u8 *)(plt_entry + 6) == pushq) ? 16 : 8;
    } else if (!runtime_memcmp(plt_entry, endbr64, sizeof(endbr64))) {
        /* first instruction: endbr64 */
        if (!runtime_memcmp(plt_entry + 4, bndjmp, sizeof(bndjmp)))
            /* second instruction: bnd jmp *0x11223344(%rip) */
            *sym_offset = *(s32 *)(plt_entry + 7) + addr + 11;
        else if (!runtime_memcmp(plt_entry + 4, jmpq, sizeof(jmpq)))
            /* second instruction: jmp *0x11223344(%rip) */
            *sym_offset = *(s32 *)(plt_entry + 6) + addr + 10;
        else
            return false;
        *entry_size = 16;
    } else {
        return false;
    }
    return true;
}

#elif defined(__aarch64__)

static const u8 swbkp_insn[] = {0x00, 0x00, 0x20, 0xd4};

#define LTRACE_SWBKP_ADDR(f)    frame_fault_pc(f)

static boolean ltrace_plt_parse(void *plt_entry, u64 addr, u64 *entry_size, u64 *sym_offset)
{
    u32 insn1 = *(u32*)plt_entry;
    u32 insn2 = *(u32*)(plt_entry + 4);
    if (((insn1 & 0x9f000000) == 0x90000000) && ((insn2 & 0xffc00000) == 0xf9400000)) {
        /* first instruction: adrp xyy, 0x11223344 */
        /* second instruction: ldr xzz, [xyy, #1234] */
        s64 addr_offset = ((insn1 & 0x007fffe0) >> 3) | ((insn1 & 0x60000000) >> 29);
        addr_offset <<= 12;
        if (insn1 & 0x00100000)
            addr_offset = -addr_offset;
        addr_offset += (insn2 & 0x003ffc00) >> 7;
        *sym_offset = (addr & 0xfffffffffffff000) + addr_offset;
        *entry_size = 16;
    } else {
        return false;
    }
    return true;
}

#else

#error "ltrace not implemented for this architecture"

#endif

static u64 ltrace_get_sym(Elf64_Rela *reltab, int relcount, u64 sym_offset, u64 *rel_index)
{
    for (u64 i = *rel_index + 1; i != *rel_index; i++) {
        if (i >= relcount)
            i = 0;
        if (reltab[i].r_offset == sym_offset) {
            *rel_index = i;
            return ELF64_R_SYM(reltab[i].r_info);
        }
    }
    return -1ull;
}

typedef struct ltrace_brkpt {
    struct rbnode n;    /* must be first */
    void *plt_entry;
    u64 addr;   /* userspace instruction pointer */
    u8 insn[sizeof(swbkp_insn)];
    sstring sym_name;
} *ltrace_brkpt;

struct ltrace {
    rbtree plt_map; /* maps PLT entries to breakpoints */
    closure_struct(rb_key_compare, brkpt_compare);
    table ctx_map;  /* maps single-stepping context frames to breakpoints */
    struct spinlock lock;
};

static struct ltrace *ltrace;

closure_func_basic(rb_key_compare, int, ltrace_brkpt_compare,
                   rbnode a, rbnode b)
{
    ltrace_brkpt ba = (ltrace_brkpt)a;
    ltrace_brkpt bb = (ltrace_brkpt)b;
    return ba->addr == bb->addr ? 0 : (ba->addr < bb->addr ? -1 : 1);
}

void ltrace_init(value cfg, buffer exe, u64 load_offset)
{
    Elf64_Shdr *symtab, *strtab;
    Elf64_Rela *reltab;
    int relcount;
    if (!elf_dyn_parse(exe, &symtab, &strtab, &reltab, &relcount))
        halt("ltrace: failed to parse dynamic section\n");
    if (!symtab || !strtab || !reltab) {
        msg_err("ltrace: not a dynamically linked executable");
        return;
    }
    u64 plt_addr, plt_offset, plt_size;
    if (!elf_plt_get(exe, &plt_addr, &plt_offset, &plt_size)) {
        halt("ltrace: failed to get PLT\n");
        return;
    }
    Elf64_Sym *syms = buffer_ref(exe, symtab->sh_offset);
    u64 sym_count = symtab->sh_size / symtab->sh_entsize;
    heap h = heap_locked(get_kernel_heaps());
    ltrace = allocate(h, sizeof(*ltrace));
    assert(ltrace != INVALID_ADDRESS);
    ltrace->plt_map = allocate_rbtree(h,
                                      init_closure_func(&ltrace->brkpt_compare, rb_key_compare,
                                                        ltrace_brkpt_compare),
                                      0);
    assert(ltrace->plt_map != INVALID_ADDRESS);
    ltrace->ctx_map = allocate_table(h, identity_key, pointer_equal);
    assert(ltrace->ctx_map != INVALID_ADDRESS);
    spin_lock_init(&ltrace->lock);

    /* For each PLT entry, retrieve the offset of the corresponding symbol, then retrieve the symbol
     * index from the relocation table; then, replace the first instruction in the PLT entry with a
     * breakpoint instruction. */
    void *plt_base = buffer_ref(exe, plt_offset);
    u64 plt_entry_size;
    u64 rel_index = relcount;
    for (void *plt_entry = plt_base; plt_entry < plt_base + plt_size;
         plt_entry += plt_entry_size, plt_addr += plt_entry_size) {
        u64 sym_offset;
        if (!ltrace_plt_parse(plt_entry, plt_addr, &plt_entry_size, &sym_offset)) {
            ltrace_debug("skipping PLT entry at 0x%lx", plt_addr);
            plt_entry_size = PLT_ENTRY_SIZE_DEFAULT;
            continue;
        }
        u64 sym_index = ltrace_get_sym(reltab, relcount, sym_offset, &rel_index);
        if (sym_index >= sym_count) {
            ltrace_debug("PLT entry at 0x%lx: cannot find symbol at 0x%lx", plt_addr, sym_offset);
            continue;
        }
        ltrace_brkpt brkpt = allocate(h, sizeof(*brkpt));
        assert(brkpt != INVALID_ADDRESS);
        brkpt->plt_entry = plt_entry;
        brkpt->addr = plt_addr + load_offset;
        runtime_memcpy(brkpt->insn, plt_entry, sizeof(swbkp_insn));
        runtime_memcpy(plt_entry, swbkp_insn, sizeof(swbkp_insn));
        brkpt->sym_name = elf_string(exe, strtab, syms[sym_index].st_name);
        if (sstring_is_null(brkpt->sym_name))
            halt("ltrace: no name for symbol 0x%lx\n", sym_index);
        ltrace_debug("PLT entry at 0x%lx: relocation 0x%lx, symbol 0x%lx at 0x%lx (%s)", plt_addr,
                     rel_index, sym_index, sym_offset, brkpt->sym_name);
        init_rbnode(&brkpt->n);
        rbtree_insert_node(ltrace->plt_map, &brkpt->n);
    }
}

/* This function is called after either hitting a breakpoint, or executing a single-stepped
 * instruction.
 * Note: replacing instructions with breakpoints and vice versa is not multi-thread-safe: if
 * different threads call the same dynamic library function at the same time, it can happen that a
 * function call is not logged, or is logged more than once, or even that invalid instructions are
 * executed; but this can (and does) happen also with the Linux ltrace tool.  */
boolean ltrace_handle_trap(context_frame f)
{
    if (!ltrace)
        return false;
    spin_lock(&ltrace->lock);
    ltrace_brkpt brkpt = table_remove(ltrace->ctx_map, f);
    spin_unlock(&ltrace->lock);
    if (brkpt) {
        /* A single-stepped instruction has been executed: reinsert the breakpoint and disable
         * single stepping. */
        runtime_memcpy(brkpt->plt_entry, swbkp_insn, sizeof(swbkp_insn));
        frame_disable_stepping(f);
        return true;
    }
    u64 insn_addr = LTRACE_SWBKP_ADDR(f);
    struct ltrace_brkpt k = {
        .addr = insn_addr,
    };
    brkpt = (ltrace_brkpt)rbtree_lookup(ltrace->plt_map, &k.n);
    if (brkpt == INVALID_ADDRESS)
        return false;

    /* A breakpoint has been hit: replace the breakpoint with the original instruction, then enable
     * single stepping and execute the original instruction. */
    rprintf("[LTRACE] %s\n", brkpt->sym_name);
    spin_lock(&ltrace->lock);
    table_set(ltrace->ctx_map, f, brkpt);
    spin_unlock(&ltrace->lock);
    runtime_memcpy(brkpt->plt_entry, brkpt->insn, sizeof(swbkp_insn));
    frame_enable_stepping(f);
    frame_set_insn_ptr(f, insn_addr);
    return true;
}

void ltrace_signal(u32 signo)
{
    if (ltrace)
        rprintf("[LTRACE] --- SIGNAL %d ---\n", signo);
}
