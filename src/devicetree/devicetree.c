#include <runtime.h>
#include <devicetree.h>

/* Devicetree parsing notes:
 * This parsing implementation tries to hide the details of the devicetree blob
 * format as much as possible from the consumer, however the interpretation of
 * properties is often custom for a particular property and requires a property
 * specific parser.
 *
 * A property value can be represented by a generic dt_value structure which
 * contains information about the value's type and can contain the actual
 * value for simple types. The dtb_read_value function will generate a dt_value
 * from a dt_prop based on the property's name. If the consumer of a property
 * knows what the type will be it can avoid using the dt_value type and just use
 * an appropriate read helper function to generate the expected type directly,
 * although there is no type validation when accessing properties this way.
 *
 * All the calls that begin with dtb will directly parse the devicetree blob
 * and do not use any heap memory. This is obviously very inefficient but
 * necessary since some devicetree parsing is required before kernel memory
 * is set up and mapped.
 */

#define DTB_MAGIC       0xd00dfeed

#define FDT_BEGIN_NODE  0x00000001
#define FDT_END_NODE    0x00000002
#define FDT_PROP        0x00000003
#define FDT_NOP         0x00000004
#define FDT_END         0x00000009

typedef struct dt_header {
	u32 magic;
	u32 totalsize;
	u32 off_dt_struct;
	u32 off_dt_strings;
	u32 off_mem_rsvmap;
	u32 version;
	u32 last_comp_version;
	u32 boot_cpuid_phys;
	u32 size_dt_strings;
	u32 size_dt_struct;
} *dt_header;

typedef struct dt_reserve_entry {
    u64 address;
    u64 size;
} *dt_reserve_entry;

struct dt_node {
    u32 token;
    char name[0];
};

struct dt_prop {
    u32 data_length;
    u32 name;
    u8 data[0];
};

typedef closure_type(dt_node_begin_handler, boolean, dt_node, char *, int, dt_node);
typedef closure_type(dt_node_end_handler, boolean, dt_node, int);
typedef closure_type(dt_prop_handler, boolean, void *, dt_node, char *, dt_prop);

#define nelem(x) (sizeof((x))/sizeof((x)[0]))
static struct prop_value_map {
    char *name;
    int type;
} prop_value_map[] = {
    { "compatible", DT_VALUE_STRINGLIST },
    { "model", DT_VALUE_STRING },
    { "phandle", DT_VALUE_U32 },
    { "status", DT_VALUE_STRING },
    { "#address-cells", DT_VALUE_U32 },
    { "#size-cells", DT_VALUE_U32 },
    { "#interrupt-cells", DT_VALUE_U32 },
    { "interrupt-parent", DT_VALUE_PHANDLE },
    { "reg", DT_VALUE_REG },
    { "virtual-reg", DT_VALUE_U32 },
    { "device_type", DT_VALUE_STRING },
    { "bootargs", DT_VALUE_STRING },
    { "stdout-path", DT_VALUE_STRING },
    { "stdin-path", DT_VALUE_STRING },
    { "clock-frequency", DT_VALUE_FREQ },
    { "timebase-frequency", DT_VALUE_FREQ },
    { "mmu-type", DT_VALUE_STRING },
    { "cpu", DT_VALUE_PHANDLE },
};

char *dtb_string(void *dtb, u64 off)
{
    dt_header fdt = dtb;
    if (off >= dt_u32(fdt->size_dt_strings))
        return "(bad string offset)";
    return (char *)fdt + dt_u32(fdt->off_dt_strings) + off;
}

#define MAX_NODE_DEPTH 16

void dtb_walk_internal(void *dtb, dt_node dn,
       dt_node_begin_handler nbh, dt_node_end_handler neh, dt_prop_handler ph)
{
    dt_node nstack[MAX_NODE_DEPTH];
    char *name;
    int nodelevel = 0;
    dt_header fdt = dtb;
    u8 *n = (u8 *)dn;
    if (dt_u32(fdt->magic) != DTB_MAGIC) {
        console("dtb_walk_internal: bad magic\n");
        return;
    }
    u8 *end = dtb + dt_u32(fdt->totalsize);
    while (true) {
        if (n < (u8 *)dtb || n >= end) {
            console("dtb_walk_internal: parsing outside blob; aborted\n");
            return;
        }
        u32 token = dt_u32(*(u32 *)n);
        void *curtok = n;
        n += 4;
        void *data = n;
        switch (token) {
        case FDT_BEGIN_NODE:
            name = data;
            if (nbh && !apply(nbh, (dt_node)curtok, name, nodelevel, nodelevel ? nstack[nodelevel - 1] : INVALID_ADDRESS))
                return;
            n += pad(runtime_strlen(name) + 1, 4);
            nstack[nodelevel++] = curtok;
            break;
        case FDT_END_NODE:
            nodelevel--;
            if (neh && !apply(neh, nstack[nodelevel], nodelevel))
                return;
            if (nodelevel == 0)
                return;
            break;
        case FDT_PROP: {
            dt_prop p = data;
            name = dt_string(dtb, p->name);
            if (ph && !apply(ph, dtb, nstack[nodelevel - 1], name, p))
                return;
            n += sizeof(*p) + pad(dt_u32(p->data_length), 4);
            break;
        }
        case FDT_NOP:
            break;
        case FDT_END:
            console("dtb_walk_internal: unexpected FDT_END\n");
            return;
        default:
            console("dtb_walk_internal: unknown token\n");
            return;
        }
    }
}

u32 dtb_blob_size(void *dtb)
{
    dt_header fdt = dtb;
    if (dt_u32(fdt->magic) != DTB_MAGIC) {
        console("dtb_blob_size: bad magic\n");
        return 0;
    }
    return dt_u32(fdt->totalsize);
}

dt_node dtb_get_root(void *dtb)
{
    dt_header fdt = dtb;
    if (dt_u32(fdt->magic) != DTB_MAGIC) {
        console("dtb_get_root: bad magic\n");
        return INVALID_ADDRESS;
    }
    return (dt_node)(dtb + dt_u32(fdt->off_dt_struct));
}

closure_function(2, 4, boolean, get_parent_handler,
                 dt_node, ln, dt_node *, p,
                 dt_node, n, char *, name, int, level, dt_node, parent)
{
    if (bound(ln) == n) {
        *bound(p) = parent;
        return false;
    }
    return true;
}

dt_node dtb_get_parent(void *dtb, dt_node n)
{
    dt_node parent = INVALID_ADDRESS;
    dtb_walk_internal(dtb, dtb_get_root(dtb),
           stack_closure(get_parent_handler, n, &parent), 0, 0);
    return parent;
}

closure_function(2, 4, boolean, get_prop_handler,
                 char *, pname, dt_prop *, p,
                 void *, dtb, dt_node, n, char *, name, dt_prop, p)
{
    if (runtime_strcmp(bound(pname), name) == 0) {
        *bound(p) = p;
        return false;
    }
    return true;
}

closure_function(0, 4, boolean, get_prop_nb,
                 dt_node, n, char *, name, int, level, dt_node, parent)
{
    if (level > 0)
        return false;
    return true;
}

dt_prop dtb_get_prop(void *dtb, dt_node dn, char *pname)
{
    dt_prop p = INVALID_ADDRESS;
    if (dn == INVALID_ADDRESS)
        return p;
    dtb_walk_internal(dtb, dn, stack_closure(get_prop_nb), 0,
            stack_closure(get_prop_handler, pname, &p));
    return p;
}

dt_value dtb_read_value(void *dtb, dt_node n, dt_prop p)
{
    dt_value v;

    if (p == INVALID_ADDRESS)
        return (dt_value){ .type = DT_VALUE_INVALID };

    char *name = dt_string(dtb, p->name);
    void *data = p->data;

    v.type = DT_VALUE_UNKNOWN;
    v.data = data;
    v.dlen = dt_u32(p->data_length);

    for (int i = 0; i < nelem(prop_value_map); i++) {
        struct prop_value_map *m = &prop_value_map[i];
        if (runtime_strcmp(name, m->name) != 0)
            continue;
        v.type = m->type;
        switch (v.type) {
        case DT_VALUE_U32:
        case DT_VALUE_PHANDLE:
            v.u.num = dt_u32(*(u32 *)data);
            break;
        case DT_VALUE_U64:
            v.u.num = dt_u64(*(u64 *)data);
            break;
        case DT_VALUE_STRING:
        case DT_VALUE_STRINGLIST:
            v.u.string = data;
            break;
        case DT_VALUE_FREQ:
            v.u.num = v.dlen == sizeof(u32) ? dt_u32(*(u32 *)data) : dt_u64(*(u64 *)data);
            break;
        case DT_VALUE_REG:
            v.u.ri = dtb_read_reg(dtb, n, p);
            break;
        default:
            break;
        }
        break;
    }
    return v;
}

closure_function(4, 4, boolean, find_node_handler,
                 char *, tok, char *, nexttok, dt_node *, rn, int, plevel,
                dt_node, n, char *, name, int, level, dt_node, parent)
{
    char *tok = bound(tok);
    if (level == 0) {
        if (tok == 0) {
            *bound(rn) = n;
            return false;
        }
        bound(plevel)++;
        return true;
    }
    if (bound(plevel) == level && runtime_strcmp(tok, name) == 0) {
        bound(tok) = runtime_strtok_r(0, "/", &bound(nexttok));
        if (bound(tok) == 0) {
            *bound(rn) = n;
            return false;
        }
        bound(plevel)++;
    }
    return true;
}

dt_node dtb_find_node_by_path(void *dtb, char *path)
{
    dt_node n = INVALID_ADDRESS;
    if (path[0] != '/')
        return INVALID_ADDRESS;
    char *nexttok;
    char *tok = runtime_strtok_r(path, "/", &nexttok);
    dtb_walk_internal(dtb, dtb_get_root(dtb),
            stack_closure(find_node_handler, tok, nexttok, &n, 0), 0, 0);
    return n;
}

closure_function(2, 4, boolean, find_phandle_handler,
                 u32, phandle, dt_node *, rn,
                 void *, dtb, dt_node, n, char *, name, dt_prop, p)
{
    if (runtime_strcmp(name, "phandle") != 0)
        return true;
    dt_value v = dtb_read_value(dtb, n, p);
    if (v.u.num != bound(phandle))
        return true;
    *bound(rn) = n;
    return false;
}

dt_node dtb_find_node_by_phandle(void *dtb, u32 phandle)
{
    dt_node n = INVALID_ADDRESS;
    dtb_walk_internal(dtb, dtb_get_root(dtb), 0, 0,
            stack_closure(find_phandle_handler, phandle, &n));
    return n;
}

closure_function(3, 4, boolean, walk_child_handler,
                 char *, match, dt_node_handler, nh, int *, nmatches,
                 dt_node, n, char *, name, int, level, dt_node, parent)
{
    char *match = bound(match);
    *bound(nmatches) = 0;
    if (level == 1 && (match == 0 || runtime_strstr(name, match) == name)) {
         char *ep = match ? name + runtime_strlen(match) : 0;
         if (!match || *ep == 0 || *ep == '@') {
            (*bound(nmatches))++;
            return apply(bound(nh), n, name);
         }
    }
    return true;
}

int dtb_walk_node_children(void *dtb, dt_node n, char *match, dt_node_handler nh)
{
    int nmatches = 0;
    dtb_walk_internal(dtb, n, stack_closure(walk_child_handler, match, nh, &nmatches), 0, 0);
    return nmatches;
}

closure_function(1, 4, boolean, print_node,
                 int *, level,
                 dt_node, n, char *, name, int, level, dt_node, parent)
{
    *bound(level) = level + 1;
    while (level-- > 0)
        console("  ");
    if (name[0] == 0)
        console("/");
    else
        console(name);
    console(" (");
    print_u64(u64_from_pointer(n));
    console(")");
    console(" {\n");
    return true;
}

closure_function(1, 2, boolean, print_node_end,
                 int *, level,
                 dt_node, n, int, level)
{
    *bound(level) = level + 1;
    while (level-- > 0)
        console("  ");
    console("}\n");
    return true;
}

closure_function(1, 4, boolean, print_prop,
                 int *, level,
                 void *, dtb, dt_node, n, char *, name, dt_prop, p)
{
    int level = *bound(level);
    dt_value v = dtb_read_value(dtb, n, p);
    while (level-- > 0)
        console("  ");
    console(name);
    console(": ");
    switch (v.type) {
    case DT_VALUE_U32:
    case DT_VALUE_U64:
    case DT_VALUE_PHANDLE:
    case DT_VALUE_FREQ:
        console("0x");
        print_u64(v.u.num);
        break;
    case DT_VALUE_STRING:
        console("\"");
        console(v.data);
        console("\"");
        break;
    case DT_VALUE_STRINGLIST: {
        int cnt = 0;
        dt_stringlist_foreach(v, c) {
            if (cnt++ != 0)
                console(",");
            console("\"");
            console(c);
            console("\"");
        }
        break;
    }
    case DT_VALUE_REG: {
        dt_reg_foreach(v.u.ri, r) {
            console("[");
            print_u64(r.start);
            console(", ");
            print_u64(r.end);
            console(") ");
        }
        break;
    }
    default:
        console(" (data length 0x");
        print_u64(v.dlen);
        console(")");
        break;
    }
    console("\n");
    return true;
}

void devicetree_dump(void *dtb)
{
    int level = 0;
    dtb_walk_internal(dtb, dtb_get_root(dtb),
            stack_closure(print_node, &level), stack_closure(print_node_end, &level), stack_closure(print_prop, &level));
}

u32 dtb_read_u32(dt_prop p)
{
    return dt_u32(*(u32 *)p->data);
}

u64 dtb_read_u64(dt_prop p)
{
    return dt_u64(*(u64 *)p->data);
}

dt_reg_iterator dtb_read_reg(void *dtb, dt_node n, dt_prop p)
{
    dt_reg_iterator ri;
    ri.data_ptr = (u32 *)p->data;
    ri.data_end = (u32 *)(p->data + dt_u32(p->data_length));
    /* These default values are specified in the "Standard Properties" section of the devicetree spec */
    ri.address_cells = 2;
    ri.size_cells = 1;
    dt_node parent = dtb_get_parent(dtb, n);
    dt_prop pv = dtb_get_prop(dtb, parent, "#address-cells");
    if (pv != DT_VALUE_INVALID)
        ri.address_cells = dtb_read_u32(pv);
    pv = dtb_get_prop(dtb, parent, "#size-cells");
    if (pv != DT_VALUE_INVALID)
        ri.size_cells = dtb_read_u32(pv);
    return ri;
}

boolean dtb_reg_iterate(dt_reg_iterator *ri, range *r)
{
    u64 start = 0, len = 0;
    assert(ri->address_cells <= 2 && ri->size_cells <= 2);
    if (ri->data_ptr >= ri->data_end)
        return false;
    u32 *n = ri->data_ptr;
    for (int i = 0; i < ri->address_cells; i++)
        start = (start << 32) | dt_u32(*n++);
    for (int i = 0; i < ri->size_cells; i++)
        len = (len << 32) | dt_u32(*n++);
    ri->data_ptr = n;
    *r = irangel(start, len);
    return true;
}

closure_function(2, 2, boolean, read_mem_size,
                 void *, dtb, range *, r,
                 dt_node, n, char *, name)
{
    void *dtb = bound(dtb);
    dt_prop p = dtb_get_prop(dtb, n, "reg");
    if (p == INVALID_ADDRESS) {
        console("read_mem_size: memory node missing 'reg' property\n");
        return false;
    }
    dt_reg_iterator ri = dtb_read_reg(dtb, n, p);
    dt_reg_foreach(ri, r) {
        *bound(r) = r;
        break;
    }
    return false;
}

/* XXX Assume only one memory entry with one range */
range dtb_read_memory_range(void *dtb)
{
    range r = irangel(INVALID_PHYSICAL, 0);
    dtb_walk_node_children(dtb, dtb_get_root(dtb), "memory", stack_closure(read_mem_size, dtb, &r));
    return r;
}

