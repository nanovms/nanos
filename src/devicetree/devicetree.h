#define dt_u32(x) be32toh(x)
#define dt_u64(x) be64toh(x)
#define dt_string(b, x) dtb_string(b, dt_u32(x))
#define dt_get_prop_value(b, n, nm) dtb_read_value((b), (n), dtb_get_prop((b), (n), (nm)))

#define dt_reg_foreach(ri, r) \
    for (range r; dtb_reg_iterate(&(ri), &(r));)

enum {
    DT_VALUE_INVALID,
    DT_VALUE_UNKNOWN,
    DT_VALUE_EMPTY,
    DT_VALUE_U32,
    DT_VALUE_U64,
    DT_VALUE_STRING,
    DT_VALUE_PHANDLE,
    DT_VALUE_STRINGLIST,
    DT_VALUE_REG,
    DT_VALUE_FREQ,
};

typedef struct dt_node *dt_node;
typedef struct dt_prop *dt_prop;

typedef struct dt_reg_iterator {
    u32 *data_ptr;
    u32 *data_end;
    u32 address_cells;
    u32 size_cells;
} dt_reg_iterator;

typedef struct dt_value {
    int type;
    void *data;
    u32 dlen;
    union {
        u64 num;
        char *string;
        dt_reg_iterator ri;
    } u;
} dt_value;

closure_type(dt_node_handler, boolean, dt_node n, sstring name);

sstring dtb_string(void *dtb, u64 off);

u32 dtb_read_u32(dt_prop p);
u64 dtb_read_u64(dt_prop p);
dt_reg_iterator dtb_read_reg(void *dtb, dt_node n, dt_prop p);
boolean dtb_reg_iterate(dt_reg_iterator *ri, range *r);
range dtb_read_memory_range(void *dtb);

dt_node dtb_find_node_by_path(void *dtb, sstring path);
dt_node dtb_find_node_by_phandle(void *dtb, u32 phandle);
int dtb_walk_node_children(void *dtb, dt_node n, sstring match, dt_node_handler nh);
u32 dtb_blob_size(void *dtb);
dt_node dtb_get_root(void *dtb);
dt_node dtb_get_parent(void *dtb, dt_node n);
dt_prop dtb_get_prop(void *dtb, dt_node n, sstring pname);
dt_value dtb_read_value(void *dtb, dt_node n, dt_prop p);

void devicetree_dump(void *dtb);


