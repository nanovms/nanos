#include <runtime.h>
#include <management.h>

static struct management {
    heap h;
    heap fth;                   /* function_tuples */
    tuple root;
} management;

static value resolve_tuple_path(tuple n, string path)
{
    vector v = split(management.h, (buffer) /* XXX */ path, '/');
    buffer i;
    vector_foreach(v, i) {
        /* null entries ("//") are skipped in path */
        if (buffer_length(i) == 0)
            continue;
        n = (tuple)get(n, intern(i));
        if (!n)
            return n;
    }
    return n;
}

closure_function(1, 1, void, mgmt_tuple_parsed,
                 buffer_handler, out,
                 void *, p)
{
    enum {
        MGMT_REQ_UNDEF,
        MGMT_REQ_GET,
        MGMT_REQ_SET,
    } req = MGMT_REQ_UNDEF;

    tuple t = (tuple)p;
    tuple args;
    buffer b = allocate_buffer(management.h, 256);
    assert(b != INVALID_ADDRESS);

    string path = 0;
    string attr = 0;
    string depthstr = 0;
    tuple target = 0;
    value v = 0;
    u64 depth = 1;

    if ((args = get_tuple(t, sym(get)))) {
        req = MGMT_REQ_GET;
    } else if ((args = get_tuple(t, sym(set)))) {
        req = MGMT_REQ_SET;
    }

    if (req == MGMT_REQ_GET || req == MGMT_REQ_SET) {
        path = get_string(args, sym(path));
        if (!path) {
            bprintf(b, "could not parse path attribute\n");
            goto out;
        }
        target = resolve_tuple_path(management.root, path);
        if (!target) {
            bprintf(b, "could not resolve path\n");
            goto out;
        }
        attr = get_string(args, sym(attr));
    }

    switch (req) {
    case MGMT_REQ_GET:
        if (attr) {
            target = get(target, intern(attr));
            if (!target) {
                bprintf(b, "attribute not found\n");
                goto out;
            }
        }
        depthstr = get_string(args, sym(depth));
        if (depthstr) {
            if (!u64_from_value(depthstr, &depth)) {
                bprintf(b, "unable to parse depth value\n");
                goto out;
            }
        }
        bprintf(b, "%V\n", target, depth);
        break;
    case MGMT_REQ_SET:
        if (!attr) {
            bprintf(b, "set: no attr found\n");
            goto out;
        }
        v = get(args, sym(value));
        if (!v) {
            bprintf(b, "value not found\n");
            goto out;
        }
        set(target, intern(attr), v);
        break;
    default:
        bprintf(b, "unable to parse request\n");
    }
  out:
    apply(bound(out), b);
}

closure_function(1, 1, void, mgmt_tuple_parse_error,
                 buffer_handler, out,
                 string, s)
{
    buffer b = allocate_buffer(management.h, 128);
    assert(b != INVALID_ADDRESS);
    bprintf(b, "failed to parse request tuple: %b\n", s);
    apply(bound(out), b);
}

parser management_parser(buffer_handler out)
{
    heap h = management.h;
    return tuple_parser(h, closure(h, mgmt_tuple_parsed, out),
                        closure(h, mgmt_tuple_parse_error, out));
}
KLIB_EXPORT(management_parser);

tuple allocate_function_tuple(tuple_get g, tuple_set s, tuple_iterate i)
{
    function_tuple f = allocate_zero(management.fth, sizeof(struct function_tuple));
    if (f == INVALID_ADDRESS)
        return INVALID_ADDRESS;
    f->g = g;
    f->s = s;
    f->i = i;
    return (tuple)f;
}
KLIB_EXPORT(allocate_function_tuple);

typedef struct tuple_notifier {
    struct function_tuple f;
    tuple parent;
    table notifys;              /* value_handlers */
} *tuple_notifier;

closure_function(1, 1, value, tuple_notifier_get,
                 tuple_notifier, tn,
                 symbol, s)
{
    /* transparent */
    return get(bound(tn)->parent, s);
}

closure_function(1, 2, void, tuple_notifier_set,
                 tuple_notifier, tn,
                 symbol, s, value, v)
{
    if (is_null_string(v))
        v = 0;
    set(bound(tn)->parent, s, v);

    /* check for notify */
    value_handler vh = table_find(bound(tn)->notifys, s);
    if (vh)
        apply(vh, v);
}

closure_function(1, 1, void, tuple_notifier_iterate,
                 tuple_notifier, tn,
                 binding_handler, h)
{
    iterate(bound(tn)->parent, h);
}

tuple_notifier tuple_notifier_wrap(tuple parent)
{
    tuple_notifier tn = allocate(management.fth, sizeof(struct tuple_notifier));
    if (tn == INVALID_ADDRESS)
        return tn;
    tn->parent = parent;
    tn->notifys = allocate_table(management.h, identity_key, pointer_equal);
    tn->f.g = closure(management.h, tuple_notifier_get, tn);
    tn->f.s = closure(management.h, tuple_notifier_set, tn);
    tn->f.i = closure(management.h, tuple_notifier_iterate, tn);
    return tn;
}

void tuple_notifier_unwrap(tuple_notifier tn)
{
    table_foreach(tn->notifys, s, n) {
        (void)s;
        apply((value_handler)n, INVALID_ADDRESS);
    }
    deallocate_table(tn->notifys);
    deallocate_closure(tn->f.g);
    deallocate_closure(tn->f.s);
    deallocate_closure(tn->f.i);
    deallocate(management.fth, tn, sizeof(struct tuple_notifier));
}

void tuple_notifier_register_notify(tuple_notifier tn, symbol s, value_handler vh)
{
    table_set(tn->notifys, s, vh);
    value v = get(tn->parent, s);
    if (v)
        apply(vh, v);
}

extern void init_management_telnet(heap h, value meta);

void init_management_root(tuple root)
{
    assert(management.h);
    assert(!management.root);
    management.root = root;

#ifdef KERNEL // XXX should be runtime mgmt options
    /* XXX move interfaces into klibs */
    value v = get(root, sym(telnet_mgmt));
    if (v)
        init_management_telnet(management.h, v);
#endif
}

void init_management(heap function_tuple_heap, heap general)
{
    management.h = general;
    management.fth = function_tuple_heap;
    management.root = 0;
}

