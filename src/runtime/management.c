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
    tuple target = 0;
    value v = 0;
    u64 depth = 0;
    char *resultstr = 0;

    if ((args = get_tuple(t, sym(get)))) {
        req = MGMT_REQ_GET;
    } else if ((args = get_tuple(t, sym(set)))) {
        req = MGMT_REQ_SET;
    }

    if (req == MGMT_REQ_GET || req == MGMT_REQ_SET) {
        path = get_string(args, sym(path));
        if (!path) {
            resultstr = "could not parse path attribute";
            goto out;
        }
        target = resolve_tuple_path(management.root, path);
        if (!target) {
            resultstr = "could not resolve path";
            goto out;
        }
        attr = get_string(args, sym(attr));
    }

    tuple attrs;
    switch (req) {
    case MGMT_REQ_GET:
        if (attr) {
            target = get(target, intern(attr));
            if (!target) {
                resultstr = "attribute not found";
                goto out;
            }
        }
        attrs = timm("indent", "3");
        if (get_u64(args, sym(depth), &depth))
            timm_append(attrs, "depth", "%ld", depth);
        bprintf(b, "(v:%V)\n", target, attrs);
        deallocate_value(attrs);
        break;
    case MGMT_REQ_SET:
        if (!attr) {
            resultstr = "attribute not found";
            goto out;
        }
        v = get_string(args, sym(value));
        if (!v) {
            resultstr = "value not found";
            goto out;
        }
        if (is_null_string(v))
            v = 0;              /* unset */
        set(target, intern(attr), v);
        bprintf(b, "()\n");
        break;
    default:
        resultstr = "unable to parse request";
    }
  out:
    if (resultstr)
        bprintf(b, "(result:%s)\n", resultstr);
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
    table get_notifys;           /* get_value_notifys */
    table set_notifys;           /* set_value_notifys */
} *tuple_notifier;

/* It might be a shade more elegant to make a function-backed value to poll
   dynamic values rather than use a get notifier, and it would avoid the table
   lookup in get_notifys. There are some subtleties that need to be sorted
   out, though. For instance, would a get or iterate always return the
   function-backed value or the resolved value (value of function)? If the
   former, then every value returned by a get may require additional
   resolution. One advantage of this method is that the backed value may be
   stored and later resolved before use, whereas resolution at the get would
   strip the value of this backed property.

   In the latter case, which makes such backing transparent for most uses,
   some uses such as destruct_tuple would need non-resolving variants of get
   and iterate to operate on the backed value itself. */

closure_function(1, 1, value, tuple_notifier_get,
                 tuple_notifier, tn,
                 symbol, s)
{
    get_value_notify n;
    if (bound(tn)->get_notifys && (n = table_find(bound(tn)->get_notifys, s)))
        return apply(n);
    else
        return get(bound(tn)->parent, s); /* transparent */
}

closure_function(1, 2, void, tuple_notifier_set,
                 tuple_notifier, tn,
                 symbol, s, value, v)
{
    /* check for notify */
    set_value_notify vh = table_find(bound(tn)->set_notifys, s);
    if (vh) {
        if (!apply(vh, v))
            return;             /* setting of value not allowed */
    }
    set(bound(tn)->parent, s, v);
}

closure_function(2, 2, boolean, tuple_notifier_iterate_each,
                 tuple_notifier, tn, binding_handler, h,
                 symbol, s, value, v)
{
    get_value_notify n;
    if (bound(tn)->get_notifys && (n = table_find(bound(tn)->get_notifys, s)))
        v = apply(n);
    return apply(bound(h), s, v);
}

closure_function(1, 1, void, tuple_notifier_iterate,
                 tuple_notifier, tn,
                 binding_handler, h)
{
    /* This assumes that all attributes of interest exist in the parent
       tuple. Values that are served by get_notifys should still have
       corresponding entries in the parent tuple if they are to be included in
       an iterate. */
    iterate(bound(tn)->parent, stack_closure(tuple_notifier_iterate_each, bound(tn), h));
}

tuple_notifier tuple_notifier_wrap(tuple parent)
{
    tuple_notifier tn = allocate(management.fth, sizeof(struct tuple_notifier));
    if (tn == INVALID_ADDRESS)
        return tn;
    tn->parent = parent;
    tn->get_notifys = 0;
    tn->set_notifys = 0;
    tn->f.g = closure(management.h, tuple_notifier_get, tn);
    tn->f.s = closure(management.h, tuple_notifier_set, tn);
    tn->f.i = closure(management.h, tuple_notifier_iterate, tn);
    return tn;
}

void tuple_notifier_unwrap(tuple_notifier tn)
{
    if (tn->set_notifys)
        deallocate_table(tn->set_notifys);
    if (tn->get_notifys)
        deallocate_table(tn->get_notifys);
    deallocate_closure(tn->f.g);
    deallocate_closure(tn->f.s);
    deallocate_closure(tn->f.i);
    deallocate(management.fth, tn, sizeof(struct tuple_notifier));
}

void tuple_notifier_register_get_notify(tuple_notifier tn, symbol s, get_value_notify n)
{
    if (!tn->get_notifys) {
        tn->get_notifys = allocate_table(management.h, identity_key, pointer_equal);
        assert(tn->get_notifys != INVALID_ADDRESS);
    }
    table_set(tn->get_notifys, s, n);
}

void tuple_notifier_register_set_notify(tuple_notifier tn, symbol s, set_value_notify n)
{
    if (!tn->set_notifys) {
        tn->set_notifys = allocate_table(management.h, identity_key, pointer_equal);
        assert(tn->set_notifys != INVALID_ADDRESS);
    }
    table_set(tn->set_notifys, s, n);
    value v = get(tn->parent, s);
    if (v)
        apply(n, v);
}

extern void init_management_telnet(heap h, value meta);

void init_management_root(tuple root)
{
    assert(management.h);
    assert(!management.root);
    management.root = root;

#ifdef KERNEL // XXX should be runtime mgmt options
    /* XXX move interfaces into klibs */
    value v = get_string(root, sym(telnet_mgmt));
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
