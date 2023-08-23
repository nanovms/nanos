#ifdef KERNEL
#include <kernel.h>
#else
#include <runtime.h>
#endif
#include <management.h>

declare_closure_struct(2, 2, void, mgmt_timer_expiry,
                       tuple, req, buffer_handler, out,
                       u64, expiry, u64, overruns);

static struct management {
    heap h;
    heap fth;                   /* function_tuples */
    tuple root;
    struct timer t;
    tuple timer_req;
    closure_struct(mgmt_timer_expiry, timer_expiry);
} management;

static value resolve_tuple_path(tuple n, string path, tuple *parent, symbol *a)
{
    vector v = split(management.h, (buffer) /* XXX */ path, '/');
    buffer i;
    vector_foreach(v, i) {
        /* null entries ("//") are skipped in path */
        if (buffer_length(i) == 0) {
            deallocate_buffer(i);
            continue;
        }
        if (parent)
            *parent = n;
        symbol s = intern(i);
        deallocate_buffer(i);
        if (a)
            *a = s;
        n = (tuple)get(n, s);
        if (!n)
            break;
    }
    deallocate_vector(v);
    return n;
}

declare_closure_function(1, 2, boolean, each_request,
                         buffer_handler, out,
                         value, k, value, args);

static void handle_request(tuple req, buffer_handler out)
{
    if (is_tuple(req))
        iterate(req, stack_closure(each_request, out));
    else {
        buffer b = aprintf(management.h, "(result:request not tuple)");
        apply(out, b);
    }
}

#ifdef KERNEL
define_closure_function(1, 2, void, mgmt_timer_expiry,
                        buffer_handler, out,
                        u64, expiry, u64, overruns)
{
    if (overruns != timer_disabled)
        handle_request(management.timer_req, bound(out));
}
#endif

define_closure_function(1, 2, boolean, each_request,
                        buffer_handler, out,
                        value, k, value, args)
{
    char *resultstr = 0;
    buffer b = allocate_buffer(management.h, 256);
    assert(b != INVALID_ADDRESS);
    if (k == sym(get)) {
        if (!is_tuple(args)) {
            resultstr = "missing arguments tuple";
            goto out;
        }
        string path = get_string(args, sym(path));
        if (!path) {
            resultstr = "could not parse path attribute";
            goto out;
        }
        value target = resolve_tuple_path(management.root, path, 0, 0);
        if (!target) {
            resultstr = "could not resolve path";
            goto out;
        }
        tuple attrs = timm("indent", "3");
        u64 depth;
        if (get_u64(args, sym(depth), &depth))
            timm_append(attrs, "depth", "%ld", depth);
        bprintf(b, "(v:%V)\n", target, attrs);
        deallocate_value(attrs);
    } else if (k == sym(set)) {
        if (!is_tuple(args)) {
            resultstr = "missing arguments tuple";
            goto out;
        }
        string path = get_string(args, sym(path));
        if (!path) {
            resultstr = "could not parse path attribute";
            goto out;
        }
        symbol a = 0;
        tuple parent = 0;
        resolve_tuple_path(management.root, path, &parent, &a);
        if (!parent) {
            resultstr = "could not resolve path";
            goto out;
        }
        value v = get(args, sym(value));
        if (!v) {
            resultstr = "value not found";
            goto out;
        }
        if (is_null_string(v))
            v = 0;              /* unset */
        set(parent, a, v);
        bprintf(b, "()\n");
#ifdef KERNEL
    } else if (k == sym(timer)) {
        if (is_null_string(args)) {
            remove_timer(kernel_timers, &management.t, 0);
        } else if (is_tuple(args)) {
            tuple req = get_tuple(args, sym(request));
            if (!req) {
                resultstr = "could not parse request";
                goto out;
            }

            u64 period;
            if (!get_u64(args, sym(period), &period)) {
                resultstr = "could not parse period";
                goto out;
            }

            /* prune the request; timer will hold onto it */
            set(args, sym(request), 0);

            /* disable any existing timer */
            remove_timer(kernel_timers, &management.t, 0);

            handle_request(req, bound(out));
            timestamp t = seconds(period);
            management.timer_req = req;
            register_timer(kernel_timers, &management.t, CLOCK_ID_MONOTONIC, t, false, t,
                           init_closure(&management.timer_expiry, mgmt_timer_expiry,
                                        bound(out)));
        } else {
            resultstr = "could not parse timer tuple";
            goto out;
        }
        bprintf(b, "()\n");
#endif
    } else {
        resultstr = "unknown command";
    }
  out:
    if (resultstr)
        bprintf(b, "(result:%s)\n", resultstr);
    apply(bound(out), b);
    return true;
}

closure_function(1, 1, void, mgmt_tuple_parsed,
                 buffer_handler, out,
                 void *, p)
{
    handle_request(p, bound(out));
    destruct_value(p, true);
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

/* icky; only one interface supported */
void management_reset(void)
{
#ifdef KERNEL
    remove_timer(kernel_timers, &management.t, 0);
    if (management.timer_req) {
        destruct_value(management.timer_req, true);
        management.timer_req = 0;
    }
#endif
}

parser management_parser(buffer_handler out)
{
    heap h = management.h;
    return tuple_parser(h, closure(h, mgmt_tuple_parsed, out),
                        closure(h, mgmt_tuple_parse_error, out));
}

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
                 value, a)
{
    symbol s;
    get_value_notify n;
    if (bound(tn)->get_notifys &&
        ((s = sym_from_attribute(a)) && (n = table_find(bound(tn)->get_notifys, s))))
        return apply(n);
    else
        return get(bound(tn)->parent, a); /* transparent */
}

closure_function(1, 2, void, tuple_notifier_set,
                 tuple_notifier, tn,
                 value, a, value, v)
{
    /* check for notify */
    set_value_notify vh;
    symbol s = sym_from_attribute(a);
    assert(s);
    if ((vh = table_find(bound(tn)->set_notifys, s))) {
        if (!apply(vh, v))
            return;             /* setting of value not allowed */
    }
    set(bound(tn)->parent, a, v);
}

closure_function(2, 2, boolean, tuple_notifier_iterate_each,
                 tuple_notifier, tn, binding_handler, h,
                 value, a, value, v)
{
    get_value_notify n;
    symbol s = sym_from_attribute(a);
    assert(s);
    if (bound(tn)->get_notifys && (n = table_find(bound(tn)->get_notifys, s)))
        v = apply(n);
    return apply(bound(h), s, v);
}

closure_function(1, 1, boolean, tuple_notifier_iterate,
                 tuple_notifier, tn,
                 binding_handler, h)
{
    /* This assumes that all attributes of interest exist in the parent
       tuple. Values that are served by get_notifys should still have
       corresponding entries in the parent tuple if they are to be included in
       an iterate. */
    return iterate(bound(tn)->parent, stack_closure(tuple_notifier_iterate_each, bound(tn), h));
}

closure_function(1, 0, value, tuple_notifier_wrapped,
                 tuple_notifier, tn)
{
    return bound(tn)->parent;
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

    /* The special /wrapped attribute is probed by print_value and friends.
       Since it's not in the parent tuple, it won't show up in an iterate; it's hidden. */
    tuple_notifier_register_get_notify(tn, sym(/wrapped),
                                       closure(management.h, tuple_notifier_wrapped, tn));
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

extern void init_management_telnet(heap h, value meta);

void init_management_root(tuple root)
{
    assert(management.h);
    assert(!management.root);
    management.root = root;

#ifdef MANAGEMENT_TELNET
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
