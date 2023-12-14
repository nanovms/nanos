void init_management(heap function_tuple_heap, heap general);
void init_management_root(tuple root);
tuple allocate_function_tuple(tuple_get g, tuple_set s, tuple_iterate i);
void management_reset(void);
parser management_parser(buffer_handler out);

struct tuple_notifier;
typedef struct tuple_notifier *tuple_notifier;
typedef closure_type(set_value_notify, boolean, value);
typedef closure_type(get_value_notify, value);

tuple_notifier tuple_notifier_wrap(value parent, boolean copy_on_write);
void tuple_notifier_unwrap(tuple_notifier tn);
void tuple_notifier_register_get_notify(tuple_notifier tn, symbol s, get_value_notify n);
void tuple_notifier_register_set_notify(tuple_notifier tn, symbol s, set_value_notify n);
