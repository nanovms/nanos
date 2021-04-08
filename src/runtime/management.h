void init_management(heap function_tuple_heap, heap general);
void init_management_root(tuple root);
tuple allocate_function_tuple(tuple_get g, tuple_set s, tuple_iterate i);
parser management_parser(buffer_handler out);

struct tuple_notifier;
typedef struct tuple_notifier *tuple_notifier;

tuple_notifier tuple_notifier_wrap(tuple parent);
void tuple_notifier_unwrap(tuple_notifier tn);
void tuple_notifier_register_notify(tuple_notifier tn, symbol s, value_handler vh);
