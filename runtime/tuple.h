typedef table tuple;

typedef struct encoder *encoder;
typedef struct dencoder *dencoder;

void init_tuples(heap theap, heap thheap);
void print_tuple(buffer b, tuple t);

void encode_tuple(buffer dest, table dictionary, tuple t);


// h is for the bodies, the space for symbols and tuples are both implicit
void *decode_value(heap h, tuple dictionary, buffer source);
void encode_eav(buffer dest, table dictionary, tuple e, symbol a, value v);
typedef closure_type(iterate_each, void, symbol, value);

// there are lots of ways to imagine specializing this,
// but vtable style here
typedef struct tuple_handler {
    void (*get)(void *, symbol, value_handler);
    void (*set)(void *, symbol, value, status_handler);
    void (*iterate)(void *, iterate_each);
} *tuple_handler;


// h is for the bodies, the space for symbols and tuples are both implicit
typedef closure_type(decode_allocate, value, value, symbol);
value decode_value(heap h, tuple dictionary, buffer source);
void encode_eav(buffer dest, table dictionary, tuple e, symbol a, value v);

// seriously reconsider types allowed in tuples.. in particular simple
// ints have an anambiguous translation back and forth to strings (?)
static inline u64 u64_from_value(value v)
{
    u64 result;
    parse_int((buffer)v, 10, &result);
    return result;
}


static inline void get(value t, symbol n, value_handler r)
{
    switch(tagof(t)) {
    case tag_tuple:
        {
            value v = table_find((table)t, n);
            apply(r, v);
        }
    case tag_tuple_handler:
        ((tuple_handler)t)->get((tuple_handler)t, n, r);
    default:
        halt("invalid get");
    }
}

static inline void set(value t, symbol n, value v, status_handler done)
{
    switch(tagof(t)) {
    case tag_tuple:
        table_set((table)valueof(t), n, v);
        apply(done, STATUS_OK);
        break;
    case tag_tuple_handler:
        ((tuple_handler)valueof(t))->set((tuple_handler)t, n, v, done);
        break;        
    default:
        halt("invalid set");
    }
}

// completion
static inline void iterate(tuple t, iterate_each r)
{
    switch(tagof(t)) {
    case tag_tuple:
        table_foreach((table)valueof(t), n ,v) apply(r, n, v);
        break;
    case tag_tuple_handler:
        return ((tuple_handler)valueof(t))->iterate((tuple_handler)t, r);
    default:
        halt("invalid iterate");
    }
}

// using substructure (like heap) cuts down on the cost of 3 addtl closures...meh?
tuple_handler allocate_tuple_handler(bytes size,
                                     void (*get)(void *, symbol, value_handler),
                                     void (*set)(void *, symbol, value, status_handler),
                                     void iterate(void *, iterate_each r));
