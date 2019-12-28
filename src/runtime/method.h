typedef void *(*m_get)(value m, symbol b);
typedef void (*m_set)(value m, symbol b, value v);
typedef u64 (*m_elements)(value m);
typedef void (*m_format)(buffer b, value m);
typedef closure_type(each, void, value, value, thunk);
typedef void (*m_iterate)(heap h, value v, each e);

typedef struct methods {
    m_get get;
    m_set set;
    m_iterate iterate;
    m_format format;
    m_elements elements;                
} *methods;

extern methods tagmethods[tag_max];

static inline methods methods_of(value v)
{
    // check tag max
    if (tagof(v) == tag_method_rewind) {
        return ((methods)v - 1);
    }
    return tagmethods[tagof(v)];
}

#define get(__m, __k) (methods_of(__m)->get)(__m, __k)
#define set(__m, __k, __v) (methods_of(__m)->set)(__m, __k, __v)
#define elements(__m) (methods_of(__m)->elements)(__m)
#define vformat(__b, __m)  (methods_of(__m)->format)(__b, __m) // should be format?
#define iterate(__h, __m, __e) (methods_of(__m)->iterate)(__h, __m, __e)

each close_each_copy(heap h, value *, value *, thunk *);

// we clear __k here at the end because the compiler is getting
// confused that the condition is being modified outside the loop body..
#define foreach(__m, __k, __v)                  \
    for (void *__k = 0, *__v, *__pnext,                         \
             *it=close_each_copy(transient, &__k, &__v, (thunk *)&__pnext);__k != INVALID_ADDRESS;) \
        for(iterate(transient, __m, (each)it); __k != INVALID_ADDRESS; __k =0 , apply((thunk)__pnext))


static inline value allocate_method_rewind(heap h, bytes size,
                                           m_get g, m_set s, m_iterate i, m_format f, m_elements e)
{
    methods m = allocate(h, size + sizeof(struct methods));
    m->get = g;
    m->set = s;
    m->iterate = i;
    m->format = f;
    m->elements = e;
    return (value)(m+1);
}

