#pragma once
typedef table tuple;

typedef struct encoder *encoder;
typedef struct dencoder *dencoder;

void init_tuples(heap theap);
void print_tuple(buffer b, tuple t);

void encode_tuple(buffer dest, table dictionary, tuple t);


// h is for the bodies, the space for symbols and tuples are both implicit
void *decode_value(heap h, tuple dictionary, buffer source);
void encode_eav(buffer dest, table dictionary, tuple e, symbol a, value v);

// seriously reconsider types allowed in tuples.. in particular simple
// ints have an anambiguous translation back and forth to strings (?)
static inline u64 u64_from_value(value v)
{
    u64 result;
    parse_int((buffer)v, 10, &result);
    return result;
}

static inline value value_from_u64(heap h, u64 v)
{
    return aprintf(h, "%d", v);
}
