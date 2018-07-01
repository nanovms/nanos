typedef table tuple;

typedef struct encoder *encoder;
typedef struct dencoder *dencoder;

void init_tuples(heap theap);
void print_tuple(buffer b, tuple t);

void encode_tuple(buffer dest, table dictionary, tuple t);


// h is for the bodies, the space for symbols and tuples are both implicit
void *decode_value(heap h, tuple dictionary, buffer source);
void encode_eav(buffer dest, table dictionary, tuple e, symbol a, value v);
