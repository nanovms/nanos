void tprintf(symbol tag, tuple attrs, const char *format, ...);
void vtprintf(symbol tag, tuple attrs, const char *format, vlist *ap);
void init_tracelog_config(tuple root);
void init_tracelog(heap h);
