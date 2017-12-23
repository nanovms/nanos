typedef struct xmitheader *xmitheader;

struct xmitheader {
  void (*callback)();
  void *a;
  void *buffer;
  int length;
  int header_length;
  xmitheader next;
};
