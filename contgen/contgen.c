#include <stdarg.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

/* Helper functions to ignore unused result (eliminate CC warning) */
static inline void igr(int x) {}

char *output;
int size;
int fill = 0;
int nleft, nright;
int twiggy;

void ins(char x)
{
    if (fill == size) output = realloc(output, size *= 2);
    output[fill++] = x;
}

void pint(int x)
{
    if (x) {
        pint(x/10);
        ins('0' + (x%10));
    }
}

void pi(char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    for (char *i = fmt; *i ; i++) {
        int count = nright;
        switch (*i) {
        case '@':
            if (twiggy) {
                ins(',');
                ins(' ');
            }
            break;

        case '%':
            {
                int x = va_arg(ap, unsigned int);
                if (x) pint(x); else ins('0');
            }
            break;
        case '^':
            count = nleft;
        case '~':
            {
                char *subformat = va_arg(ap, char *);
                if (count == 0)
                    break;
                for (int i = 0 ; i < count; i++)
                    pi(subformat, i, i);
                twiggy = 1;
                break;
            }
        case '|':
            ins('\\');
            ins('\n');
            break;
        default: ins(*i);
        }
    }
    va_end(ap);
}

#define p(...)  {twiggy = 0; pi(__VA_ARGS__);}

void cblock()
{
    p("#define CLOSURE_STRUCT_%_%(_rettype, _name^~)|", nleft, nright, ", _lt%, _ln%", ", _rt%, _rn%");
    p("struct _closure_##_name {|");
    p("  _rettype (*__apply)(struct _closure_##_name *~);|", ", _rt%");
    p("  struct _closure_common __c;|");
    for (int i = 0; i < nleft ; i++)  p("  _lt% _ln%;|", i, i);
    p("};\n\n");

    p("#define CLOSURE_DECLARE_FUNCS_%_%(_rettype, _name^~)|", nleft, nright, ", _lt%, _ln%", ", _rt%, _rn%");
    p("static _rettype (**_fill_##_name(heap h, struct _closure_##_name* n, bytes s^))(void *~);|", ", _lt% l%", ", _rt%");
    p("static _rettype _name(struct _closure_##_name *~);\n\n", ", _rt%");

    p("#define CLOSURE_DEFINE_%_%(_rettype, _name^~)|", nleft, nright, ", _lt%, _ln%", ", _rt%, _rn%");
    p("static _rettype (**_fill_##_name(heap h, struct _closure_##_name* n, bytes s^))(void *~) {|", ", _lt% l%", ", _rt%");
    p("  if (n != INVALID_ADDRESS) {|");
    p("    n->__apply = _name;|");
    p("    n->__c.name = #_name;|");
    p("    n->__c.h = h;|");
    p("    n->__c.size = s;|");
    for (int i = 0; i < nleft ; i++)  p("  n->_ln% = l%;|", i, i);
    p("  }|");
    p("  return (_rettype (**)(void *~))n;|", ", _rt%");
    p("}|");
    p("static _rettype _name(struct _closure_##_name *__self~)\n\n\n", ", _rt% _rn%");

    p("#define CLOSURE_SIMPLE_DEFINE_%_%(_rettype, _name^~)|", nleft, nright, ", _lt%, _ln%", ", _rt%, _rn%");
    p("typedef _rettype (**_name##_func)(void *~);|", ", _rt%");
    p("static _rettype _name(struct _closure_##_name *__self~)\n\n\n", ", _rt% _rn%");
}

int main(int argc, char **argv)
{
    if (argc < 3) {
        char *p = strrchr(argv[0], '/');
	if (p != NULL)
            *p++ = '\0';
        else
            p = argv[0];
        fprintf(stderr, "Usage: %s lc rc\n", p);
	exit(1);
    }
    int lc = atoi(argv[1]);
    int rc = atoi(argv[2]);
    output = malloc(size = 1024);
    for (nleft = 0; nleft < lc; nleft++)
        for (nright = 0; nright < rc; nright++)
            cblock();
    igr(write(1, output, fill));
}
