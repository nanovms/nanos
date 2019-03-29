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
    for (char *i = fmt; *i ; i ++) {
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
                for (int i = 0 ; i< count; i++)  {
                    pi(subformat, i, i);
                    twiggy = 1;
                }
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
    p("#define CLOSURE_%_%(_name, _rettype^~)|", nleft, nright, ", _l%", ", _r%");
    p("_rettype _name(^~);|", "@_l%", "@_r%");

    p("struct _closure_##_name{|");
    p("  _rettype (*_apply)(void *~);|", ", _r%");
    p("  char *name;|");
    for (int i = 0; i < nleft ; i++)  p("  _l% l%;|", i, i);
    p("};|");

    p("static _rettype _apply_##_name(void *z~){|", ", _r% r%");
    if (nleft)
        p("  struct _closure_##_name *n = z; |");
    p("  return _name(^~);|", "@n->l%", "@r%");
    p("}|");

    p("static _rettype (**_fill_##_name(struct _closure_##_name* n, heap h^))(void *~){|", ", _l% l%", ", _r%");
    p("  n->_apply = _apply_##_name;|");
    p("  n->name = #_name;|");
    for (int i = 0; i < nleft ; i++)  p("  n->l% = l%;|", i, i);
    p("  return (_rettype (**)(void *~))n;|", ", _r%");
    p("}\n\n");
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
