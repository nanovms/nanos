#include <sys/socket.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define STATE_FIRST 1
#define STATE_HEADER 2
#define STATE_VALUE 3
#define STATE_BODY 4

static char head[] =""
    "<html><title>shower controller</title><body>\n"
    "<a href=\"water\">water</a><br/>"
    "<a href=\"soap\">soap</a><br/>";
static char tail[] =  "</body></html>\n";


typedef int boolean;
#define false 0
#define true 1
typedef int bytes;

typedef struct buffer {
    bytes start;
    bytes end;
    bytes length;
    unsigned char *contents;
} *buffer;

typedef struct parser {
    int state;
    // i dont think we need all these
    buffer header;
    buffer value;
    buffer resp, html;
    buffer first, clen;
    int content_length;
    int out;
} *parser;

static int decimal(buffer b) {
    int res = 0;
    int i;
    for (i = 0 ; i < b->end; i++)
        res = res*10 + (b->contents[i] - '0');
    return res;
}

static boolean compare(buffer a, buffer b)
{
    if (a->end != b->end) return false;
    int i;
    for (i= 0;i<a->end; i++)
        if (a->contents[i] != b->contents[i]) return false;
    return true;
}

static void reset_buffer(buffer b)
{
    b->start = b->end = 0;
}

static inline void buffer_insert(buffer b, char n)
{
    *((unsigned char *)b->contents + b->end++) = n;
}

static inline void buffer_string(buffer b, char *n)
{
    for (char *i = n;*i;i++) buffer_insert(b, *i);
}

buffer allocate_buffer(bytes s)
{
    buffer b = malloc(sizeof(struct buffer));
    b->start = 0;
    b->end = 0;
    b->length = s;
    // two allocations to remove the deallocate ambiguity, otherwise
    // we'd prefer to do it in one
    b->contents = malloc(s);
    return(b);
}

void send_int(buffer b, int v)
{
    char x;
    int z, log = 1;
    for (z = v ; z > 0; z /= 10, log*=10);
    log /= 10;
    if (log == 0) {
        buffer_insert(b, 0);
    } else {
        for (z = v ; (log > 0) && (x = '0' + (z/log) % 10) ; log/=10)
            buffer_insert(b, x);
    }
}

void http_response(buffer d,
                   char *content_type,
                   buffer c)
{
    reset_buffer(d);
    buffer_string(d, "HTTP/1.1 200 OK\r\n");
    buffer_string(d, "Content-Length: ");
    send_int(d, c->end);
    buffer_string(d, "\r\n");
    buffer_string(d, "Content-Type: ");
    buffer_string(d, "content_type");
    buffer_string(d, "\r\n\r\n");
    memcpy(d->contents + d->end, c->contents, c->end);
    d->end += c->end;
}



void http_recv(parser p, buffer b)
{
    int i;
    char key;
    int kp = 0;
    int sp = 0;
    reset_buffer(p->first);
    
    for (i = b->start ; i < b->end; i ++) {
        char x = ((unsigned char *)b->contents)[i];
        
        switch (p->state) {
        case STATE_FIRST:
            // get the url
            buffer_insert(p->first, x);
            if (x == ' ') sp++;

            if (kp) {
                key = x;
                kp = 0;
            }
            if ((x == '/') && (sp == 1)) kp = 1;
            if (x == '\r')  {
                p->state = STATE_HEADER;
                reset_buffer(p->header);
            }
            break;
        case STATE_HEADER:
            switch(x) {
            case ' ':
                p->state = STATE_VALUE;
                reset_buffer(p->value);
                break;
            case '\r':
                p->state = STATE_BODY;
                break;
            default:
                buffer_insert(p->header, x);
            }
            break;
        case STATE_VALUE:
            if (x == '\r')  {
                if (compare(p->header, p->clen)) {
                    p->content_length = decimal(p->header);
                }
                p->state = STATE_HEADER;
                reset_buffer(p->header);
            } else {
                buffer_insert(p->value, x);
            }
            break;
        case STATE_BODY:
            --p->content_length;
        }
        if ((p->state == STATE_BODY) && (p->content_length == 0)) {
            reset_buffer(p->resp);
            reset_buffer(p->html);            
            buffer_string(p->html, head);
            buffer_string(p->html, tail);
            http_response(p->resp, "application/html", p->html);
            write(p->out, p->resp->contents, p->resp->end);
            p->state = STATE_FIRST;
        }
    }
}

parser allocate_parser()
{
    parser p = malloc(sizeof(struct parser));
    p->state = STATE_FIRST;
    p->content_length = 0;
    p->resp = allocate_buffer(1024);
    p->html = allocate_buffer(1024);
    p->first = allocate_buffer(1024);
    p->value = allocate_buffer(1024);
    p->clen = allocate_buffer(1024);
    p->header = allocate_buffer(1024);                    
    return p;
}

void main(int argc, char **argv)
{
    int service, conn;
    struct sockaddr_in where;

    service = socket(AF_INET, SOCK_STREAM, 0);
    memset(&where.sin_addr, 0, sizeof(unsigned int));
    where.sin_family = AF_INET;
    where.sin_port = htons(8800);
    if (setsockopt(service, SOL_SOCKET, SO_REUSEADDR, &(int){ 1 }, sizeof(int)) < 0)
        perror("setsockopt(SO_REUSEADDR) failed");
    
    if (bind(service, (struct sockaddr *)&where, sizeof(struct sockaddr_in))) {
        perror("bind:");
        exit(-1);
    }
    if (listen(service, 5)) {
        perror("listen:");
        exit(-1);
    }

    unsigned int addrlen;
    while (addrlen = sizeof(struct sockaddr_in), (conn = accept(service, (struct sockaddr *)&where, &addrlen))>=0) {
        parser p = allocate_parser();
        buffer b = allocate_buffer(512);
        p->out = conn;
        while ((b->end = read(conn, b->contents, 512)) > 0) {
            http_recv(p, b);
            reset_buffer(b);
        }
    }
}

