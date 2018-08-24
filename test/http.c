#include <runtime.h>
#include <http.h>

#define STATE_START_LINE 1
#define STATE_HEADER 2
#define STATE_VALUE 3
#define STATE_BODY 4

typedef struct http_parser {
    heap h;
    vector start_line;
    int state;
    buffer word;
    symbol s;
    tuple header;
    value_handler each;
    u64 content_length;
} *http_parser;

static CLOSURE_1_2(each_header, void, buffer, symbol, value);
static void each_header(buffer dest, symbol n, value v)
{
    if (n != sym(url))
        bprintf(dest, "%v: %v\r\n", n, v);
}

void http_header(buffer dest, tuple t)
{
    // asynch in new world
    table_foreach(t, k , v) each_header(dest, k, v);
    bprintf(dest, "\r\n");    
}

void http_request(buffer_handler bh, tuple headers)
{
    buffer b = allocate_buffer(transient, 10);
    buffer url = table_find(headers, sym(url));
    bprintf(b, "GET %b HTTP/1.1\r\n", url);
    http_header(b, headers);
    apply(bh, b);
}

// xxx - other http streaming interfaces are less straightforward
void send_http_response(buffer_handler out,
                        tuple t,
                        buffer c)
{

    // status from t
    buffer d = allocate_buffer(transient, 1000);
    bprintf (d, "HTTP/1.1 200 OK\r\n");
    table_foreach(t, k, v) each_header(d, k, v);
    each_header(d, sym(Content-Length), aprintf(transient, "%d", c->end));
    bprintf(d, "\r\n");
    apply(out, d);
    apply(out, c);
    
}

static void reset_parser(http_parser p)
{
    p->state = STATE_START_LINE;
    p->header = allocate_tuple();
    p->word = allocate_buffer(p->h, 10);
    p->start_line = allocate_vector(p->h, 3);
    p->content_length = 0;
}

// we're going to patch the connection together by looking at the
// leftover bits in buffer...defer until we need to actually
// switch protocols
CLOSURE_1_1(http_recv, void, http_parser, buffer);
void http_recv(http_parser p, buffer b)
{
    int i;

    for (i = b->start ; i < b->end; i ++) {
        char x = ((unsigned char *)b->contents)[i];
        switch (p->state) {
        case STATE_START_LINE:
            switch (x){
            case '\r':
                p->state = STATE_HEADER;
                vector_push(p->start_line, p->word);
                p->word = allocate_buffer(p->h, 0);                
                break;                
            case ' ':
                vector_push(p->start_line, p->word);
                p->word = allocate_buffer(p->h, 0);
                break;
            default:
                push_u8(p->word, x);
            }
            break;
            
        case STATE_HEADER:
            switch(x) {
            case ' ':
                p->state = STATE_VALUE;
                p->s = intern(p->word);
                buffer_clear(p->word);
                break;
            case '\r':
                p->state = STATE_BODY;
                break;
            default:
                push_u8(p->word, x);
            }
            break;
            
        case STATE_VALUE:
            if (x == '\r')  {
                if (p->s == sym(Content-Length))  
                    parse_int(p->word, 10, &p->content_length);
                table_set(p->header, p->s, p->word);
                p->word = allocate_buffer(p->h, 0);                
                p->state = STATE_HEADER;
            } else {
                push_u8(p->word, x);
            }
            break;
            
        case STATE_BODY:
            push_u8(p->word, x);            
            --p->content_length;
        }
        
        if ((p->state == STATE_BODY) && (p->content_length == 0)) {
            table_set(p->header, sym(content), p->word);
            apply(p->each, p->header);
            reset_parser(p);
        }
    }
}


buffer_handler allocate_http_parser(heap h, value_handler each)
{
    http_parser p = allocate(h, sizeof(struct http_parser));
    p->h = h;
    p->each = each;
    reset_parser(p);
    return closure(h, http_recv, p);
}



