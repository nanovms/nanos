#include <runtime.h>

struct timer {
    thunk t;
    time  w;
    time  interval; 
    boolean   disable;
};

// should pass a timer around
static pqueue timers;
static heap theap;

static boolean timer_less_than(void *za, void *zb)
{
    timer a = za;
    timer b = zb;    
    return(a->w < b->w);
}

void remove_timer(timer t)
{
    t->disable = true;
}

timer register_timer(time interval, thunk n)
{
    timer t=(timer)allocate(theap, sizeof(struct timer));

    t->t= n;
    t->interval = 0;
    t->disable = 0;
    t->w = now() + interval;
    pqueue_insert(timers, t);
    return(t);
}

timer register_periodic_timer(time interval, thunk n)
{
    timer t=(timer)allocate(theap, sizeof(struct timer));

    t->t = n;
    t->disable = 0;
    t->interval = interval;    
    t->w = now(theap);
    pqueue_insert(timers, t);
    return(t);
}

time timer_check()
{
    time here;
    timer current = 0;
    // thread safety, predication?
    while ((current = pqueue_peek(timers)) &&
           (here = now(), current->w < here)) {
        if (!current->disable) {
            pqueue_pop(timers);
            apply(current->t);
            if (current->interval) {
                current->w += current->interval;
                pqueue_insert(timers, current); 
            }
        }
    }
    if (current) return(current->w - here);
    return(0);
}


time parse_time(string b)
{
    character c;
    u64 s = 0, frac = 0, fracnorm = 0;

    foreach_character (c, b) {
        if (c == '.')  {
            fracnorm = 1;
        } else {
            if (fracnorm) {
                frac = frac*10 + digit_of(c);
                fracnorm *= 10;
            } else s = s *10 + digit_of(c);
        }
    }
    time result = s << 32;

    if (fracnorm) result |= (frac<<32)/fracnorm;
    return(result);
}

void print_time(string b, time t)
{
    u64 s= t>>32;
    u64 f= t&MASK(32);

    bprintf(b, "%u", s);
    if (f) {
        int count=0;

        bprintf(b,".");

        /* should round or something */
        while ((f *= 10) && (count++ < 6)) {
            u32 d = (f>>32);
            bprintf (b, "%d", d);
            f -= ((u64)d)<<32;
        }
    }
}

void initialize_timers(kernel_heaps kh)
{
    heap h = heap_general(kh);
    timers = allocate_pqueue(h, timer_less_than);
    theap = h;
}
