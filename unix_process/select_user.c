#include <unix_process_runtime.h>
#include <sys/epoll.h>
#include <string.h>
#include <errno.h>

typedef struct select_bitmaps {
    bitmap r;
    bitmap w;
    bitmap e;
} select_bitmaps;

typedef struct select_notifier {
    struct notifier n;
    vector registrations;
    descriptor nfds;		/* highest fd given plus one */
    select_bitmaps fds;
    select_bitmaps tmp;
} *select_notifier;

static inline void select_bitmaps_init(heap h, select_bitmaps * b)
{
    b->r = allocate_bitmap(h, infinity);
    b->w = allocate_bitmap(h, infinity);
    b->e = allocate_bitmap(h, infinity);
}

static boolean select_register(notifier n, descriptor f, u32 events, thunk a)
{
#ifdef SOCKET_USER_EPOLL_DEBUG
    rprintf("select_register: notifier %p, fd %d, events %P, thunk %p\n", n, f, events, a);
#endif
    select_notifier s = (select_notifier)n;
    registration new = allocate(n->h, sizeof(struct registration));
    new->fd = f;
    new->events = events;
    new->a = a;
    new->next = vector_get(s->registrations, f);
    vector_set(s->registrations, f, new);
    if (f >= s->nfds)
	s->nfds = f + 1;

    if ((events & EPOLLIN))
	bitmap_set(s->fds.r, f, 1);
    if ((events & EPOLLOUT))
	bitmap_set(s->fds.w, f, 1);
    if ((events & EPOLLPRI))
	bitmap_set(s->fds.e, f, 1);

    return true;
}

static void select_reset_fd(notifier n, descriptor f)
{
#ifdef SOCKET_USER_EPOLL_DEBUG
    rprintf("select_reset_fd: fd %d, notifier %p\n", f, n);
#endif
    select_notifier s = (select_notifier)n;
    registration r;
    if (!(r = vector_get(s->registrations, f)))
	return;

    bitmap_set(s->fds.r, f, 0);
    bitmap_set(s->fds.w, f, 0);
    bitmap_set(s->fds.e, f, 0);

    do {
	registration next;
	assert(r->fd == f);
	next = r->next;
	deallocate(n->h, r, sizeof(struct registration));
	r = next;
    } while(r);
    vector_set(s->registrations, f, 0);
}

static void select_spin(notifier n)
{
#ifdef SOCKET_USER_EPOLL_DEBUG
    rprintf("select_spin enter: notifier %p\n", n);
#endif
    select_notifier s = (select_notifier)n;

    while (1) {
	bitmap_copy(s->tmp.r, s->fds.r);
	bitmap_copy(s->tmp.w, s->fds.w);
	bitmap_copy(s->tmp.e, s->fds.e);
	u64 * rp = bitmap_base(s->tmp.r);
	u64 * wp = bitmap_base(s->tmp.w);
	u64 * ep = bitmap_base(s->tmp.e);
#ifdef SOCKET_USER_EPOLL_DEBUG
	rprintf("   calling select with nfds = %d\n", s->nfds);
	rprintf("      r: %P\tw: %P\te: %P\n", *rp, *wp, *ep);
#endif
	int res = select(s->nfds, (fd_set*)rp, (fd_set*)wp, (fd_set*)ep, 0);
#ifdef SOCKET_USER_EPOLL_DEBUG
	rprintf("   returned %d\n", res);
	rprintf("      r: %P\tw: %P\te: %P\n", *rp, *wp, *ep);
#endif
        if (res == -1)
	    halt ("select failed with %s (%d)\n", strerror(errno), errno);
	if (res == 0)
	    continue;
	int words = pad(s->nfds, 64) >> 6;
        for (int i = 0; i < words; i++) {
	    u64 u = *rp | *wp | *ep;

	    bitmap_word_foreach_set(u, bit, fd, (i << 6)) {
		u32 events = 0;
		u64 mask = 1ull << bit;
		if (*rp & mask)
		    events |= EPOLLIN;
		if (*wp & mask)
		    events |= EPOLLOUT;
		if (*wp & mask)
		    events |= EPOLLPRI;
#ifdef SOCKET_USER_EPOLL_DEBUG
		rprintf("   fd %d, events %P:\n", fd, events);
#endif
		registration r = vector_get(s->registrations, fd);
		do {
		    if (r->events & events) {
#ifdef SOCKET_USER_EPOLL_DEBUG
			rprintf("      match events %P, applying thunk %p\n",
				r->events, r->a);
#endif
			apply(r->a);
		    }
		    r = r->next;
		} while (r);
	    }
	    rp++;
	    wp++;
	    ep++;
        }
    }
}

notifier create_select_notifier(heap h)
{
    select_notifier s = allocate(h, sizeof(struct select_notifier));
    s->n.h = h;
    s->n._register = select_register;
    s->n.reset_fd = select_reset_fd;
    s->n.spin = select_spin;
    s->registrations = allocate_vector(h, 10);
    select_bitmaps_init(h, &s->fds);
    select_bitmaps_init(h, &s->tmp);
    s->nfds = 0;
    return (notifier)s;
}
