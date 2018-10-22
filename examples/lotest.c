/* loopback socket test

   Presently used to test epoll edge detect, oneshot, etc. However
   this may provide a decent boiler plate to test other socket-related
   features.
*/

#include <runtime.h>
#include <socket_user.h>
#include <stdlib.h>
#include <sys/epoll.h>

static boolean debugs = false;

#define lotest_debug(x, ...) if (debugs) { rprintf("%s: " x, __func__,  ##__VA_ARGS__); }

static CLOSURE_4_1(recv_a, void, heap, tuple, notifier, buffer_handler, buffer);
static void recv_a(heap h, tuple t, notifier n, buffer_handler bh, buffer b)
{
    lotest_debug("enter\n");
}

static CLOSURE_4_1(recv_b, void, heap, tuple, notifier, buffer_handler, buffer);
static void recv_b(heap h, tuple t, notifier n, buffer_handler bh, buffer b)
{
    lotest_debug("enter\n");
}

static CLOSURE_3_1(connected, buffer_handler, heap, tuple, notifier, buffer_handler);
static buffer_handler connected(heap h, tuple t, notifier n, buffer_handler out)
{
    lotest_debug("enter\n");
    buffer b = allocate_buffer(h, 16);
    bprintf(b, "test string\n");
    apply(out, b);
    return closure(h, recv_a, h, t, n, out);
}

static CLOSURE_3_1(accepted, buffer_handler, heap, tuple, notifier, buffer_handler);
static buffer_handler accepted(heap h, tuple t, notifier n, buffer_handler out)
{
    lotest_debug("enter\n");
    return closure(h, recv_b, h, t, n, out);
}

static CLOSURE_0_1(connection_error, void, status);
static void connection_error(status s)
{
    msg_err("%v\n", s);
    exit(-1);
}

table parse_arguments(heap h, int argc, char **argv);

void main(int argc, char **argv)
{
    heap h = init_process_runtime();
    tuple t = parse_arguments(h, argc, argv);
    notifier n = create_epoll_notifier(h);

    if (table_find(t, sym(debug)))
	debugs = true;

    /*
      edge:
       - poll on EPOLLIN | EPOLLET, spin, read partial, spin again
         with timeout
	 - fail if EPOLLIN received, pass on timeout
       - complete read to reset trigger, write more data and spin with timeout
         - pass on event received, fail on timeout
       - close

       oneshot:
       - poll on EPOLLIN | EPOLLONESHOT, spin, read complete, write
         more data and spin with timeout
	 - fail on EPOLLIN received, pass on timeout
       - reset with epoll_ctl (need to extend notifier interface to allow re-enable)
       - spin with timeout
         - fail if timeout, pass on EPOLLIN received
    */

    listen_port(h, n, 5309, closure(h, accepted, h, t, n));

    buffer target = wrap_buffer_cstring(h, "127.0.0.1:5309");
    connection(h, n, target, closure(h, connected, h, t, n),
	       closure(h, connection_error));

    /* XXX As Levente noted before, the notifier semantics should be fixed to
       allow quitting from a spin loop. */
    notifier_spin(n);
}

