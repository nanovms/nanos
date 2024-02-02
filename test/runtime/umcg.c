#define _GNU_SOURCE
#include <errno.h>
#include <linux/futex.h>
#include <pthread.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <runtime.h>

#include "../test_utils.h"

#define __NR_umcg_ctl  450

#define UMCG_WORKER_ID_SHIFT    5
#define UMCG_WORKER_EVENT_MASK  ((1 << UMCG_WORKER_ID_SHIFT) - 1)

#define UMCG_WAIT_FLAG_INTERRUPTED  (1ull)

enum umcg_cmd {
    UMCG_REGISTER_WORKER = 1,
    UMCG_REGISTER_SERVER,
    UMCG_UNREGISTER,
    UMCG_WAKE,
    UMCG_WAIT,
    UMCG_CTX_SWITCH,
};

enum umcg_event_type {
    UMCG_WE_BLOCK = 1,
    UMCG_WE_WAKE,
    UMCG_WE_WAIT,
    UMCG_WE_EXIT,
    UMCG_WE_TIMEOUT,
    UMCG_WE_PREEMPT,
};

static int umcg_test_duration = 10; /* expressed in seconds */

static inline int sys_umcg_ctl(u64 flags, u64 cmd, pid_t next_tid, u64 abs_timeout,
                               u64 *events, int event_sz)
{
    return syscall(__NR_umcg_ctl, flags, cmd, next_tid, abs_timeout, events, event_sz);
}

struct umcg_test_worker {
    struct list node;
    pid_t tid;
};

struct umcg_test_server {
    struct list node;
    pid_t cur;
    int workers;
};

struct condvar_test_syncdata {
    volatile int worker_task;
    pthread_mutex_t *mutex;
    pthread_cond_t *cond;
};

static int umcg_test_worker_add(struct umcg_test_server *server, pid_t foo)
{
    struct umcg_test_worker *task = malloc(sizeof(*task));

    if (task == NULL)
        return -1;
    task->tid = foo;
    list_push_back(&server->node, &task->node);
    return 0;
}

static pid_t umcg_test_worker_pick(struct umcg_test_server *server)
{
    struct umcg_test_worker *first;
    pid_t tid;

    if (list_empty(&server->node))
        return 0;
    first = struct_from_list(list_begin(&server->node), struct umcg_test_worker *, node);
    list_delete(&first->node);
    tid = first->tid;
    free(first);
    return tid;
}

static int umcg_wait_retry(u64 worker_id, u64 *events, u64 event_sz)
{
    u64 flags = 0;
    int ret;

    do  {
        ret = sys_umcg_ctl(flags, UMCG_WAIT, worker_id >> UMCG_WORKER_ID_SHIFT, 0,
                           events, event_sz);
        flags = UMCG_WAIT_FLAG_INTERRUPTED;
    } while (ret && (errno == EINTR));
    return ret;
}

static void umcg_yield(void)
{
    test_assert(umcg_wait_retry(0, NULL, 0) == 0);
}

static u64 umcg_wait_any_worker(enum umcg_event_type event)
{
    const int event_sz = 2;
    u64 events[event_sz];

    test_assert(umcg_wait_retry(0, events, event_sz) == 0);
    test_assert(((events[0] & UMCG_WORKER_EVENT_MASK) == event) && (events[1] == 0));
    return events[0] & ~UMCG_WORKER_EVENT_MASK;
}

static void umcg_assert_worker_event(u64 event, u64 worker_id, enum umcg_event_type type)
{
    test_assert((event & UMCG_WORKER_EVENT_MASK) == type);
    test_assert((event & ~UMCG_WORKER_EVENT_MASK) == worker_id);
}

static void umcg_ctxsw_assert_worker_event(u64 worker_id, enum umcg_event_type event)
{
    const int event_sz = 2;
    u64 events[event_sz];

    test_assert(sys_umcg_ctl(0, UMCG_CTX_SWITCH, worker_id >> UMCG_WORKER_ID_SHIFT, 0,
                             events, event_sz) == 0);
    umcg_assert_worker_event(events[0], worker_id, event);
    test_assert(events[1] == 0);
}

static volatile boolean done = false;

static void umcg_test_check_done(struct timespec *start)
{
    struct timespec now;

    clock_gettime(CLOCK_REALTIME, &now);
    if (now.tv_sec < start->tv_sec + umcg_test_duration)
        return;
    if ((now.tv_nsec >= start->tv_nsec) || (now.tv_sec > start->tv_sec + umcg_test_duration))
        done = true;
}

/* always running worker */
static void *umcg_demo_worker_a(void *arg)
{
    struct umcg_test_server *server = arg;
    pid_t tid;
    unsigned long i = 0;
    int ret;

    tid = syscall(SYS_gettid);
    printf("A == %d\n", tid);
    ret = sys_umcg_ctl(0, UMCG_REGISTER_WORKER, 0, ((u64)tid) << UMCG_WORKER_ID_SHIFT, NULL, 0);
    if (ret)
        test_perror("umcg_ctl(A)");
    __atomic_add_fetch(&server->workers, 1, __ATOMIC_RELAXED);
    while (!done) {
        int x = i++;

        if (!(x % 1000000)) {
            putchar('.');
            fflush(stdout);
        }
        if (!(x % 10000000))
            umcg_yield();
    }
    printf("A == done\n");
    __atomic_add_fetch(&server->workers, -1, __ATOMIC_RELAXED);
    ret = sys_umcg_ctl(0, UMCG_UNREGISTER, 0, 0, NULL, 0);
    if (ret)
        test_perror("umcg_ctl(~A)");
    return NULL;
}

static void *umcg_demo_worker_b(void *arg)
{
    struct umcg_test_server *server = arg;
    pid_t tid;
    int ret;

    tid = syscall(SYS_gettid);
    printf("B == %d\n", tid);
    ret = sys_umcg_ctl(0, UMCG_REGISTER_WORKER, 0, ((u64)tid) << UMCG_WORKER_ID_SHIFT, NULL, 0);
    if (ret)
        test_perror("umcg_ctl(B)");
    __atomic_add_fetch(&server->workers, 1, __ATOMIC_RELAXED);
    while (!done) {
        printf("B\n");
        sleep(1);
    }
    printf("B == done\n");
    __atomic_add_fetch(&server->workers, -1, __ATOMIC_RELAXED);
    ret = sys_umcg_ctl(0, UMCG_UNREGISTER, 0, 0, NULL, 0);
    if (ret)
        test_perror("umcg_ctl(~B)");
    return NULL;
}

static void *umcg_demo_worker_c(void *arg)
{
    struct umcg_test_server *server = arg;
    pid_t tid;
    int ret;

    tid = syscall(SYS_gettid);
    printf("C == %d\n", tid);
    ret = sys_umcg_ctl(0, UMCG_REGISTER_WORKER, 0, ((u64)tid) << UMCG_WORKER_ID_SHIFT, NULL, 0);
    if (ret)
        test_perror("umcg_ctl(C)");
    __atomic_add_fetch(&server->workers, 1, __ATOMIC_RELAXED);
    while (!done) {
        printf("C\n");
        sleep(2);
    }
    printf("C == done\n");
    __atomic_add_fetch(&server->workers, -1, __ATOMIC_RELAXED);
    ret = sys_umcg_ctl(0, UMCG_UNREGISTER, 0, 0, NULL, 0);
    if (ret)
        perror("umcg_ctl(~C)");
    return NULL;
}

static int umcg_demo(void)
{
    struct umcg_test_server server = { };
    const int worker_count = 3;
    pthread_t worker[worker_count];
    const int event_sz = worker_count * 2;
    u64 events[event_sz];
    struct timespec start;
    int ret;

    list_init(&server.node);
    ret = sys_umcg_ctl(0, UMCG_REGISTER_SERVER, 0, 0, NULL, 0);
    if (ret)
        test_perror("umcg_ctl(server)");
    pthread_create(&worker[0], NULL, umcg_demo_worker_a, &server);
    pthread_create(&worker[1], NULL, umcg_demo_worker_b, &server);
    pthread_create(&worker[2], NULL, umcg_demo_worker_c, &server);
    clock_gettime(CLOCK_REALTIME, &start);
    while (!(done && !__atomic_load_n(&server.workers, __ATOMIC_RELAXED))) {
        server.cur = umcg_test_worker_pick(&server);
        if (!server.cur) {
            putchar('x');
            ret = umcg_wait_retry(0, events, event_sz);
        } else {
            printf("pick: %d\n", server.cur);
            ret = sys_umcg_ctl(0, UMCG_CTX_SWITCH, server.cur, 0, events, event_sz);
        }
        if (ret)
            test_perror("server loop");
        for (int i = 0; i < event_sz; i++) {
            u64 event = events[i];

            if (event == 0)
                break;
            switch (event & UMCG_WORKER_EVENT_MASK) {
            case UMCG_WE_WAKE:
            case UMCG_WE_WAIT:
                if (umcg_test_worker_add(&server, event >> UMCG_WORKER_ID_SHIFT) < 0)
                    test_error("cannot add runnable worker %lld", event >> UMCG_WORKER_ID_SHIFT);
                break;
            default:
                printf("worker tid %lld, event %lld\n", event >> UMCG_WORKER_ID_SHIFT,
                       event & UMCG_WORKER_EVENT_MASK);
            }
        }
        umcg_test_check_done(&start);
    }
    pthread_join(worker[0], NULL);
    pthread_join(worker[1], NULL);
    pthread_join(worker[2], NULL);
    return 0;
}

static void *umcg_perftest_worker(void *arg)
{
    test_assert(sys_umcg_ctl(0, UMCG_REGISTER_WORKER, 0,
                             syscall(SYS_gettid) << UMCG_WORKER_ID_SHIFT, NULL, 0) == 0);
    while (!done)
        test_assert(sys_umcg_ctl(0, UMCG_WAIT, 0, 0, NULL, 0) == 0);
    test_assert(sys_umcg_ctl(0, UMCG_UNREGISTER, 0, 0, NULL, 0) == 0);
    return NULL;
}

static int umcg_perftest(void)
{
    pthread_t worker;
    u64 worker_id;
    struct timespec start;
    long long cycles;

    printf("UMCG performance test duration: %d seconds...\n", umcg_test_duration);
    test_assert(sys_umcg_ctl(0, UMCG_REGISTER_SERVER, 0, 0, NULL, 0) == 0);
    pthread_create(&worker, NULL, umcg_perftest_worker, NULL);
    worker_id = umcg_wait_any_worker(UMCG_WE_WAKE);
    clock_gettime(CLOCK_REALTIME, &start);
    for (cycles = 0; !done; cycles++) {
        umcg_ctxsw_assert_worker_event(worker_id, UMCG_WE_WAIT);
        umcg_test_check_done(&start);
    }
    printf("Results: %lld cycles (%g cycles/sec)\n", cycles, cycles/ (double)umcg_test_duration);
    umcg_ctxsw_assert_worker_event(worker_id, UMCG_WE_EXIT);
    pthread_join(worker, NULL);
    return 0;
}

static void *futex_perftest_worker(void *arg)
{
    int *word_ptr = arg;

    while (!done) {
        syscall(SYS_futex, word_ptr, FUTEX_WAIT | FUTEX_PRIVATE_FLAG, 0, 0, NULL, 0);
        *word_ptr = 0;
        syscall(SYS_futex, word_ptr, FUTEX_WAKE | FUTEX_PRIVATE_FLAG, 1, 0, NULL, 0);
    }
    return NULL;
}

static int futex_perftest(void)
{
    int futex_word;
    pthread_t worker;
    struct timespec start;
    long long cycles;

    printf("Futex performance test duration: %d seconds...\n", umcg_test_duration);
    pthread_create(&worker, NULL, futex_perftest_worker, &futex_word);
    clock_gettime(CLOCK_REALTIME, &start);
    for (cycles = 0; !done; cycles++) {
        futex_word = 1;
        syscall(SYS_futex, &futex_word, FUTEX_WAKE | FUTEX_PRIVATE_FLAG, 1, 0, NULL, 0);
        syscall(SYS_futex, &futex_word, FUTEX_WAIT | FUTEX_PRIVATE_FLAG, 1, 0, NULL, 0);
        umcg_test_check_done(&start);
    }
    printf("Results: %lld cycles (%g cycles/sec)\n", cycles, cycles/ (double)umcg_test_duration);
    futex_word = 1;
    syscall(SYS_futex, &futex_word, FUTEX_WAKE | FUTEX_PRIVATE_FLAG, 1, 0, NULL, 0);
    pthread_join(worker, NULL);
    return 0;
}

static void *condvar_perftest_worker(void *arg)
{
    struct condvar_test_syncdata *syncdata = arg;
    pthread_cond_t *cond = syncdata->cond;
    pthread_mutex_t *mutex = syncdata->mutex;

    while (!done) {
        pthread_mutex_lock(mutex);
        while (!syncdata->worker_task)
            test_assert(pthread_cond_wait(cond, mutex) == 0);
        syncdata->worker_task = 0;
        pthread_mutex_unlock(mutex);
        test_assert(pthread_cond_signal(cond) == 0);
    }
    return NULL;
}

static int condvar_perftest(void)
{
    pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
    pthread_cond_t cond = PTHREAD_COND_INITIALIZER;
    struct condvar_test_syncdata syncdata = {
        .worker_task = 0,
        .mutex = &mutex,
        .cond = &cond,
    };
    pthread_t worker;
    struct timespec start;
    long long cycles;

    printf("Condition variable performance test duration: %d seconds...\n", umcg_test_duration);
    pthread_create(&worker, NULL, condvar_perftest_worker, &syncdata);
    clock_gettime(CLOCK_REALTIME, &start);
    for (cycles = 0; !done; cycles++) {
        pthread_mutex_lock(&mutex);
        while (syncdata.worker_task)
            test_assert(pthread_cond_wait(&cond, &mutex) == 0);
        syncdata.worker_task = 1;
        pthread_mutex_unlock(&mutex);
        test_assert(pthread_cond_signal(&cond) == 0);
        umcg_test_check_done(&start);
    }
    printf("Results: %lld cycles (%g cycles/sec)\n", cycles, cycles/ (double)umcg_test_duration);
    syncdata.worker_task = 1;
    test_assert(pthread_cond_signal(&cond) == 0);
    pthread_join(worker, NULL);
    return 0;
}

static void *umcg_worker_dummy(void *arg)
{
    test_assert(sys_umcg_ctl(0, UMCG_REGISTER_WORKER, 0,
                             syscall(SYS_gettid) << UMCG_WORKER_ID_SHIFT, NULL, 0) == 0);
    test_assert(sys_umcg_ctl(0, UMCG_UNREGISTER, 0, 0, NULL, 0) == 0);
    return NULL;
}

static void *umcg_worker_blocking(void *arg)
{
    test_assert(sys_umcg_ctl(0, UMCG_REGISTER_WORKER, 0,
                             syscall(SYS_gettid) << UMCG_WORKER_ID_SHIFT, NULL, 0) == 0);
    usleep(16 * 1024);
    test_assert(sys_umcg_ctl(0, UMCG_UNREGISTER, 0, 0, NULL, 0) == 0);
    return NULL;
}

static void *umcg_worker_wait_timeout(void *arg)
{
    struct timespec ts;

    test_assert(sys_umcg_ctl(0, UMCG_REGISTER_WORKER, 0,
                             syscall(SYS_gettid) << UMCG_WORKER_ID_SHIFT, NULL, 0) == 0);
    clock_gettime(CLOCK_REALTIME, &ts);
    test_assert(sys_umcg_ctl(0, UMCG_WAIT, 0, ts.tv_sec * BILLION + ts.tv_nsec, NULL, 0) == -1);
    test_assert(errno == ETIMEDOUT);
    test_assert(sys_umcg_ctl(0, UMCG_UNREGISTER, 0, 0, NULL, 0) == 0);
    return NULL;
}

static void *umcg_worker_ctxsw_timeout(void *arg)
{
    u64 worker_id = *(u64 *)arg;
    struct timespec ts;
    int ret;

    test_assert(sys_umcg_ctl(0, UMCG_REGISTER_WORKER, 0,
                             syscall(SYS_gettid) << UMCG_WORKER_ID_SHIFT, NULL, 0) == 0);
    clock_gettime(CLOCK_REALTIME, &ts);
    ret = sys_umcg_ctl(0, UMCG_CTX_SWITCH, worker_id >> UMCG_WORKER_ID_SHIFT,
                       ts.tv_sec * BILLION + ts.tv_nsec, NULL, 0);
    test_assert((ret == 0) || ((ret < 0) && (errno == ETIMEDOUT)));
    test_assert(sys_umcg_ctl(0, UMCG_UNREGISTER, 0, 0, NULL, 0) == 0);
    return NULL;
}

static void *umcg_worker_preempted(void *arg)
{
    volatile int *worker_exit = arg;

    test_assert(sys_umcg_ctl(0, UMCG_REGISTER_WORKER, 0,
                             syscall(SYS_gettid) << UMCG_WORKER_ID_SHIFT, NULL, 0) == 0);
    while (!*worker_exit);
    test_assert(sys_umcg_ctl(0, UMCG_UNREGISTER, 0, 0, NULL, 0) == 0);
    return NULL;
}

static void *umcg_worker_exiting(void *arg)
{
    u64 worker_id = syscall(SYS_gettid) << UMCG_WORKER_ID_SHIFT;
    const int event_sz = 2;
    u64 events[event_sz];

    int ret;

    test_assert(sys_umcg_ctl(0, UMCG_REGISTER_WORKER, 0, worker_id, NULL, 0) == 0);

    /* try to register an already registered worker */
    ret = sys_umcg_ctl(0, UMCG_REGISTER_WORKER, 0, worker_id, NULL, 0);
    test_assert((ret < 0) && (errno == EINVAL));

    /* try to context-switch to itself */
    ret = sys_umcg_ctl(0, UMCG_CTX_SWITCH, worker_id >> UMCG_WORKER_ID_SHIFT, 0, NULL, 0);
    test_assert((ret == -1) && (errno == EINVAL));

    ret = sys_umcg_ctl(0, UMCG_WAIT, worker_id, 0, NULL, 0);
    test_assert((ret < 0) && (errno == EINVAL));    /* non-zero next_tid */

    ret = sys_umcg_ctl(0, UMCG_WAIT, 0, 0, events, 0);
    test_assert((ret < 0) && (errno == EINVAL));    /* non-NULL events */

    ret = sys_umcg_ctl(0, UMCG_WAIT, 0, 0, NULL, event_sz);
    test_assert((ret == -1) && (errno == EINVAL));  /* non-zero event size */

    return NULL;    /* exit thread without unregistering worker */
}

static void umcg_test_basic(void)
{
    pthread_t workers[2];
    u64 worker_ids[2];
    int ret;
    const int event_sz = 2;
    u64 events[event_sz];
    int worker_exit;

    test_assert(sys_umcg_ctl(0, UMCG_REGISTER_SERVER, 0, 0, NULL, 0) == 0);

    pthread_create(&workers[0], NULL, umcg_worker_blocking, NULL);
    worker_ids[0] = umcg_wait_any_worker(UMCG_WE_WAKE);
    umcg_ctxsw_assert_worker_event(worker_ids[0], UMCG_WE_BLOCK);
    test_assert(umcg_wait_retry(worker_ids[0], NULL, 0) == 0);  /* wait for worker to unblock */
    test_assert(umcg_wait_any_worker(UMCG_WE_WAKE) == worker_ids[0]);
    umcg_ctxsw_assert_worker_event(worker_ids[0], UMCG_WE_EXIT);
    pthread_join(workers[0], NULL);

    pthread_create(&workers[0], NULL, umcg_worker_wait_timeout, NULL);
    worker_ids[0] = umcg_wait_any_worker(UMCG_WE_WAKE);
    umcg_ctxsw_assert_worker_event(worker_ids[0], UMCG_WE_WAIT);
    test_assert(umcg_wait_any_worker(UMCG_WE_TIMEOUT) == worker_ids[0]);
    umcg_ctxsw_assert_worker_event(worker_ids[0], UMCG_WE_EXIT);
    pthread_join(workers[0], NULL);

    pthread_create(&workers[0], NULL, umcg_worker_dummy, NULL);
    worker_ids[0] = umcg_wait_any_worker(UMCG_WE_WAKE);
    pthread_create(&workers[1], NULL, umcg_worker_ctxsw_timeout, &worker_ids[0]);
    worker_ids[1] = umcg_wait_any_worker(UMCG_WE_WAKE);
    /* run second worker, which will context-switch to first worker, which will exit */
    ret = sys_umcg_ctl(0, UMCG_CTX_SWITCH, worker_ids[1] >> UMCG_WORKER_ID_SHIFT, 0,
                       events, event_sz);
    test_assert(ret == 0);
    umcg_assert_worker_event(events[0], worker_ids[0], UMCG_WE_EXIT);
    test_assert(events[1] == 0);
    /* retrieve events from second worker */
    test_assert(umcg_wait_retry(0, events, event_sz) == 0);
    umcg_assert_worker_event(events[0], worker_ids[1], UMCG_WE_WAIT);
    if (events[1])
        umcg_assert_worker_event(events[1], worker_ids[1], UMCG_WE_TIMEOUT);
    umcg_ctxsw_assert_worker_event(worker_ids[1], UMCG_WE_EXIT);
    pthread_join(workers[0], NULL);
    pthread_join(workers[1], NULL);

    worker_exit = 0;
    pthread_create(&workers[0], NULL, umcg_worker_preempted, &worker_exit);
    worker_ids[0] = umcg_wait_any_worker(UMCG_WE_WAKE);
    umcg_ctxsw_assert_worker_event(worker_ids[0], UMCG_WE_PREEMPT);
    worker_exit = 1;
    umcg_ctxsw_assert_worker_event(worker_ids[0], UMCG_WE_EXIT);
    pthread_join(workers[0], NULL);

    pthread_create(&workers[0], NULL, umcg_worker_exiting, NULL);
    worker_ids[0] = umcg_wait_any_worker(UMCG_WE_WAKE);
    umcg_ctxsw_assert_worker_event(worker_ids[0], UMCG_WE_EXIT);
    pthread_join(workers[0], NULL);

    test_assert(sys_umcg_ctl(0, UMCG_UNREGISTER, 0, 0, NULL, 0) == 0);
}

static void *umcg_server_dummy(void *arg)
{
    const int event_sz = 2;
    u64 events[event_sz];

    test_assert(sys_umcg_ctl(0, UMCG_REGISTER_SERVER, 0, 0, NULL, 0) == 0);

    /* wait for non-existing workers, until woken up by the main thread */
    test_assert(umcg_wait_retry(0, events, event_sz) == 0);
    test_assert((events[0] == 0));

    test_assert(sys_umcg_ctl(0, UMCG_UNREGISTER, 0, 0, NULL, 0) == 0);
    return NULL;
}

static void umcg_test_server2server(void)
{
    pthread_t server;
    int ret;

    test_assert(sys_umcg_ctl(0, UMCG_REGISTER_SERVER, 0, 0, NULL, 0) == 0);

    pthread_create(&server, NULL, umcg_server_dummy, NULL);
    do {    /* wake up the idle server that is waiting for non-existing workers */
        ret = sys_umcg_ctl(0, UMCG_WAKE, 0, 0, NULL, 0);
        if (ret)
            test_assert((ret < 0) && (errno == EAGAIN));
    } while (ret);
    pthread_join(server, NULL);

    test_assert(sys_umcg_ctl(0, UMCG_UNREGISTER, 0, 0, NULL, 0) == 0);
}

static void umcg_test_errors(void)
{
    struct timespec ts;
    pthread_t worker;
    u64 worker_id;
    const int event_sz = 2;
    u64 events[event_sz];
    int ret;

    ret = sys_umcg_ctl(0, UMCG_REGISTER_WORKER, 0, UMCG_WORKER_EVENT_MASK, NULL, 0);
    test_assert((ret < 0) && (errno == EINVAL));    /* invalid worker id */

    test_assert(sys_umcg_ctl(0, UMCG_REGISTER_SERVER, 0, 0, NULL, 0) == 0);

    /* try to context-switch to itself */
    ret = sys_umcg_ctl(0, UMCG_CTX_SWITCH, syscall(SYS_gettid), 0, events, event_sz);
    test_assert((ret == -1) && (errno == EINVAL));

    ret = sys_umcg_ctl(0, UMCG_WAIT, 0, 0, events, 1);
    test_assert((ret == -1) && (errno == EINVAL));  /* there must be room for 2 events */

    clock_gettime(CLOCK_REALTIME, &ts);
    ret = sys_umcg_ctl(0, UMCG_WAIT, 0, ts.tv_sec * BILLION + ts.tv_nsec, events, event_sz);
    test_assert((ret == -1) && (errno == ETIMEDOUT));

    ret = sys_umcg_ctl(0, UMCG_WAIT, 0, 1, events, event_sz); /* poll without blocking */
    test_assert((ret == -1) && (errno == ETIMEDOUT));

    pthread_create(&worker, NULL, umcg_worker_dummy, NULL);
    worker_id = umcg_wait_any_worker(UMCG_WE_WAKE);

    ret = sys_umcg_ctl(0, UMCG_WAIT, worker_id >> UMCG_WORKER_ID_SHIFT, 0, events, 0);
    test_assert((ret == -1) && (errno == EINVAL));  /* non-NULL events */

    ret = sys_umcg_ctl(0, UMCG_WAIT, worker_id >> UMCG_WORKER_ID_SHIFT, 0, NULL, event_sz);
    test_assert((ret == -1) && (errno == EINVAL));  /* non-zero event size */

    ret = sys_umcg_ctl(0, UMCG_CTX_SWITCH, worker_id >> UMCG_WORKER_ID_SHIFT, 1, events, event_sz);
    test_assert((ret == -1) && (errno == EINVAL));  /* non-zero timeout */

    ret = sys_umcg_ctl(0, UMCG_CTX_SWITCH, worker_id >> UMCG_WORKER_ID_SHIFT, 0, events, 0);
    test_assert((ret == -1) && (errno == EINVAL));  /* zero event size */

    ret = sys_umcg_ctl(0, UMCG_CTX_SWITCH, worker_id >> UMCG_WORKER_ID_SHIFT, 0, FAULT_ADDR, 1);
    test_assert((ret == -1) && (errno == EFAULT));
    pthread_join(worker, NULL);

    /* try to context-switch to a non-existing thread */
    ret = sys_umcg_ctl(0, UMCG_CTX_SWITCH, worker_id >> UMCG_WORKER_ID_SHIFT, 0, events, event_sz);
    test_assert((ret == -1) && (errno == ESRCH));

    /* try to wake up an idle server when there aren't any */
    ret = sys_umcg_ctl(0, UMCG_WAKE, 0, 0, NULL, 0);
    test_assert((ret == -1) && (errno == EAGAIN));

    test_assert(sys_umcg_ctl(0, UMCG_UNREGISTER, 0, 0, NULL, 0) == 0);
}

static void umcg_usage(const char *prog)
{
    printf("Usage: %s [-dufc] [-t <duration>]\n"
           "Options:\n"
           " -d: demo mode\n"
           " -u: UMCG performance test\n"
           " -f: futex performance test\n"
           " -c: condition variable performance test\n"
           " -t <duration>: (demo mode and performance tests) duration in seconds (default: 10)\n"
           , prog);
    exit(EXIT_FAILURE);
}

int main(int argc, char **argv)
{
    int opt;
    enum {
        mode_test,
        mode_demo,
        mode_umcg_perf,
        mode_condvar_perf,
        mode_futex_perf,
    } mode = mode_test;

    while ((opt = getopt(argc, argv, "dufct:")) != EOF) {
        switch (opt) {
        case 'd':
            mode = mode_demo;
            break;
        case 'u':
            mode = mode_umcg_perf;
            break;
        case 'f':
            mode = mode_futex_perf;
            break;
        case 'c':
            mode = mode_condvar_perf;
            break;
        case 't':
            umcg_test_duration = atoi(optarg);
            if (umcg_test_duration <= 0) {
                printf("Invalid duration value '%s'\n", optarg);
                umcg_usage(argv[0]);
            }
            break;
        default:
            umcg_usage(argv[0]);
        }
    }
    switch (mode) {
    case mode_test:
        umcg_test_basic();
        umcg_test_server2server();
        umcg_test_errors();
        printf("UMCG tests OK\n");
        break;
    case mode_demo:
        return umcg_demo();
    case mode_umcg_perf:
        return umcg_perftest();
    case mode_futex_perf:
        return futex_perftest();
    case mode_condvar_perf:
        return condvar_perftest();
    }
    return 0;
}
