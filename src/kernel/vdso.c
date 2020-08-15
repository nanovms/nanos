/* VDSO syscall implementations
 *
 * Unless there's a BUG somewhere, or Linux implements some new syscalls here,
 * there shouldn't be any reason to modify this
 */

#include <unix_internal.h>

static sysreturn
fallback_clock_gettime(clockid_t clk_id, struct timespec * tp)
{
    return do_syscall(SYS_clock_gettime, clk_id, tp);
}

static sysreturn
fallback_gettimeofday(struct timeval * tv, void * tz)
{
    return do_syscall(SYS_gettimeofday, tv, tz);
}

static sysreturn
fallback_time(time_t * t)
{
    return do_syscall(SYS_time, t, 0);
}

static sysreturn
do_vdso_clock_gettime(clockid_t clk_id, struct timespec * tp)
{
    timestamp ts = vdso_now(clk_id);
    if (ts == VDSO_NO_NOW)
        return fallback_clock_gettime(clk_id, tp);

    timespec_from_time(tp, ts);
    return 0;
}

static sysreturn
do_vdso_gettimeofday(struct timeval * tv, void * tz)
{
    timestamp ts = vdso_now(CLOCK_ID_REALTIME);
    if (ts == VDSO_NO_NOW)
        return fallback_gettimeofday(tv, tz);

    timeval_from_time(tv, ts);
    return 0;
}

static sysreturn
do_vdso_getcpu(unsigned * cpu, unsigned * node, void * tcache)
{
    if (cpu)
        *cpu = 0;
    if (node)
        *node = 0;
    return 0;
}

static sysreturn
do_vdso_time(time_t * t)
{
    time_t ret;
    timestamp ts = vdso_now(CLOCK_ID_REALTIME);
    if (ts == VDSO_NO_NOW)
        return fallback_time(t);

    ret = time_t_from_time(ts);
    if (t)
        *t = ret;
    return ret;
}


/* --------------------------------------------------------------------- */
/* Below are the full set of visible functions exported through the VDSO */
/*              Everything above must be marked static                   */
/* --------------------------------------------------------------------- */

sysreturn
__vdso_clock_gettime(clockid_t clk_id, struct timespec * tp)
{
    return do_vdso_clock_gettime(clk_id, tp);
}

sysreturn
clock_gettime(clockid_t clk_id, struct timespec * tp)
{
    return do_vdso_clock_gettime(clk_id, tp);
}

sysreturn
__vdso_gettimeofday(struct timeval * tv, void * tz)
{
    return do_vdso_gettimeofday(tv, tz);
}

sysreturn
gettimeofday(struct timeval * tv, void * tz)
{
    return do_vdso_gettimeofday(tv, tz);
}

sysreturn
__vdso_getcpu(unsigned * cpu, unsigned * node, void * tcache)
{
    return do_vdso_getcpu(cpu, node, tcache);
}

sysreturn
getcpu(unsigned * cpu, unsigned * node, void * tcache)
{
    return do_vdso_getcpu(cpu, node, tcache);
}

sysreturn
__vdso_time(time_t * t)
{
    return do_vdso_time(t);
}

sysreturn
time(time_t * t)
{
    return do_vdso_time(t);
}
