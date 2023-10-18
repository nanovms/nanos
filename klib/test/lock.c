#include <kernel.h>

static boolean klib_test_rw_spinlock(void)
{
    struct rw_spinlock l;
    spin_rw_lock_init(&l);
    if (!spin_tryrlock(&l)) {
        msg_err("couldn't rlock unlocked spinlock\n");
        return false;
    }
    if (spin_trywlock(&l)) {
        msg_err("could wlock rlocked spinlock\n");
        return false;
    }
#if defined(SMP_ENABLE)
    if (!spin_tryrlock(&l)) {
        msg_err("couldn't rlock rlocked spinlock\n");
        return false;
    }
    spin_runlock(&l);
#endif
    spin_runlock(&l);
    if (!spin_trywlock(&l)) {
        msg_err("couldn't wlock unlocked spinlock\n");
        return false;
    }
    if (spin_tryrlock(&l)) {
        msg_err("could rlock wlocked spinlock\n");
        return false;
    }
    if (spin_trywlock(&l)) {
        msg_err("could wlock wlocked spinlock\n");
        return false;
    }
    spin_wunlock(&l);
    return true;
}

int init(status_handler complete)
{
    if (!klib_test_rw_spinlock())
        return KLIB_INIT_FAILED;
    rprintf("Lock test OK\n");
    return KLIB_INIT_OK;
}
