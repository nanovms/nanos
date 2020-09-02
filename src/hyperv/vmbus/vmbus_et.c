/*-
 * Copyright (c) 2015,2016-2017 Microsoft Corp.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *      notice, this list of conditions and the following disclaimer in the
 *      documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <kernel.h>
#include <page.h>
#include <hyperv_internal.h>
#include "hyperv_reg.h"
#include "hyperv_var.h"
#include "vmbus_var.h"

//#define VMBUS_TIMER_DEBUG
#ifdef VMBUS_TIMER_DEBUG
#define vmbus_timer_debug(x, ...) do { rprintf("VMBUS TIMER: " x, ##__VA_ARGS__); } while(0)
#else
#define vmbus_timer_debug(x, ...)
#endif

#define MSR_HV_STIMER0_CFG_SINT        \
    ((((uint64_t)VMBUS_SINT_TIMER) << MSR_HV_STIMER_CFG_SINT_SHIFT) & \
     MSR_HV_STIMER_CFG_SINT_MASK)

/*
 * Additionally required feature:
 * - SynIC is needed for interrupt generation.
 */
#define CPUID_HV_ET_MASK        (CPUID_HV_MSR_SYNIC |        \
                     CPUID_HV_MSR_SYNTIMER)

struct vmbus_timer {
} vmbus_timer;

typedef struct vmbus_timer *vmbus_timer_t;

static vmbus_timer_t vmbus_et;

static __inline u64
hyperv_sbintime2count(timestamp time)
{
    return (sec_from_timestamp(time) * HYPERV_TIMER_FREQ) +
        (nsec_from_timestamp(truncate_seconds(time)) / HYPERV_TIMER_NS_FACTOR);
}

void
vmbus_et_intr(void)
{
    vmbus_timer_debug("%s\n", __func__);
}

closure_function(1, 1, void, vmbus_et_timer, hyperv_tc64_t, hyperv_tc64,
                 timestamp, interval)
{
    u64 cur = bound(hyperv_tc64)();
    cur += hyperv_sbintime2count(interval);
    write_msr(MSR_HV_STIMER0_COUNT, cur);
}

closure_function(0, 0, void, vmbus_et_timer_percpu_init)
{
    /*
     * Make sure that STIMER0 is really disabled before writing
     * to STIMER0_CONFIG.
     *
     * "Writing to the configuration register of a timer that
     *  is already enabled may result in undefined behaviour."
     */
    for (;;) {
        uint64_t val;

        /* Stop counting, and this also implies disabling STIMER0 */
        write_msr(MSR_HV_STIMER0_COUNT, 0);

        val = read_msr(MSR_HV_STIMER0_CONFIG);
        if ((val & MSR_HV_STIMER_CFG_ENABLE) == 0)
            break;
        kern_pause();
    }
    write_msr(MSR_HV_STIMER0_CONFIG,
        MSR_HV_STIMER_CFG_AUTOEN | MSR_HV_STIMER0_CFG_SINT);
}

boolean
init_vmbus_et_timer(heap general, u32 hyperv_features, hyperv_tc64_t hyperv_tc64,
                    clock_timer *ct, thunk *per_cpu_init)
{
    if ((hyperv_features & CPUID_HV_ET_MASK) != CPUID_HV_ET_MASK)
        return false;
    assert(!vmbus_et);
    vmbus_et = &vmbus_timer;
    *ct = closure(general, vmbus_et_timer, hyperv_tc64);
    *per_cpu_init = closure(general, vmbus_et_timer_percpu_init);
    apply(*per_cpu_init);
    return true;
}
