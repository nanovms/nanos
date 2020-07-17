/*-
 * Copyright (c) 2016 Microsoft Corp.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice unmodified, this list of conditions, and the following
 *    disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
#include <kernel.h>
#include <page.h>
#include <hyperv_internal.h>
#include <hyperv_busdma.h>
#include <vmbus_xact.h>
#include "vmbus_var.h"

#define NULL 0
#define VMBUS_XACT_CTXF_DESTROY        0x0001

#ifdef VMBUS_XACT_DEBUG
#define vmbus_xact_debug(x, ...) do {rprintf(" VMBUS XACT: " x "\n", ##__VA_ARGS__);} while(0)
#else
#define vmbus_xact_debug(x, ...)
#endif

static struct vmbus_xact    *vmbus_xact_alloc(vmbus_dev dev, struct vmbus_xact_ctx *);
static struct vmbus_xact    *vmbus_xact_get1(struct vmbus_xact_ctx *,
                    uint32_t);
static const void        *vmbus_xact_wait1(struct vmbus_xact *, size_t *,
                    bool);
static const void        *vmbus_xact_return(struct vmbus_xact *,
                    size_t *);
static void            vmbus_xact_save_resp(struct vmbus_xact *,
                    const void *, size_t);

static struct vmbus_xact *
vmbus_xact_alloc(vmbus_dev dev, struct vmbus_xact_ctx *ctx)
{
    struct vmbus_xact *xact = allocate_zero(dev->general, sizeof(*xact));
    assert(xact != INVALID_ADDRESS);
    xact->x_ctx = ctx;

    /* XXX assume that page aligned is enough */
    xact->x_req = allocate(dev->contiguous, ctx->xc_req_size);
    assert(xact->x_req != INVALID_ADDRESS);
    assert((u64)xact->x_req == pad((u64)xact->x_req, PAGESIZE));
    xact->x_req_dma.hv_paddr = physical_from_virtual(xact->x_req);
    assert(xact->x_req_dma.hv_paddr != INVALID_PHYSICAL);

    if (ctx->xc_priv_size != 0) {
        xact->x_priv = allocate(dev->general, ctx->xc_priv_size);
        assert(xact->x_priv != INVALID_ADDRESS);
    }
    xact->x_resp0 = allocate(dev->general, ctx->xc_resp_size);
    assert(xact->x_resp0 != INVALID_ADDRESS);

    return (xact);
}

static struct vmbus_xact *
vmbus_xact_get1(struct vmbus_xact_ctx *ctx, uint32_t dtor_flag)
{
    struct vmbus_xact *xact;

    u64 flags = spin_lock_irq(&ctx->xc_lock);

    while ((ctx->xc_flags & dtor_flag) == 0 && ctx->xc_free == NULL)
        kern_pause();
    if (ctx->xc_flags & dtor_flag) {
        /* Being destroyed */
        xact = NULL;
    } else {
        xact = ctx->xc_free;
        assert(xact != NULL); //no free xact
        assert(xact->x_resp == NULL); //xact has pending response
        ctx->xc_free = NULL;
    }

    spin_unlock_irq(&ctx->xc_lock, flags);

    return (xact);
}

void vmbus_xact_ctx_create(vmbus_dev dev, size_t req_size, size_t resp_size,
    size_t priv_size)
{
    struct vmbus_xact_ctx *ctx = &dev->vmbus_xc;

    zero(ctx, sizeof(*ctx));

    assert(req_size > 0); //request size is 0
    assert(resp_size > 0); //response size is 0

    ctx->xc_req_size = req_size;
    ctx->xc_resp_size = resp_size;
    ctx->xc_priv_size = priv_size;

    ctx->xc_free = vmbus_xact_alloc(dev, ctx);
    assert(ctx->xc_free != INVALID_ADDRESS);

    spin_lock_init(&ctx->xc_lock);
}

bool
vmbus_xact_ctx_orphan(struct vmbus_xact_ctx *ctx)
{
    u64 flags = spin_lock_irq(&ctx->xc_lock);
    if (ctx->xc_flags & VMBUS_XACT_CTXF_DESTROY) {
        spin_unlock_irq(&ctx->xc_lock, flags);
        return (false);
    }
    ctx->xc_flags |= VMBUS_XACT_CTXF_DESTROY;
    spin_unlock_irq(&ctx->xc_lock, flags);

    ctx->xc_orphan = vmbus_xact_get1(ctx, 0);
    if (ctx->xc_orphan == NULL)
        halt("can't get xact");
    return (true);
}

struct vmbus_xact *
vmbus_xact_get(struct vmbus_xact_ctx *ctx, size_t req_len)
{
    struct vmbus_xact *xact;

    if (req_len > ctx->xc_req_size)
        halt("invalid request size %zu", req_len);

    xact = vmbus_xact_get1(ctx, VMBUS_XACT_CTXF_DESTROY);
    if (xact == NULL)
        return (NULL);

    runtime_memset(xact->x_req, 0, req_len);
    return (xact);
}

void
vmbus_xact_put(struct vmbus_xact *xact)
{
    struct vmbus_xact_ctx *ctx = xact->x_ctx;

    assert(ctx->xc_active == NULL); //pending active xact
    xact->x_resp = NULL;

    u64 flags = spin_lock_irq(&ctx->xc_lock);
    assert(ctx->xc_free == NULL); //has free xact
    ctx->xc_free = xact;
    spin_unlock_irq(&ctx->xc_lock, flags);
}

void *
vmbus_xact_req_data(const struct vmbus_xact *xact)
{
    return (xact->x_req);
}

bus_addr_t
vmbus_xact_req_paddr(const struct vmbus_xact *xact)
{
    return (xact->x_req_dma.hv_paddr);
}

void *
vmbus_xact_priv(const struct vmbus_xact *xact, size_t priv_len)
{

    if (priv_len > xact->x_ctx->xc_priv_size)
        halt("invalid priv size %zu", priv_len);
    return (xact->x_priv);
}

void
vmbus_xact_activate(struct vmbus_xact *xact)
{
    struct vmbus_xact_ctx *ctx = xact->x_ctx;

    assert(xact->x_resp == NULL); //xact has pending response

    u64 flags = spin_lock_irq(&ctx->xc_lock);
    assert(ctx->xc_active == NULL); // pending active xact
    ctx->xc_active = xact;
    spin_unlock_irq(&ctx->xc_lock, flags);
}

void
vmbus_xact_deactivate(struct vmbus_xact *xact)
{
    struct vmbus_xact_ctx *ctx = xact->x_ctx;

    u64 flags = spin_lock_irq(&ctx->xc_lock);
    assert(ctx->xc_active == xact); // xact mismatch
    ctx->xc_active = NULL;
    spin_unlock_irq(&ctx->xc_lock, flags);
}

static const void *
vmbus_xact_return(struct vmbus_xact *xact, size_t *resp_len)
{
    struct vmbus_xact_ctx *ctx = xact->x_ctx;
    const void *resp;

    assert(ctx->xc_active == xact); //xact trashed

    if ((ctx->xc_flags & VMBUS_XACT_CTXF_DESTROY) && xact->x_resp == NULL) {
        uint8_t b = 0;

        /*
         * Orphaned and no response was received yet; fake up
         * an one byte response.
         */
        rprintf("vmbus: xact ctx was orphaned w/ pending xact\n");
        vmbus_xact_save_resp(ctx->xc_active, &b, sizeof(b));
    }
    assert(xact->x_resp != NULL); //no response

    ctx->xc_active = NULL;

    resp = xact->x_resp;
    *resp_len = xact->x_resp_len;

    return (resp);
}


static const void *
vmbus_xact_wait1(struct vmbus_xact *xact, size_t *resp_len,
    bool can_sleep)
{
    struct vmbus_xact_ctx *ctx = xact->x_ctx;
    const void *resp;

    u64 flags = spin_lock_irq(&ctx->xc_lock);

    assert(ctx->xc_active == xact); // xact mismatch
    while (xact->x_resp == NULL &&
        (ctx->xc_flags & VMBUS_XACT_CTXF_DESTROY) == 0) {
            spin_unlock_irq(&ctx->xc_lock, flags);
            kernel_delay(milliseconds(1));
            flags = spin_lock_irq(&ctx->xc_lock);
    }
    resp = vmbus_xact_return(xact, resp_len);

    spin_unlock_irq(&ctx->xc_lock, flags);

    return (resp);
}

const void *
vmbus_xact_wait(struct vmbus_xact *xact, size_t *resp_len)
{
    return (vmbus_xact_wait1(xact, resp_len, true /* can sleep */));
}

const void *
vmbus_xact_busywait(struct vmbus_xact *xact, size_t *resp_len)
{
    return (vmbus_xact_wait1(xact, resp_len, false /* can't sleep */));
}

const void *
vmbus_xact_poll_first(struct vmbus_xact *xact, size_t *resp_len)
{
    struct vmbus_xact_ctx *ctx = xact->x_ctx;
    const void *resp;

    u64 flags = spin_lock_irq(&ctx->xc_lock);

    assert(ctx->xc_active == xact); //xact mismatch
    if (xact->x_resp == NULL &&
        (ctx->xc_flags & VMBUS_XACT_CTXF_DESTROY) == 0) {
        spin_unlock_irq(&ctx->xc_lock, flags);
        *resp_len = 0;
        return (NULL);
    }

    resp = xact->x_resp;
    *resp_len = xact->x_resp_len;

    spin_unlock_irq(&ctx->xc_lock, flags);

    return (resp);
}

const void *
vmbus_xact_poll(struct vmbus_xact *xact, size_t *resp_len)
{
    struct vmbus_xact_ctx *ctx = xact->x_ctx;
    const void *resp;

    u64 flags = spin_lock_irq(&ctx->xc_lock);

    assert(ctx->xc_active == xact); //xact mismatch
    if (xact->x_resp == NULL) {
        spin_unlock_irq(&ctx->xc_lock, flags);
        *resp_len = 0;
        return (NULL);
    }
    resp = vmbus_xact_return(xact, resp_len);

    spin_unlock_irq(&ctx->xc_lock, flags);

    return (resp);
}

static void
vmbus_xact_save_resp(struct vmbus_xact *xact, const void *data, size_t dlen)
{
    struct vmbus_xact_ctx *ctx = xact->x_ctx;
    size_t cplen = dlen;

    if (cplen > ctx->xc_resp_size) {
        rprintf("vmbus: xact response truncated %zu -> %zu\n",
            cplen, ctx->xc_resp_size);
        cplen = ctx->xc_resp_size;
    }

    assert(ctx->xc_active == xact); // xact mismatch
    runtime_memcpy(xact->x_resp0, data, cplen);
    xact->x_resp_len = cplen;
    xact->x_resp = xact->x_resp0;
}

void
vmbus_xact_wakeup(struct vmbus_xact *xact, const void *data, size_t dlen)
{
    struct vmbus_xact_ctx *ctx = xact->x_ctx;

    u64 flags = spin_lock_irq(&ctx->xc_lock);
    /*
     * NOTE:
     * xc_active could be NULL, if the ctx has been orphaned.
     */
    if (ctx->xc_active != NULL) {
        vmbus_xact_save_resp(xact, data, dlen);
    } else {
        assert(ctx->xc_flags & VMBUS_XACT_CTXF_DESTROY); //no active xact pending
        rprintf("vmbus: drop xact response\n");
    }
    spin_unlock_irq(&ctx->xc_lock, flags);
}

void
vmbus_xact_ctx_wakeup(struct vmbus_xact_ctx *ctx, const void *data, size_t dlen)
{
    u64 flags = spin_lock_irq(&ctx->xc_lock);
    /*
     * NOTE:
     * xc_active could be NULL, if the ctx has been orphaned.
     */
    if (ctx->xc_active != NULL) {
        vmbus_xact_save_resp(ctx->xc_active, data, dlen);
    } else {
        assert(ctx->xc_flags & VMBUS_XACT_CTXF_DESTROY); //no active xact pending
        vmbus_xact_debug("vmbus: drop xact response");
    }
    spin_unlock_irq(&ctx->xc_lock, flags);
}
