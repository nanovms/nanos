typedef s8 int8_t;
typedef u8 uint8_t;
typedef u16 uint16_t;
typedef s16 int16_t;
typedef u32 uint32_t;
typedef s32 int32_t;
typedef u64 uint64_t;
typedef s64 int64_t;

#define __XEN_INTERFACE_VERSION__ 0x00040d00

#include "xen.h"
#include "arch-x86/cpuid.h"
#include "event_channel.h"
#include "platform.h"
#include "hvm/params.h"
#include "hvm/hvm_op.h"
#include "io/xs_wire.h"
#include "memory.h"
#include "features.h"
#include "version.h"
#include "vcpu.h"
#include "hypercall.h"
#include "grant_table.h"
#include "io/xenbus.h"

#define memset runtime_memset
#define xen_wmb write_barrier
#define xen_mb memory_barrier

typedef struct xen_dev {
    int if_id;
    domid_t backend_id;
    buffer frontend;
    buffer backend;
} *xen_dev;

status xen_allocate_evtchn(domid_t other_id, evtchn_port_t *evtchn);
void xen_register_evtchn_handler(evtchn_port_t evtchn, thunk handler);
int xen_notify_evtchn(evtchn_port_t evtchn);
int xen_unmask_evtchn(evtchn_port_t evtchn);

grant_ref_t xen_grant_page_access(u16 domid, u64 phys, boolean readonly);
void xen_revoke_page_access(grant_ref_t ref);

status xenbus_get_state(buffer path, XenbusState *state);
status xenbus_set_state(u32 tx_id, buffer path, XenbusState newstate);

status xenstore_read_u64(u32 tx_id, buffer path, const char *node, u64 *result);
status xenstore_sync_request(u32 tx_id, enum xsd_sockmsg_type type, buffer request, buffer response);
status xenstore_sync_printf(u32 tx_id, buffer path, const char *node, const char *format, ...);
status xenstore_transaction_start(u32 *tx_id);
status xenstore_transaction_end(u32 tx_id, boolean abort);

status xendev_attach(xen_dev xd, int id, buffer frontend, tuple meta);

typedef closure_type(xen_device_probe, boolean, int, buffer, tuple);
void register_xen_driver(const char * name, xen_device_probe probe);
