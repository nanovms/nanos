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

typedef closure_type(xen_device_probe, boolean, int, tuple);
void register_xen_driver(const char * name, xen_device_probe probe);
grant_ref_t xen_grant_access(u16 domid, u64 phys, boolean readonly);


    
