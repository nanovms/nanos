/*-
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * This header is BSD licensed so anyone can use the definitions to implement
 * compatible drivers/servers.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of IBM nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL IBM OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $FreeBSD$
 */

#ifndef _PVSCSI_H_
#define _PVSCSI_H_

#define	PCI_VENDOR_ID_VMWARE		0x15ad
#define	PCI_DEVICE_ID_VMWARE_PVSCSI	0x07c0

enum pvscsi_reg_offset {
	PVSCSI_REG_OFFSET_COMMAND		= 0x0000,
	PVSCSI_REG_OFFSET_COMMAND_DATA		= 0x0004,
	PVSCSI_REG_OFFSET_COMMAND_STATUS	= 0x0008,
	PVSCSI_REG_OFFSET_LAST_STS_0		= 0x0100,
	PVSCSI_REG_OFFSET_LAST_STS_1		= 0x0104,
	PVSCSI_REG_OFFSET_LAST_STS_2		= 0x0108,
	PVSCSI_REG_OFFSET_LAST_STS_3		= 0x010c,
	PVSCSI_REG_OFFSET_INTR_STATUS		= 0x100c,
	PVSCSI_REG_OFFSET_INTR_MASK		= 0x2010,
	PVSCSI_REG_OFFSET_KICK_NON_RW_IO	= 0x3014,
	PVSCSI_REG_OFFSET_DEBUG			= 0x3018,
	PVSCSI_REG_OFFSET_KICK_RW_IO		= 0x4018,
};

enum pvscsi_commands {
	PVSCSI_CMD_FIRST			= 0,

	PVSCSI_CMD_ADAPTER_RESET		= 1,
	PVSCSI_CMD_ISSUE_SCSI			= 2,
	PVSCSI_CMD_SETUP_RINGS			= 3,
	PVSCSI_CMD_RESET_BUS			= 4,
	PVSCSI_CMD_RESET_DEVICE			= 5,
	PVSCSI_CMD_ABORT_CMD			= 6,
	PVSCSI_CMD_CONFIG			= 7,
	PVSCSI_CMD_SETUP_MSG_RING		= 8,
	PVSCSI_CMD_DEVICE_UNPLUG		= 9,
	PVSCSI_CMD_SETUP_REQCALLTHRESHOLD	= 10,
	PVSCSI_CMD_GET_MAX_TARGETS		= 11,

	PVSCSI_CMD_LAST				= 12,
};

#define	PVSCSI_SETUP_RINGS_MAX_NUM_PAGES	32
#define	PVSCSI_SETUP_MSG_RING_MAX_NUM_PAGES	16

struct pvscsi_cmd_desc_setup_rings {
	u32	req_ring_num_pages;
	u32	cmp_ring_num_pages;
	u64	rings_state_ppns[1];
	u64	req_ring_ppns[PVSCSI_SETUP_RINGS_MAX_NUM_PAGES];
	u64	cmp_ring_ppns[PVSCSI_SETUP_RINGS_MAX_NUM_PAGES];
} __attribute__((packed));

struct pvscsi_rings_state {
	u32	req_prod_idx;
	u32	req_cons_idx;
	u32	req_num_entries_log2;
	u32	cmp_prod_idx;
	u32	cmp_cons_idx;
	u32	cmp_num_entries_log2;
	u32	req_call_threshold;
	u8		_pad[100];
	u32	msg_prod_idx;
	u32	msg_cons_idx;
	u32	msg_num_entries_log2;
} __attribute__((packed));

#define	PVSCSI_FLAG_CMD_DIR_NONE	(1 << 2)
#define	PVSCSI_FLAG_CMD_DIR_TOHOST	(1 << 3)
#define	PVSCSI_FLAG_CMD_DIR_TODEVICE	(1 << 4)

#define	PVSCSI_INTR_CMPL_0	(1 << 0)
#define	PVSCSI_INTR_CMPL_1	(1 << 1)
#define	PVSCSI_INTR_CMPL_MASK	MASK(2)

#define	PVSCSI_INTR_ALL_SUPPORTED MASK(4)

struct pvscsi_ring_req_desc {
	u64	context;
	u64	data_addr;
	u64	data_len;
	u64	sense_addr;
	u32	sense_len;
	u32	flags;
	u8	cdb[16];
	u8	cdb_len;
	u8	lun[8];
	u8	tag;
	u8	bus;
	u8	target;
	u8	vcpu_hint;
	u8	unused[59];
} __attribute__((packed));

struct pvscsi_ring_cmp_desc {
	u64	context;
	u64	data_len;
	u32	sense_len;
	u16	host_status;
	u16	scsi_status;
	u32	_pad[2];
} __attribute__((packed));

#define	PVSCSI_MAX_NUM_PAGES_REQ_RING	PVSCSI_SETUP_RINGS_MAX_NUM_PAGES
#define	PVSCSI_MAX_NUM_PAGES_CMP_RING	PVSCSI_SETUP_RINGS_MAX_NUM_PAGES

#define	PVSCSI_MAX_NUM_REQ_ENTRIES_PER_PAGE \
	(PAGESIZE / sizeof(struct pvscsi_ring_req_desc))
#define	PVSCSI_MAX_NUM_CMP_ENTRIES_PER_PAGE \
	(PAGESIZE / sizeof(struct pvscs_ring_cmp_desc))
#define	PVSCSI_MAX_NUM_MSG_ENTRIES_PER_PAGE \
	(PAGESIZE / sizeof(struct pvscsi_ring_msg_desc))

#define	PVSCSI_MAX_REQ_QUEUE_DEPTH \
	(PVSCSI_MAX_NUM_PAGES_REQ_RING * PVSCSI_MAX_NUM_REQ_ENTRIES_PER_PAGE)
#define	PVSCSI_MAX_CMP_QUEUE_DEPTH \
	(PVSCSI_MAX_NUM_PAGES_CMP_RING * PVSCSI_MAX_NUM_CMP_ENTRIES_PER_PAGE)
#define	PVSCSI_MAX_QUEUE_DEPTH \
	MAX(PVSCSI_MAX_REQ_QUEUE_DEPTH, PVSCSI_MAX_CMP_QUEUE_DEPTH)

#define BTSTAT_SUCCESS 0

#define MAX_LUN 1

#define MSG_SIMPLE_Q_TAG   0x20 /* O/O */

#endif /* _PVSCSI_H_ */
