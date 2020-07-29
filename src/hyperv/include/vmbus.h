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
 *
 * $FreeBSD$
 */

#ifndef _VMBUS_H_
#define _VMBUS_H_

/*
 * VMBUS version is 32 bit, upper 16 bit for major_number and lower
 * 16 bit for minor_number.
 *
 * 0.13  --  Windows Server 2008
 * 1.1   --  Windows 7
 * 2.4   --  Windows 8
 * 3.0   --  Windows 8.1
 * 4.0   --  Windows 10
 * 5.0   --  Newer Windows 10
 */
#define VMBUS_VERSION_WS2008		((0 << 16) | (13))
#define VMBUS_VERSION_WIN7		((1 << 16) | (1))
#define VMBUS_VERSION_WIN8		((2 << 16) | (4))
#define VMBUS_VERSION_WIN8_1		((3 << 16) | (0))
#define VMBUS_VERSION_WIN10		((4 << 16) | (0))
#define VMBUS_VERSION_WIN10_V5		((5 << 16) | (0))

#define VMBUS_VERSION_MAJOR(ver)	(((uint32_t)(ver)) >> 16)
#define VMBUS_VERSION_MINOR(ver)	(((uint32_t)(ver)) & 0xffff)

#define VMBUS_CHAN_POLLHZ_MIN		100	/* 10ms interval */
#define VMBUS_CHAN_POLLHZ_MAX		1000000	/* 1us interval */

/*
 * GPA stuffs.
 */
struct vmbus_gpa_range {
	uint32_t	gpa_len;
	uint32_t	gpa_ofs;
	uint64_t	gpa_page[0];
} __packed;

/* This is actually vmbus_gpa_range.gpa_page[1] */
struct vmbus_gpa {
	uint32_t	gpa_len;
	uint32_t	gpa_ofs;
	uint64_t	gpa_page;
} __packed;

#define VMBUS_CHANPKT_SIZE_SHIFT	3

#define VMBUS_CHANPKT_GETLEN(pktlen)	\
	(((int)(pktlen)) << VMBUS_CHANPKT_SIZE_SHIFT)

struct vmbus_chanpkt_hdr {
	uint16_t	cph_type;	/* VMBUS_CHANPKT_TYPE_ */
	uint16_t	cph_hlen;	/* header len, in 8 bytes */
	uint16_t	cph_tlen;	/* total len, in 8 bytes */
	uint16_t	cph_flags;	/* VMBUS_CHANPKT_FLAG_ */
	uint64_t	cph_xactid;
} __packed;

#define VMBUS_CHANPKT_TYPE_INBAND	0x0006
#define VMBUS_CHANPKT_TYPE_RXBUF	0x0007
#define VMBUS_CHANPKT_TYPE_GPA		0x0009
#define VMBUS_CHANPKT_TYPE_COMP		0x000b

#define VMBUS_CHANPKT_FLAG_NONE		0
#define VMBUS_CHANPKT_FLAG_RC		0x0001	/* report completion */

#define VMBUS_CHANPKT_CONST_DATA(pkt)		\
	(const void *)((const uint8_t *)(pkt) +	\
	VMBUS_CHANPKT_GETLEN((pkt)->cph_hlen))

/* Include padding */
#define VMBUS_CHANPKT_DATALEN(pkt)		\
	(VMBUS_CHANPKT_GETLEN((pkt)->cph_tlen) -\
	 VMBUS_CHANPKT_GETLEN((pkt)->cph_hlen))

struct vmbus_rxbuf_desc {
	uint32_t	rb_len;
	uint32_t	rb_ofs;
} __packed;

struct vmbus_chanpkt_rxbuf {
	struct vmbus_chanpkt_hdr cp_hdr;
	uint16_t	cp_rxbuf_id;
	uint16_t	cp_rsvd;
	uint32_t	cp_rxbuf_cnt;
	struct vmbus_rxbuf_desc cp_rxbuf[];
} __packed;

struct vmbus_chan_br {
	void		*cbr;
	bus_addr_t	cbr_paddr;
	int		cbr_txsz;
	int		cbr_rxsz;
};

struct vmbus_channel;
struct vmbus_xact;
struct vmbus_xact_ctx;
struct hyperv_guid;

typedef void	(*vmbus_chan_callback_t)(struct vmbus_channel *, void *);

/*
 * vmbus_chan_open_br()
 *
 * Return values:
 * 0			Succeeded.
 * EISCONN		Failed, and the memory passed through 'br' is still
 *			connected.  Callers must _not_ free the the memory
 *			passed through 'br', if this error happens.
 * other values		Failed.  The memory passed through 'br' is no longer
 *			connected.  Callers are free to do anything with the
 *			memory passed through 'br'.
 */
void		vmbus_chan_open(struct vmbus_channel *chan,
		    int txbr_size, int rxbr_size, const void *udata, int udlen,
		    vmbus_chan_callback_t cb, void *cbarg);
int		vmbus_chan_open_br(struct vmbus_channel *chan,
		    const struct vmbus_chan_br *cbr, const void *udata,
		    int udlen, vmbus_chan_callback_t cb, void *cbarg);
void		vmbus_chan_gpadl_connect(struct vmbus_channel *chan,
		    bus_addr_t paddr, int size, uint32_t *gpadl);
void		vmbus_chan_gpadl_disconnect(struct vmbus_channel *chan,
		    uint32_t gpadl);

void		vmbus_chan_cpu_set(struct vmbus_channel *chan, int cpu);

int		vmbus_chan_recv(struct vmbus_channel *chan, void *data, int *dlen,
		    uint64_t *xactid);
int		vmbus_chan_recv_pkt(struct vmbus_channel *chan,
		    struct vmbus_chanpkt_hdr *pkt, int *pktlen);

int		vmbus_chan_send(struct vmbus_channel *chan, uint16_t type,
		    uint16_t flags, void *data, int dlen, uint64_t xactid);
int		vmbus_chan_send_sglist(struct vmbus_channel *chan,
		    struct vmbus_gpa sg[], int sglen, void *data, int dlen,
		    uint64_t xactid);

bool		vmbus_chan_is_revoked(const struct vmbus_channel *chan);

void           vmbus_chan_poll_messages(struct vmbus_channel *chan);
#endif	/* !_VMBUS_H_ */
