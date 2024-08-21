enum protocol_type {
    SOCK_STREAM  = 1,    /* stream (connection) socket	*/
    SOCK_DGRAM   = 2,    /* datagram (conn.less) socket	*/
    SOCK_RAW     = 3,    /* raw socket			*/
    SOCK_SEQPACKET = 5,
};

#define SOCK_TYPE_MASK	0xf
#define __SOCK_SIZE__	16		/* sizeof(struct sockaddr)	*/

#define AF_UNSPEC   0
#define AF_UNIX 1
#define AF_INET 2
#define AF_INET6    10
#define AF_NETLINK  16
#define AF_VSOCK    40

#define SIOCGIFNAME    0x8910
#define SIOCGIFCONF    0x8912
#define SIOCGIFFLAGS   0x8913
#define SIOCSIFFLAGS   0x8914
#define SIOCGIFADDR    0x8915
#define SIOCSIFADDR    0x8916
#define SIOCGIFNETMASK 0x891b
#define SIOCSIFNETMASK 0x891c
#define SIOCGIFMETRIC  0x891d
#define SIOCSIFMETRIC  0x891e
#define SIOCGIFMTU     0x8921
#define SIOCSIFMTU     0x8922
#define SIOCGIFHWADDR  0x8927
#define SIOCGIFINDEX   0x8933
#define SIOCDIFADDR    0x8936

/* ARP protocol HARDWARE identifiers */
#define ARPHRD_ETHER    1
#define ARPHRD_LOOPBACK 772
#define ARPHRD_VOID     0xFFFF

#define MSG_OOB         0x00000001
#define MSG_PEEK        0x00000002
#define MSG_DONTROUTE   0x00000004
#define MSG_PROBE       0x00000010
#define MSG_TRUNC       0x00000020
#define MSG_DONTWAIT    0x00000040
#define MSG_EOR         0x00000080
#define MSG_CONFIRM     0x00000800
#define MSG_NOSIGNAL    0x00004000
#define MSG_MORE        0x00008000
#define MSG_WAITFORONE  0x00010000

// tuplify
#define SOCK_NONBLOCK 00004000
#define SOCK_CLOEXEC  02000000
#define TCP_NODELAY		1	/* Turn off Nagle's algorithm. */
#define TCP_MAXSEG		2	/* Limit MSS */
#define TCP_CORK		3	/* Never send partially complete segments */
#define TCP_KEEPIDLE		4	/* Start keeplives after this period */
#define TCP_KEEPINTVL		5	/* Interval between keepalives */
#define TCP_KEEPCNT		6	/* Number of keepalives before death */
#define TCP_SYNCNT		7	/* Number of SYN retransmits */
#define TCP_LINGER2		8	/* Life time of orphaned FIN-WAIT-2 state */
#define TCP_DEFER_ACCEPT	9	/* Wake up listener only when data arrive */
#define TCP_WINDOW_CLAMP	10	/* Bound advertised window */
#define TCP_INFO		11	/* Information about this connection. */
#define TCP_QUICKACK		12	/* Block/reenable quick acks */
#define TCP_CONGESTION		13	/* Congestion control algorithm */
#define TCP_MD5SIG		14	/* TCP MD5 Signature (RFC2385) */
#define TCP_THIN_LINEAR_TIMEOUTS 16      /* Use linear timeouts for thin streams*/
#define TCP_THIN_DUPACK         17      /* Fast retrans. after 1 dupack */
#define TCP_USER_TIMEOUT	18	/* How long for loss retry before timeout */
#define TCP_REPAIR		19	/* TCP sock is under repair right now */
#define TCP_REPAIR_QUEUE	20
#define TCP_QUEUE_SEQ		21
#define TCP_REPAIR_OPTIONS	22
#define TCP_FASTOPEN		23	/* Enable FastOpen on listeners */
#define TCP_TIMESTAMP		24
#define TCP_NOTSENT_LOWAT	25	/* limit number of unsent bytes in write queue */
#define TCP_CC_INFO		26	/* Get Congestion Control (optional) info */
#define TCP_SAVE_SYN		27	/* Record SYN headers for new connections */
#define TCP_SAVED_SYN		28	/* Get SYN headers recorded for connection */

#define SHUT_RD   0
#define SHUT_WR   1
#define SHUT_RDWR 2

struct tcp_info {
    u8 tcpi_state;
    u8 tcpi_ca_state;
    u8 tcpi_retransmits;
    u8 tcpi_probes;
    u8 tcpi_backoff;
    u8 tcpi_options;
    u8 tcpi_snd_wscale : 4, tcpi_rcv_wscale : 4;
    u8 tcpi_delivery_rate_app_limited:1, tcpi_fastopen_client_fail:2;

    u32 tcpi_rto;
    u32 tcpi_ato;
    u32 tcpi_snd_mss;
    u32 tcpi_rcv_mss;

    u32 tcpi_unacked;
    u32 tcpi_sacked;
    u32 tcpi_lost;
    u32 tcpi_retrans;
    u32 tcpi_fackets;

    u32 tcpi_last_data_sent;
    u32 tcpi_last_ack_sent;
    u32 tcpi_last_data_recv;
    u32 tcpi_last_ack_recv;

    u32 tcpi_pmtu;
    u32 tcpi_rcv_ssthresh;
    u32 tcpi_rtt;
    u32 tcpi_rttvar;
    u32 tcpi_snd_ssthresh;
    u32 tcpi_snd_cwnd;
    u32 tcpi_advmss;
    u32 tcpi_reordering;

    u32 tcpi_rcv_rtt;
    u32 tcpi_rcv_space;

    u32 tcpi_total_retrans;

    u64 tcpi_pacing_rate;
    u64 tcpi_max_pacing_rate;
    u64 tcpi_bytes_acked;
    u64 tcpi_bytes_received;
    u32 tcpi_segs_out;
    u32 tcpi_segs_in;

    u32 tcpi_notsent_bytes;
    u32 tcpi_min_rtt;
    u32 tcpi_data_segs_in;
    u32 tcpi_data_segs_out;

    u64 tcpi_delivery_rate;

    u64 tcpi_busy_time;
    u64 tcpi_rwnd_limited;
    u64 tcpi_sndbuf_limited;

    u32 tcpi_delivered;
    u32 tcpi_delivered_ce;

    u64 tcpi_bytes_sent;
    u64 tcpi_bytes_retrans;
    u32 tcpi_dsack_dups;
    u32 tcpi_reord_seen;

    u32 tcpi_rcv_ooopack;

    u32 tcpi_snd_wnd;
};

/* values for tcp_info.tcpi_state */
enum {
    TCP_ESTABLISHED = 1,
    TCP_SYN_SENT,
    TCP_SYN_RECV,
    TCP_FIN_WAIT1,
    TCP_FIN_WAIT2,
    TCP_TIME_WAIT,
    TCP_CLOSE,
    TCP_CLOSE_WAIT,
    TCP_LAST_ACK,
    TCP_LISTEN,
    TCP_CLOSING,
    TCP_NEW_SYN_RECV,
    TCP_BOUND_INACTIVE,
};

/* values for tcp_info.tcpi_ca_state  */
enum tcp_ca_state
{
  TCP_CA_Open = 0,
  TCP_CA_Disorder,
  TCP_CA_CWR,
  TCP_CA_Recovery,
  TCP_CA_Loss,
};

/* flags for tcp_info.tcpi_options  */
# define TCPI_OPT_TIMESTAMPS    0x01
# define TCPI_OPT_SACK          0x02
# define TCPI_OPT_WSCALE        0x04
# define TCPI_OPT_ECN           0x08
# define TCPI_OPT_ECN_SEEN      0x10
# define TCPI_OPT_SYN_DATA      0x20

