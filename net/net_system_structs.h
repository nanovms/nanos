#define	ENOTSOCK	88	/* Socket operation on non-socket */
#define	EPFNOSUPPORT	96	/* Protocol family not supported */
#define	EAFNOSUPPORT	97	/* Address family not supported by protocol */
#define	EADDRINUSE	98	/* Address already in use */
#define	EADDRNOTAVAIL	99	/* Cannot assign requested address */
#define	ENETDOWN	100	/* Network is down */
#define	ENETUNREACH	101	/* Network is unreachable */
#define	ENETRESET	102	/* Network dropped connection because of reset */
#define	ECONNRESET	104
#define	ENOBUFS		105	/* No buffer space available */
#define	EISCONN		106	/* Transport endpoint is already connected */
#define	ENOTCONN	107	/* Transport endpoint is not connected */
#define	ETIMEDOUT	110	/* Connection timed out */
#define	ECONNREFUSED	111	/* Connection refused */
#define	EHOSTUNREACH	113	/* No route to host */


enum protocol_type {
    SOCK_STREAM  = 1,    /* stream (connection) socket	*/
    SOCK_DGRAM   = 2,    /* datagram (conn.less) socket	*/
    SOCK_RAW     = 3     /* raw socket			*/
};

#define __SOCK_SIZE__	16		/* sizeof(struct sockaddr)	*/

#define AF_INET 10
