#ifndef _ERRNO_H_
#define _ERRNO_H_

#define EPERM           1       /* Operation not permitted */
#define ENOENT          2       /* No such file or directory */
#define ESRCH           3       /* No such process */
#define EINTR           4       /* Interrupted system call */
#define EIO             5       /* Input/output error */
#define ENXIO           6       /* Device not configured */
#define E2BIG           7       /* Argument list too long */
#define ENOEXEC         8       /* Exec format error */
#define EBADF           9       /* Bad file descriptor */
#define ECHILD          10      /* No child processes */
#define EAGAIN          11      /* Resource deadlock avoided */
#define ENOMEM          12      /* Cannot allocate memory */
#define EACCES          13      /* Permission denied */
#define EFAULT          14      /* Bad address */
#define EBUSY           16      /* Device busy */
#define EEXIST          17      /* File exists */
#define EXDEV           18      /* Cross-device link */
#define ENODEV          19      /* Operation not supported by device */
#define ENOTDIR         20      /* Not a directory */
#define EISDIR          21      /* Is a directory */
#define EINVAL          22      /* Invalid argument */
#define ENFILE          23      /* Too many open files in system */
#define EMFILE          24      /* Too many open files */
#define ENOTTY          25      /* Inappropriate ioctl for device */
#define EFBIG           27      /* File too large */
#define ENOSPC          28      /* No space left on device */
#define ESPIPE          29      /* Illegal seek */
#define EROFS           30      /* Read-only filesystem */
#define EMLINK          31      /* Too many links */
#define EPIPE           32      /* Broken pipe */
#define ERANGE          34      /* Math result not representable */
#define ENAMETOOLONG    36      /* File name too long */
#define ENOSYS          38      /* Invalid system call number */
#define ENOTEMPTY       39      /* Directory not empty */
#define ELOOP           40      /* Too many symbolic links */
#define ENOPROTOOPT     42      /* Protocol not available */
#define ENODATA         61      /* No data available */
#define ETIME           62      /* Timer expired */
#define EOVERFLOW       75      /* Value too large for defined data type */
#define EBADFD          77      /* File descriptor in bad state */
#define ENOTSOCK        88      /* Socket operation on non-socket */
#define EDESTADDRREQ    89      /* Destination address required */
#define EMSGSIZE        90      /* Message too long */
#define EPROTOTYPE      91      /* Wrong protocol type for socket */
#define EPROTONOSUPPORT 93      /* Protocol not supported */
#define ESOCKTNOSUPPORT 94      /* Socket type not supported */
#define EOPNOTSUPP      95      /* Operation not supported */
#define EPFNOSUPPORT    96      /* Protocol family not supported */
#define EAFNOSUPPORT    97      /* Address family not supported by protocol */
#define EADDRINUSE      98      /* Address already in use */
#define EADDRNOTAVAIL   99      /* Cannot assign requested address */
#define ENETDOWN        100     /* Network is down */
#define ENETUNREACH     101     /* Network is unreachable */
#define ENETRESET       102     /* Network dropped connection because of reset */
#define ECONNABORTED    103     /* Software caused connection abort */
#define ECONNRESET      104     /* Connection reset by peer */
#define ENOBUFS         105     /* No buffer space available */
#define EISCONN         106     /* Transport endpoint is already connected */
#define ENOTCONN        107     /* Transport endpoint is not connected */
#define ETIMEDOUT       110     /* Connection timed out */
#define ECONNREFUSED    111     /* Connection refused */
#define EHOSTUNREACH    113     /* No route to host */
#define EALREADY        114     /* Operation already in progress */
#define EINPROGRESS     115     /* Operation now in progress */
#define ECANCELED       125     /* Operation canceled */

#endif
