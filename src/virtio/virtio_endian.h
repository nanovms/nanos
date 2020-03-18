/*
 * virtio legacy host: guest-endian
 * virtio v1 (modern) host: little-endian
 */
#define virtio_htog16(modern, val) ((modern) ? le16toh(val) : (val))
#define virtio_htog32(modern, val) ((modern) ? le32toh(val) : (val))
#define virtio_htog64(modern, val) ((modern) ? le64toh(val) : (val))
