struct ata;

struct ata *ata_alloc(heap general);
void ata_dealloc(struct ata *);
boolean ata_probe(struct ata *);
u64 ata_get_capacity(struct ata *);

/* ATA commands (from sys/sys/ata.h) */
#define ATA_NOP                         0x00    /* NOP */
#define ATA_DATA_SET_MANAGEMENT         0x06
#define ATA_DEVICE_RESET                0x08    /* reset device */
#define ATA_READ                        0x20    /* read */
#define ATA_READ48                      0x24    /* read 48bit LBA */
#define ATA_READ_DMA48                  0x25    /* read DMA 48bit LBA */
#define ATA_READ_DMA_QUEUED48           0x26    /* read DMA QUEUED 48bit LBA */
#define ATA_READ_NATIVE_MAX_ADDRESS48   0x27    /* read native max addr 48bit */
#define ATA_READ_MUL48                  0x29    /* read multi 48bit LBA */
#define ATA_READ_STREAM_DMA48           0x2a    /* read DMA stream 48bit LBA */
#define ATA_READ_LOG_EXT                0x2f    /* read log ext - PIO Data-In */
#define ATA_READ_STREAM48               0x2b    /* read stream 48bit LBA */
#define ATA_WRITE                       0x30    /* write */
#define ATA_WRITE48                     0x34    /* write 48bit LBA */
#define ATA_WRITE_DMA48                 0x35    /* write DMA 48bit LBA */
#define ATA_WRITE_DMA_QUEUED48          0x36    /* write DMA QUEUED 48bit LBA*/
#define ATA_SET_MAX_ADDRESS48           0x37    /* set max address 48bit */
#define ATA_WRITE_MUL48                 0x39    /* write multi 48bit LBA */
#define ATA_WRITE_STREAM_DMA48          0x3a
#define ATA_WRITE_STREAM48              0x3b
#define ATA_WRITE_DMA_FUA48             0x3d
#define ATA_WRITE_DMA_QUEUED_FUA48      0x3e
#define ATA_WRITE_LOG_EXT               0x3f
#define ATA_READ_VERIFY                 0x40
#define ATA_READ_VERIFY48               0x42
#define ATA_WRITE_UNCORRECTABLE48       0x45    /* write uncorrectable 48bit LBA */
#define ATA_READ_LOG_DMA_EXT            0x47    /* read log DMA ext - PIO Data-In */
#define ATA_ZAC_MANAGEMENT_IN           0x4a    /* ZAC management in */
#define ATA_WRITE_LOG_DMA_EXT           0x57    /* WRITE LOG DMA EXT */
#define ATA_TRUSTED_NON_DATA            0x5b    /* TRUSTED NON-DATA */
#define ATA_TRUSTED_RECEIVE             0x5c    /* TRUSTED RECEIVE */
#define ATA_TRUSTED_RECEIVE_DMA         0x5d    /* TRUSTED RECEIVE DMA */
#define ATA_TRUSTED_SEND                0x5e    /* TRUSTED SEND */
#define ATA_TRUSTED_SEND_DMA            0x5f    /* TRUSTED SEND DMA */
#define ATA_READ_FPDMA_QUEUED           0x60    /* read DMA NCQ */
#define ATA_WRITE_FPDMA_QUEUED          0x61    /* write DMA NCQ */
#define ATA_NCQ_NON_DATA                0x63    /* NCQ non-data command */
#define ATA_SEND_FPDMA_QUEUED           0x64    /* send DMA NCQ */
#define ATA_RECV_FPDMA_QUEUED           0x65    /* receive DMA NCQ */
#define ATA_SEP_ATTN                    0x67    /* SEP request */
#define ATA_SEEK                        0x70    /* seek */
#define ATA_ZAC_MANAGEMENT_OUT          0x9f    /* ZAC management out */
#define ATA_DOWNLOAD_MICROCODE          0x92    /* DOWNLOAD MICROCODE */
#define ATA_DOWNLOAD_MICROCODE_DMA      0x93    /* DOWNLOAD MICROCODE DMA */
#define ATA_PACKET_CMD                  0xa0    /* packet command */
#define ATA_ATAPI_IDENTIFY              0xa1    /* get ATAPI params*/
#define ATA_SERVICE                     0xa2    /* service command */
#define ATA_SMART_CMD                   0xb0    /* SMART command */
#define ATA_CFA_ERASE                   0xc0    /* CFA erase */
#define ATA_READ_MUL                    0xc4    /* read multi */
#define ATA_WRITE_MUL                   0xc5    /* write multi */
#define ATA_SET_MULTI                   0xc6    /* set multi size */
#define ATA_READ_DMA_QUEUED             0xc7    /* read DMA QUEUED */
#define ATA_READ_DMA                    0xc8    /* read DMA */
#define ATA_WRITE_DMA                   0xca    /* write DMA */
#define ATA_WRITE_DMA_QUEUED            0xcc    /* write DMA QUEUED */
#define ATA_WRITE_MUL_FUA48             0xce
#define ATA_STANDBY_IMMEDIATE           0xe0    /* standby immediate */
#define ATA_IDLE_IMMEDIATE              0xe1    /* idle immediate */
#define ATA_STANDBY_CMD                 0xe2    /* standby */
#define ATA_IDLE_CMD                    0xe3    /* idle */
#define ATA_READ_BUFFER                 0xe4    /* read buffer */
#define ATA_READ_PM                     0xe4    /* read portmultiplier */
#define ATA_CHECK_POWER_MODE            0xe5    /* device power mode */
#define ATA_SLEEP                       0xe6    /* sleep */
#define ATA_FLUSHCACHE                  0xe7    /* flush cache to disk */
#define ATA_WRITE_BUFFER                0xe8    /* write buffer */
#define ATA_WRITE_PM                    0xe8    /* write portmultiplier */
#define ATA_READ_BUFFER_DMA             0xe9    /* read buffer DMA */
#define ATA_FLUSHCACHE48                0xea    /* flush cache to disk */
#define ATA_WRITE_BUFFER_DMA            0xeb    /* write buffer DMA */
#define ATA_ATA_IDENTIFY                0xec    /* get ATA params */
#define ATA_SETFEATURES                 0xef    /* features command */
#define ATA_CHECK_POWER_MODE            0xe5    /* Check Power Mode */
#define ATA_SECURITY_SET_PASSWORD       0xf1    /* set drive password */
#define ATA_SECURITY_UNLOCK             0xf2    /* unlock drive using passwd */
#define ATA_SECURITY_ERASE_PREPARE      0xf3    /* prepare to erase drive */
#define ATA_SECURITY_ERASE_UNIT         0xf4    /* erase all blocks on drive */
#define ATA_SECURITY_FREEZE_LOCK        0xf5    /* freeze security config */
#define ATA_SECURITY_DISABLE_PASSWORD   0xf6    /* disable drive password */
#define ATA_READ_NATIVE_MAX_ADDRESS     0xf8    /* read native max address */
#define ATA_SET_MAX_ADDRESS             0xf9    /* set max address */

void ata_io_cmd(void *dev, int cmd, void *buf, range blocks, status_handler s);
block_io create_ata_io(heap h, void * dev, int cmd);
