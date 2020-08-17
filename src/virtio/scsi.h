/*
 * Status Byte
 */
#define SCSI_STATUS_OK                  0x00
#define SCSI_STATUS_CHECK_COND          0x02
#define SCSI_STATUS_COND_MET            0x04
#define SCSI_STATUS_BUSY                0x08
#define SCSI_STATUS_INTERMED            0x10
#define SCSI_STATUS_INTERMED_COND_MET   0x14
#define SCSI_STATUS_RESERV_CONFLICT     0x18
#define SCSI_STATUS_CMD_TERMINATED      0x22    /* Obsolete in SAM-2 */
#define SCSI_STATUS_QUEUE_FULL          0x28
#define SCSI_STATUS_ACA_ACTIVE          0x30
#define SCSI_STATUS_TASK_ABORTED        0x40

/*
 * Fixed format sense data.
 *
 * For Hyper-V compatibility this structure omits extra_bytes field,
 * see struct scsi_sense_data_extra
 *
 */
struct scsi_sense_data
{
	u8 error_code;
#define	SSD_ERRCODE			0x7F
#define		SSD_CURRENT_ERROR	0x70
#define		SSD_DEFERRED_ERROR	0x71
#define	SSD_ERRCODE_VALID	0x80
	u8 segment;
	u8 flags;
#define	SSD_KEY				0x0F
#define		SSD_KEY_NO_SENSE	0x00
#define		SSD_KEY_RECOVERED_ERROR	0x01
#define		SSD_KEY_NOT_READY	0x02
#define		SSD_KEY_MEDIUM_ERROR	0x03
#define		SSD_KEY_HARDWARE_ERROR	0x04
#define		SSD_KEY_ILLEGAL_REQUEST	0x05
#define		SSD_KEY_UNIT_ATTENTION	0x06
#define		SSD_KEY_DATA_PROTECT	0x07
#define		SSD_KEY_BLANK_CHECK	0x08
#define		SSD_KEY_Vendor_Specific	0x09
#define		SSD_KEY_COPY_ABORTED	0x0a
#define		SSD_KEY_ABORTED_COMMAND	0x0b
#define		SSD_KEY_EQUAL		0x0c
#define		SSD_KEY_VOLUME_OVERFLOW	0x0d
#define		SSD_KEY_MISCOMPARE	0x0e
#define		SSD_KEY_COMPLETED	0x0f
#define	SSD_SDAT_OVFL	0x10
#define	SSD_ILI		0x20
#define	SSD_EOM		0x40
#define	SSD_FILEMARK	0x80
	u8 info[4];
	u8 extra_len;
	u8 cmd_spec_info[4];
	u8 asc;
	u8 ascq;
	u8 fru;
	u8 sense_key_spec[3];
} __attribute__((packed));

/*
 * Fixed format sense data with extra_bytes
 */
struct scsi_sense_data_extra {
	struct scsi_sense_data sense;
#define	SSD_SCS_VALID		0x80
#define	SSD_FIELDPTR_CMD	0x40
#define	SSD_BITPTR_VALID	0x08
#define	SSD_BITPTR_VALUE	0x07
	u8 extra_bytes[14];
} __attribute__((packed));

#define SCSI_CMD_TEST_UNIT_READY        0x00
#define SCSI_CMD_INQUIRY                0x12
#define SCSI_CMD_READ_16                0x88
#define SCSI_CMD_WRITE_16               0x8a
#define SCSI_CMD_SERVICE_ACTION         0x9e
#define SCSI_CMD_REPORT_LUNS            0xa0

struct scsi_cdb_test_unit_ready
{
    u8 opcode;
    u8 byte2;
    u8 unused[3];
    u8 control;
} __attribute__((packed));

struct scsi_cdb_inquiry
{
    u8 opcode;
    u8 byte2;
#define SI_EVPD                 0x01
#define SI_CMDDT                0x02
    u8 page_code;
    u16 length;
    u8 control;
} __attribute__((packed));

struct scsi_res_inquiry
{
    u8 device;
#define SID_TYPE(inq_data) ((inq_data)->device & 0x1f)
#define SID_QUAL(inq_data) (((inq_data)->device & 0xE0) >> 5)
#define SID_QUAL_LU_CONNECTED   0x00    /*
                     * The specified peripheral device
                     * type is currently connected to
                     * logical unit.  If the target cannot
                     * determine whether or not a physical
                     * device is currently connected, it
                     * shall also use this peripheral
                     * qualifier when returning the INQUIRY
                     * data.  This peripheral qualifier
                     * does not mean that the device is
                     * ready for access by the initiator.
                     */
#define SID_QUAL_LU_OFFLINE     0x01    /*
                     * The target is capable of supporting
                     * the specified peripheral device type
                     * on this logical unit; however, the
                     * physical device is not currently
                     * connected to this logical unit.
                     */
#define SID_QUAL_RSVD           0x02
#define SID_QUAL_BAD_LU         0x03    /*
                     * The target is not capable of
                     * supporting a physical device on
                     * this logical unit. For this
                     * peripheral qualifier the peripheral
                     * device type shall be set to 1Fh to
                     * provide compatibility with previous
                     * versions of SCSI. All other
                     * peripheral device type values are
                     * reserved for this peripheral
                     * qualifier.
                     */
#define SID_QUAL_IS_VENDOR_UNIQUE(inq_data) ((SID_QUAL(inq_data) & 0x04) != 0)
    u8 dev_qual2;
#define SID_QUAL2               0x7F
#define SID_LU_CONG             0x40
#define SID_RMB                 0x80
#define SID_IS_REMOVABLE(inq_data) (((inq_data)->dev_qual2 & SID_RMB) != 0)
    u8 version;
#define SID_ANSI_REV(inq_data) ((inq_data)->version & 0x07)
#define SCSI_REV_0              0
#define SCSI_REV_CCS            1
#define SCSI_REV_2              2
#define SCSI_REV_SPC            3
#define SCSI_REV_SPC2           4
#define SCSI_REV_SPC3           5
#define SCSI_REV_SPC4           6
#define SCSI_REV_SPC5           7

#define SID_ECMA                0x38
#define SID_ISO                 0xC0
    u8 response_format;
#define SID_AENC                0x80
#define SID_TrmIOP              0x40
#define SID_NormACA             0x20
#define SID_HiSup               0x10
    u8 additional_length;
#define SID_ADDITIONAL_LENGTH(iqd)                    \
        ((iqd)->additional_length +                   \
        offsetof(struct scsi_inquiry_data *, additional_length) + 1)
    u8 spc3_flags;
#define SPC3_SID_PROTECT        0x01
#define SPC3_SID_3PC            0x08
#define SPC3_SID_TPGS_MASK      0x30
#define SPC3_SID_TPGS_IMPLICIT  0x10
#define SPC3_SID_TPGS_EXPLICIT  0x20
#define SPC3_SID_ACC            0x40
#define SPC3_SID_SCCS           0x80
    u8 spc2_flags;
#define SPC2_SID_ADDR16         0x01
#define SPC2_SID_MChngr         0x08
#define SPC2_SID_MultiP         0x10
#define SPC2_SID_EncServ        0x40
#define SPC2_SID_BQueue         0x80

#define INQ_DATA_TQ_ENABLED(iqd)                \
    ((SID_ANSI_REV(iqd) < SCSI_REV_SPC2)? ((iqd)->flags & SID_CmdQue) :    \
    (((iqd)->flags & SID_CmdQue) && !((iqd)->spc2_flags & SPC2_SID_BQueue)) || \
    (!((iqd)->flags & SID_CmdQue) && ((iqd)->spc2_flags & SPC2_SID_BQueue)))

    u8 flags;
#define SID_SftRe               0x01
#define SID_CmdQue              0x02
#define SID_Linked              0x08
#define SID_Sync                0x10
#define SID_WBus16              0x20
#define SID_WBus32              0x40
#define SID_RelAdr              0x80
#define SID_VENDOR_SIZE         8
    char vendor[SID_VENDOR_SIZE];
#define SID_PRODUCT_SIZE        16
    char product[SID_PRODUCT_SIZE];
#define SID_REVISION_SIZE       4
    char revision[SID_REVISION_SIZE];
    /*
     * The following fields were taken from SCSI Primary Commands - 2
     * (SPC-2) Revision 14, Dated 11 November 1999
     */
#define SID_VENDOR_SPECIFIC_0_SIZE      20
    u8 vendor_specific0[SID_VENDOR_SPECIFIC_0_SIZE];
    /*
     * An extension of SCSI Parallel Specific Values
     */
#define SID_SPI_IUS             0x01
#define SID_SPI_QAS             0x02
#define SID_SPI_CLOCK_ST        0x00
#define SID_SPI_CLOCK_DT        0x04
#define SID_SPI_CLOCK_DT_ST     0x0C
#define SID_SPI_MASK            0x0F
    u8 spi3data;
    u8 reserved2;
    /*
     * Version Descriptors, stored 2 byte values.
     */
    u8 version1[2];
    u8 version2[2];
    u8 version3[2];
    u8 version4[2];
    u8 version5[2];
    u8 version6[2];
    u8 version7[2];
    u8 version8[2];

    u8 reserved3[22];

#define SID_VENDOR_SPECIFIC_1_SIZE      160
    u8 vendor_specific1[SID_VENDOR_SPECIFIC_1_SIZE];
} __attribute__((packed));

struct scsi_cdb_readwrite_16
{
    u8 opcode;
#define SRW16_RELADDR   0x01
#define SRW16_FUA       0x08
#define SRW16_DPO       0x10
    u8 byte2;
    u64 addr;
    u32 length;
    u8 reserved;
    u8 control;
} __attribute__((packed));

struct scsi_cdb_read_capacity_16
{
    u8 opcode;
#define SRC16_SERVICE_ACTION    0x10
    u8 service_action;
    u8 addr[8];
    u32 alloc_len;
#define SRC16_PMI               0x01
#define SRC16_RELADDR           0x02
    u8 reladr;
    u8 control;
} __attribute__((packed));

struct scsi_res_read_capacity_16
{
    u64 addr;
    u32 length;
#define SRC16_PROT_EN           0x01
#define SRC16_P_TYPE            0x0e
#define SRC16_PTYPE_1           0x00
#define SRC16_PTYPE_2           0x02
#define SRC16_PTYPE_3           0x04
    u8 prot;
#define SRC16_LBPPBE            0x0f
#define SRC16_PI_EXPONENT       0xf0
#define SRC16_PI_EXPONENT_SHIFT 4
    u8 prot_lbppbe;
#define SRC16_LALBA             0x3f
#define SRC16_LBPRZ             0x40
#define SRC16_LBPME             0x80
/*
 * Alternate versions of these macros that are intended for use on a 16-bit
 * version of the lalba_lbp field instead of the array of 2 8 bit numbers.
 */
#define SRC16_LALBA_A           0x3fff
#define SRC16_LBPRZ_A           0x4000
#define SRC16_LBPME_A           0x8000
    u16 lalba_lbp;
    u8 reserved[16];
} __attribute__((packed));

struct scsi_cdb_report_luns
{
    u8 opcode;
    u8 reserved1;
#define RPL_REPORT_DEFAULT      0x00
#define RPL_REPORT_WELLKNOWN    0x01
#define RPL_REPORT_ALL          0x02
#define RPL_REPORT_ADMIN        0x10
#define RPL_REPORT_NONSUBSID    0x11
#define RPL_REPORT_CONGLOM      0x12
    u8 select_report;
    u8 reserved2[3];
    u32 length;
    u8 reserved3;
    u8 control;
} __attribute__((packed));

struct scsi_res_report_luns
{
    u32 length;
    u32 reserved;
    u64 lundata[256];
} __attribute__((packed));

int scsi_data_len(u8 cmd);

void scsi_dump_sense(const u8 *sense, int length);
