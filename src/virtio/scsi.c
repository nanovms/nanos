#include <runtime.h>
#include <scsi.h>

int scsi_data_len(u8 cmd)
{
    switch (cmd) {
    case SCSI_CMD_INQUIRY:
        return sizeof(struct scsi_res_inquiry);
    case SCSI_CMD_SERVICE_ACTION:
        return sizeof(struct scsi_res_read_capacity_16);
    case SCSI_CMD_REPORT_LUNS:
        return sizeof(struct scsi_res_report_luns);
    default:
        return 0;
    }
}

static void scsi_bdump_sense(buffer b, const u8 *sense, int length)
{
    assert(length >= sizeof(struct scsi_sense_data));
    for (int i = 0; i < sizeof(struct scsi_sense_data); i++) {
        bprintf(b, "%s%P", i > 0 ? " " : "", (u64) sense[i]);
    }
    struct scsi_sense_data *ssd = (struct scsi_sense_data *) sense;
    bprintf(b, ": KEY %P, ASC/ASCQ %P/%P",
        (u64) (ssd->flags & SSD_KEY), (u64) ssd->asc, (u64) ssd->ascq);
}

void scsi_dump_sense(const u8 *sense, int length)
{
    buffer b = little_stack_buffer(1024);
    scsi_bdump_sense(b, sense, length);
    rprintf("SCSI SENSE %b\n", b);
}
