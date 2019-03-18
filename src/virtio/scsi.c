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
    assert(length >= 14);
    for (int i = 0; i < MIN(length, 16); i++) {
        bprintf(b, "%s%P", i > 0 ? " " : "", (u64) sense[i]);
    }
    bprintf(b, ": key %P, asc %P/%P",
        (u64) (sense[2] & 0xf), (u64) sense[12], (u64) sense[13]);
}

void scsi_dump_sense(const u8 *sense, int length)
{
    buffer b = little_stack_buffer(1024);
    scsi_bdump_sense(b, sense, length);
    rprintf("sense %b\n", b);
}
