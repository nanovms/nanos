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
