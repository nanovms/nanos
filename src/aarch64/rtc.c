/* PrimeCell RTC (PL031) */
#include <kernel.h>
#include "mktime.h"

//#define RTC_DEBUG
#ifdef RTC_DEBUG
#define rtc_debug(x, ...) do {rprintf("RTC:  " x, ##__VA_ARGS__);} while(0)
#else
#define rtc_debug(x, ...)
#endif

#define rtc_reg(offset) (*(volatile u32 *)pointer_from_u64(mmio_base_addr(RTC) + offset))
#define RTCDR           rtc_reg(0x000) /* data */
#define RTCMR           rtc_reg(0x004) /* match */
#define RTCLR           rtc_reg(0x008) /* load */
#define RTCCR           rtc_reg(0x00c) /* control */
#define RTCIMSC         rtc_reg(0x010) /* interrupt mask set or clear */
#define RTCRIS          rtc_reg(0x014) /* raw interrupt status */
#define RTCMIS          rtc_reg(0x018) /* masked interrupt status */
#define RTCICR          rtc_reg(0x01c) /* interrupt clear */
#define RTCPeriphID0    rtc_reg(0xfe0) /* peripheral ID bits [7:0] */
#define RTCPeriphID1    rtc_reg(0xfe4) /* peripheral ID bits [15:8] */
#define RTCPeriphID2    rtc_reg(0xfe8) /* peripheral ID bits [23:16] */
#define RTCPeriphID3    rtc_reg(0xfec) /* peripheral ID bits [31:24] */
#define RTCPCellID0     rtc_reg(0xff0) /* PrimeCell ID bits [7:0] */
#define RTCPCellID1     rtc_reg(0xff4) /* PrimeCell ID bits [7:0] */
#define RTCPCellID2     rtc_reg(0xff8) /* PrimeCell ID bits [7:0] */
#define RTCPCellID3     rtc_reg(0xffc) /* PrimeCell ID bits [7:0] */

#define RTCPeriphID0_val  0x31
#define RTCPeriphID1_val  0x10
#define RTCPeriphID2_mask 0x0f
#define RTCPeriphID2_val  0x04
#define RTCPeriphID3_val  0x00

#define RTCPCellID0_val 0x0d
#define RTCPCellID1_val 0xf0
#define RTCPCellID2_val 0x05
#define RTCPCellID3_val 0xb1

static boolean rtc_detect(void)
{
    static boolean probed = false;
    static boolean detected = false;
    if (!probed) {
        probed = true;
        if (RTCPeriphID0 != RTCPeriphID0_val ||
            RTCPeriphID1 != RTCPeriphID1_val ||
            (RTCPeriphID2 & RTCPeriphID2_mask) != RTCPeriphID2_val ||
            RTCPeriphID3 != RTCPeriphID3_val ||
            RTCPCellID0 != RTCPCellID0_val ||
            RTCPCellID1 != RTCPCellID1_val ||
            RTCPCellID2 != RTCPCellID2_val ||
            RTCPCellID3 != RTCPCellID3_val) {
            msg_err("no PL031 RTC detected\n");
        } else {
            rtc_debug("PL031 RTC detected\n");
            detected = true;
        }
    }
    return detected;
}

u64 rtc_gettimeofday(void) {
    if (!rtc_detect())
        return 0;
    u64 seconds = RTCDR;
    rtc_debug("%s: returning %ld seconds\n", __func__, seconds);
    return seconds;
}

void rtc_settimeofday(u64 seconds) {
    rtc_debug("%s: setting rtc to %ld seconds\n", __func__, seconds);
    if (rtc_detect())
        RTCLR = seconds;
}
