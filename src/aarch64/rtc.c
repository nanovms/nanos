/* PrimeCell RTC (PL031) */
#include <kernel.h>
#include <boot/uefi.h>
#include "mktime.h"

//#define RTC_DEBUG
#ifdef RTC_DEBUG
#define rtc_debug(x, ...) do {rprintf("RTC:  " x, ##__VA_ARGS__);} while(0)
#else
#define rtc_debug(x, ...)
#endif

#define rtc_reg(offset) (*(volatile u32 *)pointer_from_u64(mmio_base_addr(RTC) + offset))
#define rtc_reg8(offset)    (*(volatile u8 *)pointer_from_u64(mmio_base_addr(RTC) + offset))
#define RTCDR           rtc_reg(0x000) /* data */
#define RTCMR           rtc_reg(0x004) /* match */
#define RTCLR           rtc_reg(0x008) /* load */
#define RTCCR           rtc_reg(0x00c) /* control */
#define RTCIMSC         rtc_reg(0x010) /* interrupt mask set or clear */
#define RTCRIS          rtc_reg(0x014) /* raw interrupt status */
#define RTCMIS          rtc_reg(0x018) /* masked interrupt status */
#define RTCICR          rtc_reg(0x01c) /* interrupt clear */
#define RTCPeriphID0    rtc_reg8(0xfe0) /* peripheral ID bits [7:0] */
#define RTCPeriphID1    rtc_reg8(0xfe4) /* peripheral ID bits [15:8] */
#define RTCPeriphID2    rtc_reg8(0xfe8) /* peripheral ID bits [23:16] */
#define RTCPeriphID3    rtc_reg8(0xfec) /* peripheral ID bits [31:24] */
#define RTCPCellID0     rtc_reg8(0xff0) /* PrimeCell ID bits [7:0] */
#define RTCPCellID1     rtc_reg8(0xff4) /* PrimeCell ID bits [7:0] */
#define RTCPCellID2     rtc_reg8(0xff8) /* PrimeCell ID bits [7:0] */
#define RTCPCellID3     rtc_reg8(0xffc) /* PrimeCell ID bits [7:0] */

#define RTCPeriphID0_val  0x31
#define RTCPeriphID1_val  0x10
#define RTCPeriphID2_mask 0x0f
#define RTCPeriphID2_val  0x04
#define RTCPeriphID3_val  0x00

#define RTCPCellID0_val 0x0d
#define RTCPCellID1_val 0xf0
#define RTCPCellID2_val 0x05
#define RTCPCellID3_val 0xb1

static BSS_RO_AFTER_INIT struct {
    u64 (*get_seconds)(void);
    boolean (*set_seconds)(u64 secs);
    boolean probed;
} rtc;

static u64 pl031_get_seconds(void)
{
    return RTCDR;
}

static boolean pl031_set_seconds(u64 secs)
{
    RTCLR = secs;
    return true;
}

static u64 efi_rt_get_seconds(void)
{
    struct efi_time efi_tm;
    if (boot_params.efi_rt_svc->get_time(&efi_tm, 0) != EFI_SUCCESS)
        return 0;
    struct tm tm;
    tm.tm_year = efi_tm.year - 1900;
    tm.tm_mon = efi_tm.month - 1;
    tm.tm_mday = efi_tm.day;
    tm.tm_hour = efi_tm.hour;
    tm.tm_min = efi_tm.minute;
    tm.tm_sec = efi_tm.second;
    return mktime(&tm);
}

static boolean efi_rt_set_seconds(u64 secs)
{
    struct tm tm;
    gmtime_r(&secs, &tm);
    struct efi_time efi_tm;
    efi_tm.year = tm.tm_year + 1900;
    efi_tm.month = tm.tm_mon + 1;
    efi_tm.day = tm.tm_mday;
    efi_tm.hour = tm.tm_hour;
    efi_tm.minute = tm.tm_min;
    efi_tm.second = tm.tm_sec;
    efi_tm.nanosecond = 0;
    efi_tm.timezone = EFI_UNSPECIFIED_TIMEZONE;
    efi_tm.daylight = 0;
    return (boot_params.efi_rt_svc->set_time(&efi_tm) == EFI_SUCCESS);
}

static boolean rtc_detect(void)
{
    if (!rtc.probed) {
        rtc.probed = true;
        if (RTCPeriphID0 != RTCPeriphID0_val ||
            RTCPeriphID1 != RTCPeriphID1_val ||
            (RTCPeriphID2 & RTCPeriphID2_mask) != RTCPeriphID2_val ||
            RTCPeriphID3 != RTCPeriphID3_val ||
            RTCPCellID0 != RTCPCellID0_val ||
            RTCPCellID1 != RTCPCellID1_val ||
            RTCPCellID2 != RTCPCellID2_val ||
            RTCPCellID3 != RTCPCellID3_val) {
            struct efi_time tm;
            if (boot_params.efi_rt_svc &&
                (boot_params.efi_rt_svc->get_time(&tm, 0) == EFI_SUCCESS)) {
                rtc_debug("using UEFI runtime services\n");
                rtc.get_seconds = efi_rt_get_seconds;
                rtc.set_seconds = efi_rt_set_seconds;
                return true;
            }
        } else {
            rtc_debug("PL031 RTC detected\n");
            rtc.get_seconds = pl031_get_seconds;
            rtc.set_seconds = pl031_set_seconds;
            return true;
        }
        msg_err("RTC not detected");
    }
    return !!rtc.get_seconds;
}

u64 rtc_gettimeofday(void) {
    if (!rtc_detect())
        return 0;
    u64 seconds = rtc.get_seconds();
    rtc_debug("%s: returning %ld seconds\n", func_ss, seconds);
    return seconds;
}

void rtc_settimeofday(u64 seconds) {
    rtc_debug("%s: setting rtc to %ld seconds\n", func_ss, seconds);
    if (rtc_detect())
        rtc.set_seconds(seconds);
}

void kaslr_fixup_rtc(void)
{
    if (rtc.get_seconds) {
        u64 addr_offset = kas_kern_offset - kernel_phys_offset;
        rtc.get_seconds += addr_offset;
        rtc.set_seconds += addr_offset;
    }
}
