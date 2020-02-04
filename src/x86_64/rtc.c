#include <kernel.h>
#include <io.h>

#include "mktime.h"

#define RTC_COMMAND 0x70
#define RTC_DATA 0x71
#define RTC_NMI_DISABLE (1 << 8)
#define RTC_NMI_ENABLE 0
#define RTC_SECONDS 0x00
#define RTC_MINUTES 0x02
#define RTC_HOURS 0x04
#define RTC_DAY_OF_MONTH 0x07
#define RTC_MONTH 0x08
#define RTC_YEAR 0x09
#define RTC_STATUS_A 0x0a
#define RTC_UIP (1 << 7)

static unsigned int bcd2bin(unsigned int bcd) {
    return ((bcd >> 4) & 0x0f) * 10 + (bcd & 0x0f);
}

static u8 rtc_read(u8 reg) {
    out8(RTC_COMMAND, reg | RTC_NMI_DISABLE);
    return in8(RTC_DATA);
}

u64 rtc_gettimeofday(void) {
    while (rtc_read(RTC_STATUS_A) & RTC_UIP) {
        continue;
    }

    struct tm tm;

    tm.tm_sec = bcd2bin(rtc_read(RTC_SECONDS));
    tm.tm_min = bcd2bin(rtc_read(RTC_MINUTES));
    tm.tm_hour = bcd2bin(rtc_read(RTC_HOURS));
    tm.tm_mday = bcd2bin(rtc_read(RTC_DAY_OF_MONTH));
    tm.tm_mon = bcd2bin(rtc_read(RTC_MONTH));
    tm.tm_year = bcd2bin(rtc_read(RTC_YEAR)) + 2000;


    return mktime(&tm);
}

