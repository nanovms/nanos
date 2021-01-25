#include <kernel.h>
#include <io.h>

#include "mktime.h"

#define RTC_COMMAND 0x70
#define RTC_DATA 0x71
#define RTC_NMI_DISABLE (1 << 7)
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

static unsigned int bin2bcd(unsigned int bin) {
    unsigned int tens = bin / 10;
    return ((tens << 4) | (bin - tens * 10));
}

static u8 rtc_read(u8 reg) {
    out8(RTC_COMMAND, reg | RTC_NMI_DISABLE);
    return in8(RTC_DATA);
}

static void rtc_write(u8 reg, u8 val) {
    out8(RTC_COMMAND, reg | RTC_NMI_DISABLE);
    out8(RTC_DATA, val);
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
    tm.tm_mon = bcd2bin(rtc_read(RTC_MONTH)) - 1;
    tm.tm_year = bcd2bin(rtc_read(RTC_YEAR)) + 100; /* assume we are in the 21st century */


    return mktime(&tm);
}

void rtc_settimeofday(u64 seconds) {
    /* Fix any possible inconsistencies due to RTC register concurrent updates by looping until the
     * timestamp read from the RTC equals the timestamp being written. */
    while (rtc_gettimeofday() != seconds) {
        struct tm tm;
        gmtime_r(&seconds, &tm);
        rtc_write(RTC_SECONDS, bin2bcd(tm.tm_sec));
        rtc_write(RTC_MINUTES, bin2bcd(tm.tm_min));
        rtc_write(RTC_HOURS, bin2bcd(tm.tm_hour));
        rtc_write(RTC_DAY_OF_MONTH, bin2bcd(tm.tm_mday));
        rtc_write(RTC_MONTH, bin2bcd(tm.tm_mon + 1));
        rtc_write(RTC_YEAR, bin2bcd(tm.tm_year - 100));
    }
}
