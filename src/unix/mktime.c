#include <kernel.h>
#include <mktime.h>

static int days_in_month(int m) {
    if (m == 2) {
        return 28;
    }
    if (m == 4 || m == 6 || m == 9 || m == 11) {
        return 30;
    }
    return 31;
}

static int is_leap_year(int year) {
    if ((year & 3) != 0) {
        return 0;
    }
    if ((year % 100) != 0) {
        return 1;
    }
    return (year % 400) == 0;
}

int mktime(struct tm *tm) {
    int days = 365 * (tm->tm_year - 70);

    for (int i = 70; i < tm->tm_year; i++) {
        if (is_leap_year(1900 + i)) {
            days++;
        }
    }

    if (is_leap_year(1900 + tm->tm_year) && tm->tm_mon >= 2) {
        days++;
    }

    for (int i = 0; i < tm->tm_mon; i++) {
        days += days_in_month(i + 1);
    }

    days += (tm->tm_mday - 1);

    return ((days * 24 + tm->tm_hour) * 60 + tm->tm_min) * 60 + tm->tm_sec;
}

struct tm *gmtime_r(u64 *timep, struct tm *result) {
    u64 seconds = *timep;
    int days = seconds / (24 * 60 * 60);
    seconds -= days * (24 * 60 * 60);
    result->tm_year = 70;   /* 1970 (Epoch) */
    while (true) {
        int days_in_year = (is_leap_year(1900 + result->tm_year)) ? 366 : 365;
        if (days >= days_in_year) {
            result->tm_year++;
            days -= days_in_year;
        } else {
            break;
        }
    }
    result->tm_mon = 0;
    while (true) {
        int d = days_in_month(result->tm_mon + 1);
        if ((result->tm_mon == 1) && is_leap_year(1900 + result->tm_year))
            d++;
        if (days >= d) {
            result->tm_mon++;
            days -= d;
        } else {
            break;
        }
    }
    result->tm_mday = 1 + days;
    result->tm_hour = seconds / (60 * 60);
    seconds -= result->tm_hour * (60 * 60);
    result->tm_min = seconds / 60;
    result->tm_sec = seconds - result->tm_min * 60;
    return result;
}
KLIB_EXPORT(gmtime_r);
