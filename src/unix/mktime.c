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
    int days = 365 * (tm->tm_year - 1970);

    for (int i = 1970; i < tm->tm_year; i++) {
        if (is_leap_year(i)) {
            days++;
        }
    }

    if (is_leap_year(tm->tm_year) && tm->tm_mon > 2) {
        days++;
    }

    for (int i = 1; i < tm->tm_mon; i++) {
        days += days_in_month(i);
    }

    days += (tm->tm_mday - 1);

    return ((days * 24 + tm->tm_hour) * 60 + tm->tm_min) * 60 + tm->tm_sec;
}
