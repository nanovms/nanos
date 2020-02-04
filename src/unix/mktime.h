struct tm {
    int tm_year;
    u8 tm_mon;
    u8 tm_mday;
    u8 tm_hour;
    u8 tm_min;
    u8 tm_sec;
};

extern int mktime(struct tm *tm);
