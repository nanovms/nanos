#ifndef AZURE_H_
#define AZURE_H_

typedef struct azure_ext {
    sstring name;
    sstring version;
    status s;
    u64 cfg_seconds;
    u64 cfg_seqno;
} *azure_ext;

boolean azure_register_ext(azure_ext ext);

#endif
