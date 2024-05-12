#ifndef AZURE_H_
#define AZURE_H_

typedef struct azure_ext {
    sstring name;
    sstring version;
    status s;
    u64 cfg_seconds;
    u64 cfg_seqno;
} *azure_ext;

closure_type(az_instance_md_handler, void, tuple md);

boolean azure_register_ext(azure_ext ext);

int azure_diag_init(tuple cfg);

void azure_instance_md_get(az_instance_md_handler complete);

void iso8601_write_interval(timestamp interval, buffer out);

#endif
