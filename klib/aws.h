#define AWS_ERR_TOKEN_EXPIRED   "ExpiredTokenException"

boolean aws_metadata_available(void);
void aws_metadata_get(heap h, const char *uri, buffer_handler handler);

static inline void aws_region_get(heap h, buffer_handler handler)
{
    aws_metadata_get(h, "/latest/meta-data/placement/region", handler);
}

static inline void aws_hostname_get(heap h, buffer_handler handler)
{
    aws_metadata_get(h, "/latest/meta-data/hostname", handler);
}

typedef struct aws_cred {
    buffer access_key;
    buffer secret;
    buffer token;
} *aws_cred;
typedef closure_type(aws_cred_handler, void, aws_cred);
void aws_cred_get(heap h, aws_cred_handler handler);

void aws_req_set_date(tuple req, buffer b);

buffer aws_req_sign(heap h, const char *region, const char *service, const char *method,
                    tuple req, buffer body, const char *access_key, const char *secret);
