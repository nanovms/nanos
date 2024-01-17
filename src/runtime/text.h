// would like to call this string.h, but unix programs
// are pretty stubborn, in this case lwip

#define CHARACTER_INVALID 0xfffffffful

typedef buffer string;

static inline s8 digit_of(character x)
{
    if ((x <= 'f') && (x >= 'a')) return(x - 'a' + 10);
    if ((x <= 'F') && (x >= 'A')) return(x - 'A' + 10);
    if ((x <= '9') && (x >= '0')) return(x - '0');
    return(-1);
}

static inline int byte_from_hex(character msn, character lsn)
{
    s8 n1, n2;
    if (((n1 = digit_of(msn)) < 0) || ((n2 = digit_of(lsn)) < 0))
        return -1;
    return ((n1 << 4) | n2);
}

static inline int buf_hex_cmp(const u8 *buf, const char *hex, bytes n)
{
    for (bytes i = 0; i < n; i++) {
        int b = byte_from_hex(hex[2 * i], hex[2 * i + 1]);
        if (b < 0)
            return b;
        else if ((u8)b != buf[i])
            return (buf[i] - b);
    }
    return 0;
}

static inline bytes utf8_length(unsigned char x)
{
    if (~x & 0x80) return 1;
    if ((x & 0xe0) == 0xc0) return 2;
    if ((x & 0xf0) == 0xe0) return 3;
    if ((x & 0xf8) == 0xf0) return 4;
    // help
    return(1);
}

// this is not the most effective implementation
static int inline string_character_length(char *s) {
    int i = 0, j= 0;
    while (s[i]) {
        if ((s[i] & 0xC0) != 0x80)
            j++;
        i++;
    }
    return (j);
}

// specialized bytewise memcpy, since this is between 1 and 4

#define string_foreach(__i, __s)                                    \
    for (character __i; __i = pop_character(__s), __i != CHARACTER_INVALID;)


static inline character utf8_decode(sstring x, int *count)
{
    if (sstring_is_empty(x))
        goto error;
    bytes len = utf8_length(x.ptr[0]);
    if (x.len < len)
        goto error;
    character c;
    switch (len) {
    case 1:
        c = x.ptr[0];
        break;
    case 2:
        c = x.ptr[0] & 0x3f;
        break;
    case 3:
        c = x.ptr[0] & 0x1f;
        break;
    case 4:
        c = x.ptr[0] & 0xf;
        break;
    default:
        goto error;
    }
    for (bytes i = 1; i < len; i++)
        c = (c << 6) | (x.ptr[i] & 0x3f);
    *count = len;
    return c;
    
  error:
    *count = 0;
    return CHARACTER_INVALID;
}

static inline boolean push_character(string s, character c)
{
    if (c<0x80) {
        return buffer_write_byte(s, c);
    } else if (c<0x800) {
        return buffer_write_byte(s, 0xc0 | (c>>6)) &&
               buffer_write_byte(s, 0x80 | (c&0x3f));
    } else if (c<0x10000) {
        return buffer_write_byte(s, 0xe0 | (c>>12)) &&
               buffer_write_byte(s, 0x80 | ((c>>6) & 0x3f)) &&
               buffer_write_byte(s, 0x80 | (c&0x3f));
    } else if (c<0x110000) {
        return buffer_write_byte(s, 0xf0 | (c>>18)) &&
               buffer_write_byte(s, 0x80 | ((c>>12)&0x3f)) &&
               buffer_write_byte(s, 0x80 | ((c>>6)&0x3f)) &&
               buffer_write_byte(s, 0x80 | (c&0x3f));
    }
    return false;
}

static inline character pop_character(buffer b)
{
    int z;
    character c = utf8_decode(buffer_to_sstring(b), &z);
    b->start += z;
    return c;
}

static inline boolean read_cstring(buffer b, char *dest, bytes maxlen)
{
    bytes count = 0;
    u8 c;
    do {
        if (buffer_length(b) == 0)
            return false;
        c = *(u8 *)buffer_ref(b, 0);
        bytes len = utf8_length(c);
        if ((len > maxlen - count) || !buffer_read(b, dest + count, len))
            return false;
        count += len;
    } while (c);
    return true;
}

// status
static inline boolean parse_int(buffer b, u32 base, u64 *result)
{
  int st = false;
  *result = 0;

  while (buffer_length(b)) {
      s8 v = digit_of(*(u8 *)buffer_ref(b, 0));
      if (v >= 0 && v < base) {
          pop_u8(b);
          st = true;
          *result = (*result * base) + v;
      } else break;
  }
  return st;
}

static inline boolean is_signed_int_string(buffer b)
{
    return buffer_length(b) > 0 && *(u8 *)buffer_ref(b, 0) == '-';
}

static inline boolean parse_signed_int(buffer b, u32 base, s64 *result)
{
  int sign = 1;

  if (is_signed_int_string(b)) {
    sign = -1;
    pop_u8(b);
  }

  if (!parse_int(b, base, (u64 *)result))
    return false;
  *result *= sign;
  return true;
}

static inline const u8 *utf8_find_r(sstring x, character c)
{
    int nbytes;
    bytes offset = 0;
    const u8 *found = false;

    while (1) {
        sstring s = isstring(x.ptr + offset, x.len - offset);
        character decoded = utf8_decode(s, &nbytes);
        if (decoded == CHARACTER_INVALID)
            break;
        if (decoded == c)
            found = (u8 *)s.ptr;
        offset += nbytes;
    }
    return found;
}
