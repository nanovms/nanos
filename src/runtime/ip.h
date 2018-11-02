static boolean parse_v4_address(buffer b, u32 *u)
{
    u64 a;
    *u = 0;
    parse_int(b, 10, &a);  *u = (*u<<8)|a;
    if (pop_u8(b) != '.') return false;
    parse_int(b, 10, &a);  *u = (*u<<8)|a;    
    if (pop_u8(b) != '.') return false;
    parse_int(b, 10, &a);  *u = (*u<<8)|a;        
    if (pop_u8(b) != '.') return false;
    parse_int(b, 10, &a);  *u = (*u<<8)|a;
    return true;
}

static boolean parse_v4_address_and_port(buffer b, u32 *u, u16 *port)
{
    u64 a;
    if (!parse_v4_address(b, u)) return false;
    if (pop_u8(b) != ':') return false;    
    parse_int(b, 10, &a);
    *port = (u16)a;
    return true;
}
