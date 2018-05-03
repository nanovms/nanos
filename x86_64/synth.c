#include <sruntime.h>


void sib(buffer b, u32 scale, u32 index, u32 base)
{
    push_character(b, scale<<6 | index<<3 | base);
}

void modrm(buffer b, u32 mod, u32 reg, u32 rm)
{
    push_character(b, mod<<6 | reg<<3 | rm);
}

void rex(buffer b, boolean width, boolean reg, boolean index, boolean base)
{
    push_character(b, 0x40 | (width<<3) | (reg <<2) | (index <<1) | base);
}

void mov_64_imm(buffer b, reg r, u64 imm)
{
    rex(b, true, false, false, false);
    push_character(b, 0xb8 + r);
    buffer_write_le64(b, imm);
}

void jump_indirect(buffer b, reg r)
{
    push_character(b, 0xff);
    // was modrm 0xe0? 
    push_character(b, 0x20 + r);    
}

void indirect_displacement(buffer b, reg dest, reg source, u32 d)
{
    rex(b, 1, 0, 0, 0);
    push_character(b, 0x8b);
    rprintf ("kil %d\n", d);
    // mode 1 is single trailing byte of displacment
    // signed? I guesso
    if (d < 128) {
        modrm(b, 1, dest, source);
        push_character(b, d);        
    } else {
        // mode 2 is 32 bit word of displacment        
        modrm(b, 2, dest, source);
        buffer_write_le32(b, d);        
    }
}

#define SIB_FOLLOWS_REGISTER 0x4
// d = a + b * 2^s
void indirect_scale(buffer b, reg dest, u32 scale, reg index, reg base)
{
    rex(b, 1, 0, 0, 0);
    push_character(b, 0x8b);
    modrm(b, 0, dest, SIB_FOLLOWS_REGISTER);
    sib(b, scale, index, base);
}

