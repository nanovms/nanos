#include <sruntime.h>

//48 b8 ab ab 43 43 a5 a5 fe fe 	// movabs $0xfefea5a54343abab,%rax


void rex(buffer b, boolean width, boolean reg, boolean index, boolean base)
{
    push_character(b, 0x40 | (width<<3) | (reg <<2) | (index <<1) | base);
}

void mov_64_imm(buffer b, int regno, u64 imm)
{
    rex(b, true, false, false, false);
    push_character(b, 0xb8 + regno);
    buffer_write_le64(b, imm);
}

void jump_indirect(buffer b, int regno)
{
    push_character(b, 0xff);
    // modrm
    push_character(b, 0xe0 + regno);    
}

