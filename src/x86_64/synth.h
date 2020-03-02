typedef u8 reg;

void mov_64_imm(buffer b, reg r, u64 imm);
void mov_32_imm(buffer b, reg r, u32 imm);
void jump_indirect(buffer b, reg r);
void indirect_displacement(buffer b, reg dest, reg source, u32 d);
void indirect_scale(buffer b, reg dest, u32 scale, reg index, reg base);
void debug_trap(buffer b);
void indirect(buffer b, reg dest, reg source);
void jump_indirect(buffer b, reg r);

// definitions in tuple space
//           is callee save        argo 
#if 0
REGISTER_A  false
REGISTER_B  true
REGISTER_C  false syscall_number   3(user)
REGISTER_D  false                  2
REGISTER_DI false                  0
REGISTER_SI false                  1
REGISTER_8  false                  4
REGISTER_9  false                  5
REGISTER_10 false                  3(syscall)
REGISTER_11 false syscall_flags
REGISTER_12 true
REGISTER_13 true
REGISTER_14 true
REGISTER_15 true
#endif
        
#define REGISTER_A  0 
#define REGISTER_B  3 
#define REGISTER_C  1
#define REGISTER_D  2
#define REGISTER_DI 7
#define REGISTER_SI 6
#define REGISTER_BP 5
#define REGISTER_SP 4
#define REGISTER_8  8
#define REGISTER_9  9
#define REGISTER_10 10
#define REGISTER_11 11
#define REGISTER_12 12
#define REGISTER_13 13
#define REGISTER_14 14
#define REGISTER_15 15





