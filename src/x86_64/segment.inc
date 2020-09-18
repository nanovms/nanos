%define SEG_DESC_G          (1 << 23) ; Granularity
%define SEG_DESC_DB         (1 << 22) ; Code: default size, Data: big
%define SEG_DESC_L          (1 << 21) ; Code: Long (64-bit)
%define SEG_DESC_AVL        (1 << 20) ; Available
%define SEG_DESC_P          (1 << 15) ; Present
%define SEG_DESC_DPL_SHIFT  13
%define SEG_DESC_S          (1 << 12) ; Code/data (vs sys)
%define SEG_DESC_CODE       (1 << 11) ; Code descriptor type (vs data)
%define SEG_DESC_C          (1 << 10) ; Conforming
%define SEG_DESC_RW         (1 << 9)  ; Code: readable, Data: writeable
%define SEG_DESC_A          (1 << 8)  ; Accessed

%define KERN_CODE_SEG_DESC  (SEG_DESC_L | SEG_DESC_P | SEG_DESC_S | SEG_DESC_CODE | SEG_DESC_RW)
%define KERN_DATA_SEG_DESC  (SEG_DESC_P | SEG_DESC_S | SEG_DESC_RW)
%define USER_CODE_SEG_DESC  (SEG_DESC_L | SEG_DESC_P | (3 << SEG_DESC_DPL_SHIFT) | SEG_DESC_S | SEG_DESC_CODE | SEG_DESC_RW)
%define USER_DATA_SEG_DESC  (SEG_DESC_S | (3 << SEG_DESC_DPL_SHIFT) | SEG_DESC_P | SEG_DESC_RW)
