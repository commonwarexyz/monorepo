// Copyright Supranational LLC. Licensed under Apache-2.0; see LICENSE-BLST.
// blst 0.3.16 ARM ELF word routines; private symbol prefix only after preprocessing.
.text
.globl cw_word384_add_mod_384
.hidden cw_word384_add_mod_384
.type cw_word384_add_mod_384,%function
.align 5
cw_word384_add_mod_384:
 hint #25
 stp x29,x30,[sp,#-6*8]!
 add x29,sp,#0
 stp x19,x20,[sp,#2*8]
 stp x21,x22,[sp,#4*8]
 ldp x4,x5,[x3]
 ldp x6,x7,[x3,#16]
 ldp x8,x9,[x3,#32]
 bl cw_word384___add_mod_384
 ldr x30,[sp,#8]
 stp x10,x11,[x0]
 stp x12,x13,[x0,#16]
 stp x14,x15,[x0,#32]
 ldp x19,x20,[x29,#2*8]
 ldp x21,x22,[x29,#4*8]
 ldr x29,[sp],#6*8
 hint #29
 ret
.size cw_word384_add_mod_384,.-cw_word384_add_mod_384
.type cw_word384___add_mod_384,%function
.align 5
cw_word384___add_mod_384:
 ldp x10,x11,[x1]
 ldp x16,x17,[x2]
 ldp x12,x13,[x1,#16]
 ldp x19,x20,[x2,#16]
 ldp x14,x15,[x1,#32]
 ldp x21,x22,[x2,#32]
cw_word384___add_mod_384_ab_are_loaded:
 adds x10,x10,x16
 adcs x11,x11,x17
 adcs x12,x12,x19
 adcs x13,x13,x20
 adcs x14,x14,x21
 adcs x15,x15,x22
 adc x3,xzr,xzr
 subs x16,x10,x4
 sbcs x17,x11,x5
 sbcs x19,x12,x6
 sbcs x20,x13,x7
 sbcs x21,x14,x8
 sbcs x22,x15,x9
 sbcs xzr,x3,xzr
 csel x10,x10,x16,lo
 csel x11,x11,x17,lo
 csel x12,x12,x19,lo
 csel x13,x13,x20,lo
 csel x14,x14,x21,lo
 csel x15,x15,x22,lo
 ret
.size cw_word384___add_mod_384,.-cw_word384___add_mod_384
.globl cw_word384_add_mod_384x
.hidden cw_word384_add_mod_384x
.type cw_word384_add_mod_384x,%function
.align 5
cw_word384_add_mod_384x:
 hint #25
 stp x29,x30,[sp,#-6*8]!
 add x29,sp,#0
 stp x19,x20,[sp,#2*8]
 stp x21,x22,[sp,#4*8]
 ldp x4,x5,[x3]
 ldp x6,x7,[x3,#16]
 ldp x8,x9,[x3,#32]
 bl cw_word384___add_mod_384
 stp x10,x11,[x0]
 add x1,x1,#48
 stp x12,x13,[x0,#16]
 add x2,x2,#48
 stp x14,x15,[x0,#32]
 bl cw_word384___add_mod_384
 ldr x30,[sp,#8]
 stp x10,x11,[x0,#48]
 stp x12,x13,[x0,#64]
 stp x14,x15,[x0,#80]
 ldp x19,x20,[x29,#2*8]
 ldp x21,x22,[x29,#4*8]
 ldr x29,[sp],#6*8
 hint #29
 ret
.size cw_word384_add_mod_384x,.-cw_word384_add_mod_384x
.globl cw_word384_rshift_mod_384
.hidden cw_word384_rshift_mod_384
.type cw_word384_rshift_mod_384,%function
.align 5
cw_word384_rshift_mod_384:
 hint #25
 stp x29,x30,[sp,#-6*8]!
 add x29,sp,#0
 stp x19,x20,[sp,#2*8]
 stp x21,x22,[sp,#4*8]
 ldp x10,x11,[x1]
 ldp x12,x13,[x1,#16]
 ldp x14,x15,[x1,#32]
 ldp x4,x5,[x3]
 ldp x6,x7,[x3,#16]
 ldp x8,x9,[x3,#32]
.Loop_rshift_mod_384:
 sub x2,x2,#1
 bl cw_word384___rshift_mod_384
 cbnz x2,.Loop_rshift_mod_384
 ldr x30,[sp,#8]
 stp x10,x11,[x0]
 stp x12,x13,[x0,#16]
 stp x14,x15,[x0,#32]
 ldp x19,x20,[x29,#2*8]
 ldp x21,x22,[x29,#4*8]
 ldr x29,[sp],#6*8
 hint #29
 ret
.size cw_word384_rshift_mod_384,.-cw_word384_rshift_mod_384
.type cw_word384___rshift_mod_384,%function
.align 5
cw_word384___rshift_mod_384:
 sbfx x22,x10,#0,#1
 and x16,x22,x4
 and x17,x22,x5
 adds x10,x10,x16
 and x19,x22,x6
 adcs x11,x11,x17
 and x20,x22,x7
 adcs x12,x12,x19
 and x21,x22,x8
 adcs x13,x13,x20
 and x22,x22,x9
 adcs x14,x14,x21
 extr x10,x11,x10,#1
 adcs x15,x15,x22
 extr x11,x12,x11,#1
 adc x22,xzr,xzr
 extr x12,x13,x12,#1
 extr x13,x14,x13,#1
 extr x14,x15,x14,#1
 extr x15,x22,x15,#1
 ret
.size cw_word384___rshift_mod_384,.-cw_word384___rshift_mod_384
.globl cw_word384_div_by_2_mod_384
.hidden cw_word384_div_by_2_mod_384
.type cw_word384_div_by_2_mod_384,%function
.align 5
cw_word384_div_by_2_mod_384:
 hint #25
 stp x29,x30,[sp,#-6*8]!
 add x29,sp,#0
 stp x19,x20,[sp,#2*8]
 stp x21,x22,[sp,#4*8]
 ldp x10,x11,[x1]
 ldp x12,x13,[x1,#16]
 ldp x14,x15,[x1,#32]
 ldp x4,x5,[x2]
 ldp x6,x7,[x2,#16]
 ldp x8,x9,[x2,#32]
 bl cw_word384___rshift_mod_384
 ldr x30,[sp,#8]
 stp x10,x11,[x0]
 stp x12,x13,[x0,#16]
 stp x14,x15,[x0,#32]
 ldp x19,x20,[x29,#2*8]
 ldp x21,x22,[x29,#4*8]
 ldr x29,[sp],#6*8
 hint #29
 ret
.size cw_word384_div_by_2_mod_384,.-cw_word384_div_by_2_mod_384
.globl cw_word384_lshift_mod_384
.hidden cw_word384_lshift_mod_384
.type cw_word384_lshift_mod_384,%function
.align 5
cw_word384_lshift_mod_384:
 hint #25
 stp x29,x30,[sp,#-6*8]!
 add x29,sp,#0
 stp x19,x20,[sp,#2*8]
 stp x21,x22,[sp,#4*8]
 ldp x10,x11,[x1]
 ldp x12,x13,[x1,#16]
 ldp x14,x15,[x1,#32]
 ldp x4,x5,[x3]
 ldp x6,x7,[x3,#16]
 ldp x8,x9,[x3,#32]
.Loop_lshift_mod_384:
 sub x2,x2,#1
 bl cw_word384___lshift_mod_384
 cbnz x2,.Loop_lshift_mod_384
 ldr x30,[sp,#8]
 stp x10,x11,[x0]
 stp x12,x13,[x0,#16]
 stp x14,x15,[x0,#32]
 ldp x19,x20,[x29,#2*8]
 ldp x21,x22,[x29,#4*8]
 ldr x29,[sp],#6*8
 hint #29
 ret
.size cw_word384_lshift_mod_384,.-cw_word384_lshift_mod_384
.type cw_word384___lshift_mod_384,%function
.align 5
cw_word384___lshift_mod_384:
 adds x10,x10,x10
 adcs x11,x11,x11
 adcs x12,x12,x12
 adcs x13,x13,x13
 adcs x14,x14,x14
 adcs x15,x15,x15
 adc x3,xzr,xzr
 subs x16,x10,x4
 sbcs x17,x11,x5
 sbcs x19,x12,x6
 sbcs x20,x13,x7
 sbcs x21,x14,x8
 sbcs x22,x15,x9
 sbcs xzr,x3,xzr
 csel x10,x10,x16,lo
 csel x11,x11,x17,lo
 csel x12,x12,x19,lo
 csel x13,x13,x20,lo
 csel x14,x14,x21,lo
 csel x15,x15,x22,lo
 ret
.size cw_word384___lshift_mod_384,.-cw_word384___lshift_mod_384
.globl cw_word384_mul_by_3_mod_384
.hidden cw_word384_mul_by_3_mod_384
.type cw_word384_mul_by_3_mod_384,%function
.align 5
cw_word384_mul_by_3_mod_384:
 hint #25
 stp x29,x30,[sp,#-6*8]!
 add x29,sp,#0
 stp x19,x20,[sp,#2*8]
 stp x21,x22,[sp,#4*8]
 ldp x10,x11,[x1]
 ldp x12,x13,[x1,#16]
 ldp x14,x15,[x1,#32]
 ldp x4,x5,[x2]
 ldp x6,x7,[x2,#16]
 ldp x8,x9,[x2,#32]
 bl cw_word384___lshift_mod_384
 ldp x16,x17,[x1]
 ldp x19,x20,[x1,#16]
 ldp x21,x22,[x1,#32]
 bl cw_word384___add_mod_384_ab_are_loaded
 ldr x30,[sp,#8]
 stp x10,x11,[x0]
 stp x12,x13,[x0,#16]
 stp x14,x15,[x0,#32]
 ldp x19,x20,[x29,#2*8]
 ldp x21,x22,[x29,#4*8]
 ldr x29,[sp],#6*8
 hint #29
 ret
.size cw_word384_mul_by_3_mod_384,.-cw_word384_mul_by_3_mod_384
.globl cw_word384_mul_by_8_mod_384
.hidden cw_word384_mul_by_8_mod_384
.type cw_word384_mul_by_8_mod_384,%function
.align 5
cw_word384_mul_by_8_mod_384:
 hint #25
 stp x29,x30,[sp,#-6*8]!
 add x29,sp,#0
 stp x19,x20,[sp,#2*8]
 stp x21,x22,[sp,#4*8]
 ldp x10,x11,[x1]
 ldp x12,x13,[x1,#16]
 ldp x14,x15,[x1,#32]
 ldp x4,x5,[x2]
 ldp x6,x7,[x2,#16]
 ldp x8,x9,[x2,#32]
 bl cw_word384___lshift_mod_384
 bl cw_word384___lshift_mod_384
 bl cw_word384___lshift_mod_384
 ldr x30,[sp,#8]
 stp x10,x11,[x0]
 stp x12,x13,[x0,#16]
 stp x14,x15,[x0,#32]
 ldp x19,x20,[x29,#2*8]
 ldp x21,x22,[x29,#4*8]
 ldr x29,[sp],#6*8
 hint #29
 ret
.size cw_word384_mul_by_8_mod_384,.-cw_word384_mul_by_8_mod_384
.globl cw_word384_mul_by_3_mod_384x
.hidden cw_word384_mul_by_3_mod_384x
.type cw_word384_mul_by_3_mod_384x,%function
.align 5
cw_word384_mul_by_3_mod_384x:
 hint #25
 stp x29,x30,[sp,#-6*8]!
 add x29,sp,#0
 stp x19,x20,[sp,#2*8]
 stp x21,x22,[sp,#4*8]
 ldp x10,x11,[x1]
 ldp x12,x13,[x1,#16]
 ldp x14,x15,[x1,#32]
 ldp x4,x5,[x2]
 ldp x6,x7,[x2,#16]
 ldp x8,x9,[x2,#32]
 bl cw_word384___lshift_mod_384
 ldp x16,x17,[x1]
 ldp x19,x20,[x1,#16]
 ldp x21,x22,[x1,#32]
 bl cw_word384___add_mod_384_ab_are_loaded
 stp x10,x11,[x0]
 ldp x10,x11,[x1,#48]
 stp x12,x13,[x0,#16]
 ldp x12,x13,[x1,#64]
 stp x14,x15,[x0,#32]
 ldp x14,x15,[x1,#80]
 bl cw_word384___lshift_mod_384
 ldp x16,x17,[x1,#48]
 ldp x19,x20,[x1,#64]
 ldp x21,x22,[x1,#80]
 bl cw_word384___add_mod_384_ab_are_loaded
 ldr x30,[sp,#8]
 stp x10,x11,[x0,#48]
 stp x12,x13,[x0,#64]
 stp x14,x15,[x0,#80]
 ldp x19,x20,[x29,#2*8]
 ldp x21,x22,[x29,#4*8]
 ldr x29,[sp],#6*8
 hint #29
 ret
.size cw_word384_mul_by_3_mod_384x,.-cw_word384_mul_by_3_mod_384x
.globl cw_word384_mul_by_8_mod_384x
.hidden cw_word384_mul_by_8_mod_384x
.type cw_word384_mul_by_8_mod_384x,%function
.align 5
cw_word384_mul_by_8_mod_384x:
 hint #25
 stp x29,x30,[sp,#-6*8]!
 add x29,sp,#0
 stp x19,x20,[sp,#2*8]
 stp x21,x22,[sp,#4*8]
 ldp x10,x11,[x1]
 ldp x12,x13,[x1,#16]
 ldp x14,x15,[x1,#32]
 ldp x4,x5,[x2]
 ldp x6,x7,[x2,#16]
 ldp x8,x9,[x2,#32]
 bl cw_word384___lshift_mod_384
 bl cw_word384___lshift_mod_384
 bl cw_word384___lshift_mod_384
 stp x10,x11,[x0]
 ldp x10,x11,[x1,#48]
 stp x12,x13,[x0,#16]
 ldp x12,x13,[x1,#64]
 stp x14,x15,[x0,#32]
 ldp x14,x15,[x1,#80]
 bl cw_word384___lshift_mod_384
 bl cw_word384___lshift_mod_384
 bl cw_word384___lshift_mod_384
 ldr x30,[sp,#8]
 stp x10,x11,[x0,#48]
 stp x12,x13,[x0,#64]
 stp x14,x15,[x0,#80]
 ldp x19,x20,[x29,#2*8]
 ldp x21,x22,[x29,#4*8]
 ldr x29,[sp],#6*8
 hint #29
 ret
.size cw_word384_mul_by_8_mod_384x,.-cw_word384_mul_by_8_mod_384x
.globl cw_word384_cneg_mod_384
.hidden cw_word384_cneg_mod_384
.type cw_word384_cneg_mod_384,%function
.align 5
cw_word384_cneg_mod_384:
 hint #25
 stp x29,x30,[sp,#-6*8]!
 add x29,sp,#0
 stp x19,x20,[sp,#2*8]
 stp x21,x22,[sp,#4*8]
 ldp x10,x11,[x1]
 ldp x4,x5,[x3]
 ldp x12,x13,[x1,#16]
 ldp x6,x7,[x3,#16]
 subs x16,x4,x10
 ldp x14,x15,[x1,#32]
 ldp x8,x9,[x3,#32]
 orr x3,x10,x11
 sbcs x17,x5,x11
 orr x3,x3,x12
 sbcs x19,x6,x12
 orr x3,x3,x13
 sbcs x20,x7,x13
 orr x3,x3,x14
 sbcs x21,x8,x14
 orr x3,x3,x15
 sbc x22,x9,x15
 cmp x3,#0
 csetm x3,ne
 ands x2,x2,x3
 csel x10,x10,x16,eq
 csel x11,x11,x17,eq
 csel x12,x12,x19,eq
 csel x13,x13,x20,eq
 stp x10,x11,[x0]
 csel x14,x14,x21,eq
 stp x12,x13,[x0,#16]
 csel x15,x15,x22,eq
 stp x14,x15,[x0,#32]
 ldp x19,x20,[x29,#2*8]
 ldp x21,x22,[x29,#4*8]
 ldr x29,[sp],#6*8
 hint #29
 ret
.size cw_word384_cneg_mod_384,.-cw_word384_cneg_mod_384
.globl cw_word384_sub_mod_384
.hidden cw_word384_sub_mod_384
.type cw_word384_sub_mod_384,%function
.align 5
cw_word384_sub_mod_384:
 hint #25
 stp x29,x30,[sp,#-6*8]!
 add x29,sp,#0
 stp x19,x20,[sp,#2*8]
 stp x21,x22,[sp,#4*8]
 ldp x4,x5,[x3]
 ldp x6,x7,[x3,#16]
 ldp x8,x9,[x3,#32]
 bl cw_word384___sub_mod_384
 ldr x30,[sp,#8]
 stp x10,x11,[x0]
 stp x12,x13,[x0,#16]
 stp x14,x15,[x0,#32]
 ldp x19,x20,[x29,#2*8]
 ldp x21,x22,[x29,#4*8]
 ldr x29,[sp],#6*8
 hint #29
 ret
.size cw_word384_sub_mod_384,.-cw_word384_sub_mod_384
.type cw_word384___sub_mod_384,%function
.align 5
cw_word384___sub_mod_384:
 ldp x10,x11,[x1]
 ldp x16,x17,[x2]
 ldp x12,x13,[x1,#16]
 ldp x19,x20,[x2,#16]
 ldp x14,x15,[x1,#32]
 ldp x21,x22,[x2,#32]
 subs x10,x10,x16
 sbcs x11,x11,x17
 sbcs x12,x12,x19
 sbcs x13,x13,x20
 sbcs x14,x14,x21
 sbcs x15,x15,x22
 sbc x3,xzr,xzr
 and x16,x4,x3
 and x17,x5,x3
 adds x10,x10,x16
 and x19,x6,x3
 adcs x11,x11,x17
 and x20,x7,x3
 adcs x12,x12,x19
 and x21,x8,x3
 adcs x13,x13,x20
 and x22,x9,x3
 adcs x14,x14,x21
 adc x15,x15,x22
 ret
.size cw_word384___sub_mod_384,.-cw_word384___sub_mod_384
.globl cw_word384_sub_mod_384x
.hidden cw_word384_sub_mod_384x
.type cw_word384_sub_mod_384x,%function
.align 5
cw_word384_sub_mod_384x:
 hint #25
 stp x29,x30,[sp,#-6*8]!
 add x29,sp,#0
 stp x19,x20,[sp,#2*8]
 stp x21,x22,[sp,#4*8]
 ldp x4,x5,[x3]
 ldp x6,x7,[x3,#16]
 ldp x8,x9,[x3,#32]
 bl cw_word384___sub_mod_384
 stp x10,x11,[x0]
 add x1,x1,#48
 stp x12,x13,[x0,#16]
 add x2,x2,#48
 stp x14,x15,[x0,#32]
 bl cw_word384___sub_mod_384
 ldr x30,[sp,#8]
 stp x10,x11,[x0,#48]
 stp x12,x13,[x0,#64]
 stp x14,x15,[x0,#80]
 ldp x19,x20,[x29,#2*8]
 ldp x21,x22,[x29,#4*8]
 ldr x29,[sp],#6*8
 hint #29
 ret
.size cw_word384_sub_mod_384x,.-cw_word384_sub_mod_384x
.globl cw_word384_mul_by_1_plus_i_mod_384x
.hidden cw_word384_mul_by_1_plus_i_mod_384x
.type cw_word384_mul_by_1_plus_i_mod_384x,%function
.align 5
cw_word384_mul_by_1_plus_i_mod_384x:
 hint #25
 stp x29,x30,[sp,#-6*8]!
 add x29,sp,#0
 stp x19,x20,[sp,#2*8]
 stp x21,x22,[sp,#4*8]
 ldp x4,x5,[x2]
 ldp x6,x7,[x2,#16]
 ldp x8,x9,[x2,#32]
 add x2,x1,#48
 bl cw_word384___sub_mod_384
 ldp x16,x17,[x1]
 ldp x19,x20,[x1,#16]
 ldp x21,x22,[x1,#32]
 stp x10,x11,[x0]
 ldp x10,x11,[x1,#48]
 stp x12,x13,[x0,#16]
 ldp x12,x13,[x1,#64]
 stp x14,x15,[x0,#32]
 ldp x14,x15,[x1,#80]
 bl cw_word384___add_mod_384_ab_are_loaded
 ldr x30,[sp,#8]
 stp x10,x11,[x0,#48]
 stp x12,x13,[x0,#64]
 stp x14,x15,[x0,#80]
 ldp x19,x20,[x29,#2*8]
 ldp x21,x22,[x29,#4*8]
 ldr x29,[sp],#6*8
 hint #29
 ret
.size cw_word384_mul_by_1_plus_i_mod_384x,.-cw_word384_mul_by_1_plus_i_mod_384x
.globl cw_word384_sgn0_pty_mod_384
.hidden cw_word384_sgn0_pty_mod_384
.type cw_word384_sgn0_pty_mod_384,%function
.align 5
cw_word384_sgn0_pty_mod_384:
 hint #34
 ldp x10,x11,[x0]
 ldp x12,x13,[x0,#16]
 ldp x14,x15,[x0,#32]
 ldp x4,x5,[x1]
 ldp x6,x7,[x1,#16]
 ldp x8,x9,[x1,#32]
 and x0,x10,#1
 adds x10,x10,x10
 adcs x11,x11,x11
 adcs x12,x12,x12
 adcs x13,x13,x13
 adcs x14,x14,x14
 adcs x15,x15,x15
 adc x3,xzr,xzr
 subs x10,x10,x4
 sbcs x11,x11,x5
 sbcs x12,x12,x6
 sbcs x13,x13,x7
 sbcs x14,x14,x8
 sbcs x15,x15,x9
 sbc x3,x3,xzr
 mvn x3,x3
 and x3,x3,#2
 orr x0,x0,x3
 ret
.size cw_word384_sgn0_pty_mod_384,.-cw_word384_sgn0_pty_mod_384
.globl cw_word384_sgn0_pty_mod_384x
.hidden cw_word384_sgn0_pty_mod_384x
.type cw_word384_sgn0_pty_mod_384x,%function
.align 5
cw_word384_sgn0_pty_mod_384x:
 hint #34
 ldp x10,x11,[x0]
 ldp x12,x13,[x0,#16]
 ldp x14,x15,[x0,#32]
 ldp x4,x5,[x1]
 ldp x6,x7,[x1,#16]
 ldp x8,x9,[x1,#32]
 and x2,x10,#1
 orr x3,x10,x11
 adds x10,x10,x10
 orr x3,x3,x12
 adcs x11,x11,x11
 orr x3,x3,x13
 adcs x12,x12,x12
 orr x3,x3,x14
 adcs x13,x13,x13
 orr x3,x3,x15
 adcs x14,x14,x14
 adcs x15,x15,x15
 adc x16,xzr,xzr
 subs x10,x10,x4
 sbcs x11,x11,x5
 sbcs x12,x12,x6
 sbcs x13,x13,x7
 sbcs x14,x14,x8
 sbcs x15,x15,x9
 sbc x16,x16,xzr
 ldp x10,x11,[x0,#48]
 ldp x12,x13,[x0,#64]
 ldp x14,x15,[x0,#80]
 mvn x16,x16
 and x16,x16,#2
 orr x2,x2,x16
 and x0,x10,#1
 orr x1,x10,x11
 adds x10,x10,x10
 orr x1,x1,x12
 adcs x11,x11,x11
 orr x1,x1,x13
 adcs x12,x12,x12
 orr x1,x1,x14
 adcs x13,x13,x13
 orr x1,x1,x15
 adcs x14,x14,x14
 adcs x15,x15,x15
 adc x16,xzr,xzr
 subs x10,x10,x4
 sbcs x11,x11,x5
 sbcs x12,x12,x6
 sbcs x13,x13,x7
 sbcs x14,x14,x8
 sbcs x15,x15,x9
 sbc x16,x16,xzr
 mvn x16,x16
 and x16,x16,#2
 orr x0,x0,x16
 cmp x3,#0
 csel x3,x0,x2,eq
 cmp x1,#0
 csel x1,x0,x2,ne
 and x3,x3,#1
 and x1,x1,#2
 orr x0,x1,x3
 ret
.size cw_word384_sgn0_pty_mod_384x,.-cw_word384_sgn0_pty_mod_384x
.globl cw_word384_vec_select_32
.hidden cw_word384_vec_select_32
.type cw_word384_vec_select_32,%function
.align 5
cw_word384_vec_select_32:
 hint #34
 dup v6.2d, x3
 ld1 {v0.2d, v1.2d}, [x1]
 cmeq v6.2d, v6.2d, #0
 ld1 {v3.2d, v4.2d}, [x2]
 bit v0.16b, v3.16b, v6.16b
 bit v1.16b, v4.16b, v6.16b
 st1 {v0.2d, v1.2d}, [x0]
 ret
.size cw_word384_vec_select_32,.-cw_word384_vec_select_32
.globl cw_word384_vec_select_48
.hidden cw_word384_vec_select_48
.type cw_word384_vec_select_48,%function
.align 5
cw_word384_vec_select_48:
 hint #34
 dup v6.2d, x3
 ld1 {v0.2d, v1.2d, v2.2d}, [x1],#48
 cmeq v6.2d, v6.2d, #0
 ld1 {v3.2d, v4.2d, v5.2d}, [x2],#48
 bit v0.16b, v3.16b, v6.16b
 bit v1.16b, v4.16b, v6.16b
 bit v2.16b, v5.16b, v6.16b
 st1 {v0.2d, v1.2d, v2.2d}, [x0]
 ret
.size cw_word384_vec_select_48,.-cw_word384_vec_select_48
.globl cw_word384_vec_select_96
.hidden cw_word384_vec_select_96
.type cw_word384_vec_select_96,%function
.align 5
cw_word384_vec_select_96:
 hint #34
 dup v6.2d, x3
 ld1 {v0.2d, v1.2d, v2.2d}, [x1],#48
 cmeq v6.2d, v6.2d, #0
 ld1 {v3.2d, v4.2d, v5.2d}, [x2],#48
 bit v0.16b, v3.16b, v6.16b
 ld1 {v16.2d, v17.2d, v18.2d}, [x1],#48
 bit v1.16b, v4.16b, v6.16b
 ld1 {v19.2d, v20.2d, v21.2d}, [x2],#48
 bit v2.16b, v5.16b, v6.16b
 st1 {v0.2d, v1.2d, v2.2d}, [x0],#48
 bit v16.16b, v19.16b, v6.16b
 bit v17.16b, v20.16b, v6.16b
 bit v18.16b, v21.16b, v6.16b
 st1 {v16.2d, v17.2d, v18.2d}, [x0]
 ret
.size cw_word384_vec_select_96,.-cw_word384_vec_select_96
.globl cw_word384_vec_select_192
.hidden cw_word384_vec_select_192
.type cw_word384_vec_select_192,%function
.align 5
cw_word384_vec_select_192:
 hint #34
 dup v6.2d, x3
 ld1 {v0.2d, v1.2d, v2.2d}, [x1],#48
 cmeq v6.2d, v6.2d, #0
 ld1 {v3.2d, v4.2d, v5.2d}, [x2],#48
 bit v0.16b, v3.16b, v6.16b
 ld1 {v16.2d, v17.2d, v18.2d}, [x1],#48
 bit v1.16b, v4.16b, v6.16b
 ld1 {v19.2d, v20.2d, v21.2d}, [x2],#48
 bit v2.16b, v5.16b, v6.16b
 st1 {v0.2d, v1.2d, v2.2d}, [x0],#48
 bit v16.16b, v19.16b, v6.16b
 ld1 {v0.2d, v1.2d, v2.2d}, [x1],#48
 bit v17.16b, v20.16b, v6.16b
 ld1 {v3.2d, v4.2d, v5.2d}, [x2],#48
 bit v18.16b, v21.16b, v6.16b
 st1 {v16.2d, v17.2d, v18.2d}, [x0],#48
 bit v0.16b, v3.16b, v6.16b
 ld1 {v16.2d, v17.2d, v18.2d}, [x1],#48
 bit v1.16b, v4.16b, v6.16b
 ld1 {v19.2d, v20.2d, v21.2d}, [x2],#48
 bit v2.16b, v5.16b, v6.16b
 st1 {v0.2d, v1.2d, v2.2d}, [x0],#48
 bit v16.16b, v19.16b, v6.16b
 bit v17.16b, v20.16b, v6.16b
 bit v18.16b, v21.16b, v6.16b
 st1 {v16.2d, v17.2d, v18.2d}, [x0]
 ret
.size cw_word384_vec_select_192,.-cw_word384_vec_select_192
.globl cw_word384_vec_select_144
.hidden cw_word384_vec_select_144
.type cw_word384_vec_select_144,%function
.align 5
cw_word384_vec_select_144:
 hint #34
 dup v6.2d, x3
 ld1 {v0.2d, v1.2d, v2.2d}, [x1],#48
 cmeq v6.2d, v6.2d, #0
 ld1 {v3.2d, v4.2d, v5.2d}, [x2],#48
 bit v0.16b, v3.16b, v6.16b
 ld1 {v16.2d, v17.2d, v18.2d}, [x1],#48
 bit v1.16b, v4.16b, v6.16b
 ld1 {v19.2d, v20.2d, v21.2d}, [x2],#48
 bit v2.16b, v5.16b, v6.16b
 st1 {v0.2d, v1.2d, v2.2d}, [x0],#48
 bit v16.16b, v19.16b, v6.16b
 ld1 {v0.2d, v1.2d, v2.2d}, [x1],#48
 bit v17.16b, v20.16b, v6.16b
 ld1 {v3.2d, v4.2d, v5.2d}, [x2],#48
 bit v18.16b, v21.16b, v6.16b
 st1 {v16.2d, v17.2d, v18.2d}, [x0],#48
 bit v0.16b, v3.16b, v6.16b
 bit v1.16b, v4.16b, v6.16b
 bit v2.16b, v5.16b, v6.16b
 st1 {v0.2d, v1.2d, v2.2d}, [x0]
 ret
.size cw_word384_vec_select_144,.-cw_word384_vec_select_144
.globl cw_word384_vec_select_288
.hidden cw_word384_vec_select_288
.type cw_word384_vec_select_288,%function
.align 5
cw_word384_vec_select_288:
 hint #34
 dup v6.2d, x3
 ld1 {v0.2d, v1.2d, v2.2d}, [x1],#48
 cmeq v6.2d, v6.2d, #0
 ld1 {v3.2d, v4.2d, v5.2d}, [x2],#48
 bit v0.16b, v3.16b, v6.16b
 ld1 {v16.2d, v17.2d, v18.2d}, [x1],#48
 bit v1.16b, v4.16b, v6.16b
 ld1 {v19.2d, v20.2d, v21.2d}, [x2],#48
 bit v2.16b, v5.16b, v6.16b
 st1 {v0.2d, v1.2d, v2.2d}, [x0],#48
 bit v16.16b, v19.16b, v6.16b
 ld1 {v0.2d, v1.2d, v2.2d}, [x1],#48
 bit v17.16b, v20.16b, v6.16b
 ld1 {v3.2d, v4.2d, v5.2d}, [x2],#48
 bit v18.16b, v21.16b, v6.16b
 st1 {v16.2d, v17.2d, v18.2d}, [x0],#48
 bit v0.16b, v3.16b, v6.16b
 ld1 {v16.2d, v17.2d, v18.2d}, [x1],#48
 bit v1.16b, v4.16b, v6.16b
 ld1 {v19.2d, v20.2d, v21.2d}, [x2],#48
 bit v2.16b, v5.16b, v6.16b
 st1 {v0.2d, v1.2d, v2.2d}, [x0],#48
 bit v16.16b, v19.16b, v6.16b
 ld1 {v0.2d, v1.2d, v2.2d}, [x1],#48
 bit v17.16b, v20.16b, v6.16b
 ld1 {v3.2d, v4.2d, v5.2d}, [x2],#48
 bit v18.16b, v21.16b, v6.16b
 st1 {v16.2d, v17.2d, v18.2d}, [x0],#48
 bit v0.16b, v3.16b, v6.16b
 ld1 {v16.2d, v17.2d, v18.2d}, [x1],#48
 bit v1.16b, v4.16b, v6.16b
 ld1 {v19.2d, v20.2d, v21.2d}, [x2],#48
 bit v2.16b, v5.16b, v6.16b
 st1 {v0.2d, v1.2d, v2.2d}, [x0],#48
 bit v16.16b, v19.16b, v6.16b
 bit v17.16b, v20.16b, v6.16b
 bit v18.16b, v21.16b, v6.16b
 st1 {v16.2d, v17.2d, v18.2d}, [x0]
 ret
.size cw_word384_vec_select_288,.-cw_word384_vec_select_288
.globl cw_word384_vec_prefetch
.hidden cw_word384_vec_prefetch
.type cw_word384_vec_prefetch,%function
.align 5
cw_word384_vec_prefetch:
 hint #34
 add x1, x1, x0
 sub x1, x1, #1
 mov x2, #64
 prfm pldl1keep, [x0]
 add x0, x0, x2
 cmp x0, x1
 csel x0, x1, x0, hi
 csel x2, xzr, x2, hi
 prfm pldl1keep, [x0]
 add x0, x0, x2
 cmp x0, x1
 csel x0, x1, x0, hi
 csel x2, xzr, x2, hi
 prfm pldl1keep, [x0]
 add x0, x0, x2
 cmp x0, x1
 csel x0, x1, x0, hi
 csel x2, xzr, x2, hi
 prfm pldl1keep, [x0]
 add x0, x0, x2
 cmp x0, x1
 csel x0, x1, x0, hi
 csel x2, xzr, x2, hi
 prfm pldl1keep, [x0]
 add x0, x0, x2
 cmp x0, x1
 csel x0, x1, x0, hi
 csel x2, xzr, x2, hi
 prfm pldl1keep, [x0]
 add x0, x0, x2
 cmp x0, x1
 csel x0, x1, x0, hi
 prfm pldl1keep, [x0]
 ret
.size cw_word384_vec_prefetch,.-cw_word384_vec_prefetch
.globl cw_word384_vec_is_zero_16x
.hidden cw_word384_vec_is_zero_16x
.type cw_word384_vec_is_zero_16x,%function
.align 5
cw_word384_vec_is_zero_16x:
 hint #34
 ld1 {v0.2d}, [x0], #16
 lsr x1, x1, #4
 sub x1, x1, #1
 cbz x1, .Loop_is_zero_done
.Loop_is_zero:
 ld1 {v1.2d}, [x0], #16
 orr v0.16b, v0.16b, v1.16b
 sub x1, x1, #1
 cbnz x1, .Loop_is_zero
.Loop_is_zero_done:
 dup v1.2d, v0.d[1]
 orr v0.16b, v0.16b, v1.16b
 umov x1, v0.d[0]
 mov x0, #1
 cmp x1, #0
 csel x0, x0, xzr, eq
 ret
.size cw_word384_vec_is_zero_16x,.-cw_word384_vec_is_zero_16x
.globl cw_word384_vec_is_equal_16x
.hidden cw_word384_vec_is_equal_16x
.type cw_word384_vec_is_equal_16x,%function
.align 5
cw_word384_vec_is_equal_16x:
 hint #34
 ld1 {v0.2d}, [x0], #16
 ld1 {v1.2d}, [x1], #16
 lsr x2, x2, #4
 eor v0.16b, v0.16b, v1.16b
.Loop_is_equal:
 sub x2, x2, #1
 cbz x2, .Loop_is_equal_done
 ld1 {v1.2d}, [x0], #16
 ld1 {v2.2d}, [x1], #16
 eor v1.16b, v1.16b, v2.16b
 orr v0.16b, v0.16b, v1.16b
 b .Loop_is_equal
 nop
.Loop_is_equal_done:
 dup v1.2d, v0.d[1]
 orr v0.16b, v0.16b, v1.16b
 umov x1, v0.d[0]
 mov x0, #1
 cmp x1, #0
 csel x0, x0, xzr, eq
 ret
.size cw_word384_vec_is_equal_16x,.-cw_word384_vec_is_equal_16x
.text
.globl cw_word384_add_mod_384x384
.hidden cw_word384_add_mod_384x384
.type cw_word384_add_mod_384x384,%function
.align 5
cw_word384_add_mod_384x384:
 hint #25
 stp x29,x30,[sp,#-8*8]!
 add x29,sp,#0
 stp x19,x20,[sp,#2*8]
 stp x21,x22,[sp,#4*8]
 stp x23,x24,[sp,#6*8]
 ldp x5,x6,[x3]
 ldp x7,x8,[x3,#16]
 ldp x9,x10,[x3,#32]
 bl cw_word384___add_mod_384x384
 ldr x30,[x29,#8]
 ldp x19,x20,[x29,#2*8]
 ldp x21,x22,[x29,#4*8]
 ldp x23,x24,[x29,#6*8]
 ldr x29,[sp],#8*8
 hint #29
 ret
.size cw_word384_add_mod_384x384,.-cw_word384_add_mod_384x384
.type cw_word384___add_mod_384x384,%function
.align 5
cw_word384___add_mod_384x384:
 ldp x11, x12, [x1]
 ldp x19,x20,[x2]
 ldp x13, x14, [x1,#16]
 adds x11,x11,x19
 ldp x21,x22,[x2,#16]
 adcs x12,x12,x20
 ldp x15, x16, [x1,#32]
 adcs x13,x13,x21
 ldp x23,x24,[x2,#32]
 adcs x14,x14,x22
 stp x11, x12, [x0]
 adcs x15,x15,x23
 ldp x11, x12, [x1,#48]
 adcs x16,x16,x24
 ldp x19,x20,[x2,#48]
 stp x13, x14, [x0,#16]
 ldp x13, x14, [x1,#64]
 ldp x21,x22,[x2,#64]
 adcs x11,x11,x19
 stp x15, x16, [x0,#32]
 adcs x12,x12,x20
 ldp x15, x16, [x1,#80]
 adcs x13,x13,x21
 ldp x23,x24,[x2,#80]
 adcs x14,x14,x22
 adcs x15,x15,x23
 adcs x16,x16,x24
 adc x17,xzr,xzr
 subs x19,x11,x5
 sbcs x20,x12,x6
 sbcs x21,x13,x7
 sbcs x22,x14,x8
 sbcs x23,x15,x9
 sbcs x24,x16,x10
 sbcs xzr,x17,xzr
 csel x11,x11,x19,lo
 csel x12,x12,x20,lo
 csel x13,x13,x21,lo
 csel x14,x14,x22,lo
 stp x11,x12,[x0,#48]
 csel x15,x15,x23,lo
 stp x13,x14,[x0,#64]
 csel x16,x16,x24,lo
 stp x15,x16,[x0,#80]
 ret
.size cw_word384___add_mod_384x384,.-cw_word384___add_mod_384x384
.globl cw_word384_sub_mod_384x384
.hidden cw_word384_sub_mod_384x384
.type cw_word384_sub_mod_384x384,%function
.align 5
cw_word384_sub_mod_384x384:
 hint #25
 stp x29,x30,[sp,#-8*8]!
 add x29,sp,#0
 stp x19,x20,[sp,#2*8]
 stp x21,x22,[sp,#4*8]
 stp x23,x24,[sp,#6*8]
 ldp x5,x6,[x3]
 ldp x7,x8,[x3,#16]
 ldp x9,x10,[x3,#32]
 bl cw_word384___sub_mod_384x384
 ldr x30,[x29,#8]
 ldp x19,x20,[x29,#2*8]
 ldp x21,x22,[x29,#4*8]
 ldp x23,x24,[x29,#6*8]
 ldr x29,[sp],#8*8
 hint #29
 ret
.size cw_word384_sub_mod_384x384,.-cw_word384_sub_mod_384x384
.type cw_word384___sub_mod_384x384,%function
.align 5
cw_word384___sub_mod_384x384:
 ldp x11, x12, [x1]
 ldp x19,x20,[x2]
 ldp x13, x14, [x1,#16]
 subs x11,x11,x19
 ldp x21,x22,[x2,#16]
 sbcs x12,x12,x20
 ldp x15, x16, [x1,#32]
 sbcs x13,x13,x21
 ldp x23,x24,[x2,#32]
 sbcs x14,x14,x22
 stp x11, x12, [x0]
 sbcs x15,x15,x23
 ldp x11, x12, [x1,#48]
 sbcs x16,x16,x24
 ldp x19,x20,[x2,#48]
 stp x13, x14, [x0,#16]
 ldp x13, x14, [x1,#64]
 ldp x21,x22,[x2,#64]
 sbcs x11,x11,x19
 stp x15, x16, [x0,#32]
 sbcs x12,x12,x20
 ldp x15, x16, [x1,#80]
 sbcs x13,x13,x21
 ldp x23,x24,[x2,#80]
 sbcs x14,x14,x22
 sbcs x15,x15,x23
 sbcs x16,x16,x24
 sbc x17,xzr,xzr
 and x19,x5,x17
 and x20,x6,x17
 adds x11,x11,x19
 and x21,x7,x17
 adcs x12,x12,x20
 and x22,x8,x17
 adcs x13,x13,x21
 and x23,x9,x17
 adcs x14,x14,x22
 and x24,x10,x17
 adcs x15,x15,x23
 stp x11,x12,[x0,#48]
 adc x16,x16,x24
 stp x13,x14,[x0,#64]
 stp x15,x16,[x0,#80]
 ret
.size cw_word384___sub_mod_384x384,.-cw_word384___sub_mod_384x384
.type cw_word384___add_mont_384,%function
.align 5
cw_word384___add_mont_384:
 ldp x11, x12, [x1]
 ldp x19,x20,[x2]
 ldp x13, x14, [x1,#16]
 adds x11,x11,x19
 ldp x21,x22,[x2,#16]
 adcs x12,x12,x20
 ldp x15, x16, [x1,#32]
 adcs x13,x13,x21
 ldp x23,x24,[x2,#32]
 adcs x14,x14,x22
 adcs x15,x15,x23
 adcs x16,x16,x24
 adc x17,xzr,xzr
 subs x19,x11,x5
 sbcs x20,x12,x6
 sbcs x21,x13,x7
 sbcs x22,x14,x8
 sbcs x23,x15,x9
 sbcs x24,x16,x10
 sbcs xzr,x17,xzr
 csel x11,x11,x19,lo
 csel x12,x12,x20,lo
 csel x13,x13,x21,lo
 csel x14,x14,x22,lo
 csel x15,x15,x23,lo
 stp x11,x12,[x0]
 csel x16,x16,x24,lo
 stp x13,x14,[x0,#16]
 stp x15,x16,[x0,#32]
 ret
.size cw_word384___add_mont_384,.-cw_word384___add_mont_384
.type cw_word384___sub_mont_384,%function
.align 5
cw_word384___sub_mont_384:
 ldp x11, x12, [x1]
 ldp x19,x20,[x2]
 ldp x13, x14, [x1,#16]
 subs x11,x11,x19
 ldp x21,x22,[x2,#16]
 sbcs x12,x12,x20
 ldp x15, x16, [x1,#32]
 sbcs x13,x13,x21
 ldp x23,x24,[x2,#32]
 sbcs x14,x14,x22
 sbcs x15,x15,x23
 sbcs x16,x16,x24
 sbc x17,xzr,xzr
 and x19,x5,x17
 and x20,x6,x17
 adds x11,x11,x19
 and x21,x7,x17
 adcs x12,x12,x20
 and x22,x8,x17
 adcs x13,x13,x21
 and x23,x9,x17
 adcs x14,x14,x22
 and x24,x10,x17
 adcs x15,x15,x23
 stp x11,x12,[x0]
 adc x16,x16,x24
 stp x13,x14,[x0,#16]
 stp x15,x16,[x0,#32]
 ret
.size cw_word384___sub_mont_384,.-cw_word384___sub_mont_384
.globl cw_word384_mul_mont_384x
.hidden cw_word384_mul_mont_384x
.type cw_word384_mul_mont_384x,%function
.align 5
cw_word384_mul_mont_384x:
 hint #25
 stp x29,x30,[sp,#-16*8]!
 add x29,sp,#0
 stp x19,x20,[sp,#2*8]
 stp x21,x22,[sp,#4*8]
 stp x23,x24,[sp,#6*8]
 stp x25,x26,[sp,#8*8]
 stp x27,x28,[sp,#10*8]
 sub sp,sp,#288
 mov x26,x0
 mov x27,x1
 mov x28,x2
 add x0,sp,#0
 bl cw_word384___mul_384
 add x1,x1,#48
 add x2,x2,#48
 add x0,sp,#96
 bl cw_word384___mul_384
 ldp x5,x6,[x3]
 ldp x7,x8,[x3,#16]
 ldp x9,x10,[x3,#32]
 sub x2,x1,#48
 add x0,sp,#240
 bl cw_word384___add_mont_384
 add x1,x28,#0
 add x2,x28,#48
 add x0,sp,#192
 bl cw_word384___add_mont_384
 add x1,x0,#0
 add x2,x0,#48
 bl cw_word384___mul_384
 ldp x5,x6,[x3]
 ldp x7,x8,[x3,#16]
 ldp x9,x10,[x3,#32]
 mov x1,x0
 add x2,sp,#0
 bl cw_word384___sub_mod_384x384
 add x2,sp,#96
 bl cw_word384___sub_mod_384x384
 add x1,sp,#0
 add x2,sp,#96
 add x0,sp,#0
 bl cw_word384___sub_mod_384x384
 add x1,sp,#0
 add x0,x26,#0
 bl cw_word384___mul_by_1_mont_384
 bl cw_word384___redc_tail_mont_384
 add x1,sp,#192
 add x0,x0,#48
 bl cw_word384___mul_by_1_mont_384
 bl cw_word384___redc_tail_mont_384
 ldr x30,[x29,#8]
 add sp,sp,#288
 ldp x19,x20,[x29,#2*8]
 ldp x21,x22,[x29,#4*8]
 ldp x23,x24,[x29,#6*8]
 ldp x25,x26,[x29,#8*8]
 ldp x27,x28,[x29,#10*8]
 ldr x29,[sp],#16*8
 hint #29
 ret
.size cw_word384_mul_mont_384x,.-cw_word384_mul_mont_384x
.globl cw_word384_sqr_mont_384x
.hidden cw_word384_sqr_mont_384x
.type cw_word384_sqr_mont_384x,%function
.align 5
cw_word384_sqr_mont_384x:
 hint #25
 stp x29,x30,[sp,#-16*8]!
 add x29,sp,#0
 stp x19,x20,[sp,#2*8]
 stp x21,x22,[sp,#4*8]
 stp x23,x24,[sp,#6*8]
 stp x25,x26,[sp,#8*8]
 stp x27,x28,[sp,#10*8]
 stp x3,x0,[sp,#12*8]
 sub sp,sp,#96
 mov x4,x3
 ldp x5,x6,[x2]
 ldp x7,x8,[x2,#16]
 ldp x9,x10,[x2,#32]
 add x2,x1,#48
 add x0,sp,#0
 bl cw_word384___add_mont_384
 add x0,sp,#48
 bl cw_word384___sub_mont_384
 ldp x11,x12,[x1]
 ldr x17, [x2]
 ldp x13,x14,[x1,#16]
 ldp x15,x16,[x1,#32]
 bl cw_word384___mul_mont_384
 adds x11,x11,x11
 adcs x12,x12,x12
 adcs x13,x13,x13
 adcs x14,x14,x14
 adcs x15,x15,x15
 adcs x16,x16,x16
 adc x25,xzr,xzr
 subs x19,x11,x5
 sbcs x20,x12,x6
 sbcs x21,x13,x7
 sbcs x22,x14,x8
 sbcs x23,x15,x9
 sbcs x24,x16,x10
 sbcs xzr,x25,xzr
 csel x19,x11,x19,lo
 csel x20,x12,x20,lo
 csel x21,x13,x21,lo
 ldp x11,x12,[sp]
 csel x22,x14,x22,lo
 ldr x17, [sp,#48]
 csel x23,x15,x23,lo
 ldp x13,x14,[sp,#16]
 csel x24,x16,x24,lo
 ldp x15,x16,[sp,#32]
 stp x19,x20,[x2,#48]
 stp x21,x22,[x2,#64]
 stp x23,x24,[x2,#80]
 add x2,sp,#48
 bl cw_word384___mul_mont_384
 ldr x30,[x29,#8]
 stp x11,x12,[x2]
 stp x13,x14,[x2,#16]
 stp x15,x16,[x2,#32]
 add sp,sp,#96
 ldp x19,x20,[x29,#2*8]
 ldp x21,x22,[x29,#4*8]
 ldp x23,x24,[x29,#6*8]
 ldp x25,x26,[x29,#8*8]
 ldp x27,x28,[x29,#10*8]
 ldr x29,[sp],#16*8
 hint #29
 ret
.size cw_word384_sqr_mont_384x,.-cw_word384_sqr_mont_384x
.globl cw_word384_mul_mont_384
.hidden cw_word384_mul_mont_384
.type cw_word384_mul_mont_384,%function
.align 5
cw_word384_mul_mont_384:
 hint #25
 stp x29,x30,[sp,#-16*8]!
 add x29,sp,#0
 stp x19,x20,[sp,#2*8]
 stp x21,x22,[sp,#4*8]
 stp x23,x24,[sp,#6*8]
 stp x25,x26,[sp,#8*8]
 stp x27,x28,[sp,#10*8]
 stp x4,x0,[sp,#12*8]
 ldp x11,x12,[x1]
 ldr x17, [x2]
 ldp x13,x14,[x1,#16]
 ldp x15,x16,[x1,#32]
 ldp x5,x6,[x3]
 ldp x7,x8,[x3,#16]
 ldp x9,x10,[x3,#32]
 bl cw_word384___mul_mont_384
 ldr x30,[x29,#8]
 stp x11,x12,[x2]
 stp x13,x14,[x2,#16]
 stp x15,x16,[x2,#32]
 ldp x19,x20,[x29,#2*8]
 ldp x21,x22,[x29,#4*8]
 ldp x23,x24,[x29,#6*8]
 ldp x25,x26,[x29,#8*8]
 ldp x27,x28,[x29,#10*8]
 ldr x29,[sp],#16*8
 hint #29
 ret
.size cw_word384_mul_mont_384,.-cw_word384_mul_mont_384
.type cw_word384___mul_mont_384,%function
.align 5
cw_word384___mul_mont_384:
 mul x19,x11,x17
 mul x20,x12,x17
 mul x21,x13,x17
 mul x22,x14,x17
 mul x23,x15,x17
 mul x24,x16,x17
 mul x4,x4,x19
 umulh x26,x11,x17
 umulh x27,x12,x17
 umulh x28,x13,x17
 umulh x0,x14,x17
 umulh x1,x15,x17
 umulh x3,x16,x17
 adds x20,x20,x26
 adcs x21,x21,x27
 mul x27,x6,x4
 adcs x22,x22,x28
 mul x28,x7,x4
 adcs x23,x23,x0
 mul x0,x8,x4
 adcs x24,x24,x1
 mul x1,x9,x4
 adc x25,xzr, x3
 mul x3,x10,x4
 mov x17,xzr
 subs xzr,x19,#1
 umulh x26,x5,x4
 adcs x20,x20,x27
 umulh x27,x6,x4
 adcs x21,x21,x28
 umulh x28,x7,x4
 adcs x22,x22,x0
 umulh x0,x8,x4
 adcs x23,x23,x1
 umulh x1,x9,x4
 adcs x24,x24,x3
 umulh x3,x10,x4
 adcs x25,x25,xzr
 adc x4,x17,xzr
 ldr x17,[x2,8*1]
 adds x19,x20,x26
 mul x26,x11,x17
 adcs x20,x21,x27
 mul x27,x12,x17
 adcs x21,x22,x28
 mul x28,x13,x17
 adcs x22,x23,x0
 mul x0,x14,x17
 adcs x23,x24,x1
 mul x1,x15,x17
 adcs x24,x25,x3
 mul x3,x16,x17
 adc x25,x4,xzr
 ldr x4,[x29,#12*8]
 adds x19,x19,x26
 umulh x26,x11,x17
 adcs x20,x20,x27
 umulh x27,x12,x17
 adcs x21,x21,x28
 mul x4,x4,x19
 umulh x28,x13,x17
 adcs x22,x22,x0
 umulh x0,x14,x17
 adcs x23,x23,x1
 umulh x1,x15,x17
 adcs x24,x24,x3
 umulh x3,x16,x17
 adcs x25,x25,xzr
 adc x17,xzr,xzr
 adds x20,x20,x26
 adcs x21,x21,x27
 mul x27,x6,x4
 adcs x22,x22,x28
 mul x28,x7,x4
 adcs x23,x23,x0
 mul x0,x8,x4
 adcs x24,x24,x1
 mul x1,x9,x4
 adcs x25,x25,x3
 mul x3,x10,x4
 adc x17,x17,xzr
 subs xzr,x19,#1
 umulh x26,x5,x4
 adcs x20,x20,x27
 umulh x27,x6,x4
 adcs x21,x21,x28
 umulh x28,x7,x4
 adcs x22,x22,x0
 umulh x0,x8,x4
 adcs x23,x23,x1
 umulh x1,x9,x4
 adcs x24,x24,x3
 umulh x3,x10,x4
 adcs x25,x25,xzr
 adc x4,x17,xzr
 ldr x17,[x2,8*2]
 adds x19,x20,x26
 mul x26,x11,x17
 adcs x20,x21,x27
 mul x27,x12,x17
 adcs x21,x22,x28
 mul x28,x13,x17
 adcs x22,x23,x0
 mul x0,x14,x17
 adcs x23,x24,x1
 mul x1,x15,x17
 adcs x24,x25,x3
 mul x3,x16,x17
 adc x25,x4,xzr
 ldr x4,[x29,#12*8]
 adds x19,x19,x26
 umulh x26,x11,x17
 adcs x20,x20,x27
 umulh x27,x12,x17
 adcs x21,x21,x28
 mul x4,x4,x19
 umulh x28,x13,x17
 adcs x22,x22,x0
 umulh x0,x14,x17
 adcs x23,x23,x1
 umulh x1,x15,x17
 adcs x24,x24,x3
 umulh x3,x16,x17
 adcs x25,x25,xzr
 adc x17,xzr,xzr
 adds x20,x20,x26
 adcs x21,x21,x27
 mul x27,x6,x4
 adcs x22,x22,x28
 mul x28,x7,x4
 adcs x23,x23,x0
 mul x0,x8,x4
 adcs x24,x24,x1
 mul x1,x9,x4
 adcs x25,x25,x3
 mul x3,x10,x4
 adc x17,x17,xzr
 subs xzr,x19,#1
 umulh x26,x5,x4
 adcs x20,x20,x27
 umulh x27,x6,x4
 adcs x21,x21,x28
 umulh x28,x7,x4
 adcs x22,x22,x0
 umulh x0,x8,x4
 adcs x23,x23,x1
 umulh x1,x9,x4
 adcs x24,x24,x3
 umulh x3,x10,x4
 adcs x25,x25,xzr
 adc x4,x17,xzr
 ldr x17,[x2,8*3]
 adds x19,x20,x26
 mul x26,x11,x17
 adcs x20,x21,x27
 mul x27,x12,x17
 adcs x21,x22,x28
 mul x28,x13,x17
 adcs x22,x23,x0
 mul x0,x14,x17
 adcs x23,x24,x1
 mul x1,x15,x17
 adcs x24,x25,x3
 mul x3,x16,x17
 adc x25,x4,xzr
 ldr x4,[x29,#12*8]
 adds x19,x19,x26
 umulh x26,x11,x17
 adcs x20,x20,x27
 umulh x27,x12,x17
 adcs x21,x21,x28
 mul x4,x4,x19
 umulh x28,x13,x17
 adcs x22,x22,x0
 umulh x0,x14,x17
 adcs x23,x23,x1
 umulh x1,x15,x17
 adcs x24,x24,x3
 umulh x3,x16,x17
 adcs x25,x25,xzr
 adc x17,xzr,xzr
 adds x20,x20,x26
 adcs x21,x21,x27
 mul x27,x6,x4
 adcs x22,x22,x28
 mul x28,x7,x4
 adcs x23,x23,x0
 mul x0,x8,x4
 adcs x24,x24,x1
 mul x1,x9,x4
 adcs x25,x25,x3
 mul x3,x10,x4
 adc x17,x17,xzr
 subs xzr,x19,#1
 umulh x26,x5,x4
 adcs x20,x20,x27
 umulh x27,x6,x4
 adcs x21,x21,x28
 umulh x28,x7,x4
 adcs x22,x22,x0
 umulh x0,x8,x4
 adcs x23,x23,x1
 umulh x1,x9,x4
 adcs x24,x24,x3
 umulh x3,x10,x4
 adcs x25,x25,xzr
 adc x4,x17,xzr
 ldr x17,[x2,8*4]
 adds x19,x20,x26
 mul x26,x11,x17
 adcs x20,x21,x27
 mul x27,x12,x17
 adcs x21,x22,x28
 mul x28,x13,x17
 adcs x22,x23,x0
 mul x0,x14,x17
 adcs x23,x24,x1
 mul x1,x15,x17
 adcs x24,x25,x3
 mul x3,x16,x17
 adc x25,x4,xzr
 ldr x4,[x29,#12*8]
 adds x19,x19,x26
 umulh x26,x11,x17
 adcs x20,x20,x27
 umulh x27,x12,x17
 adcs x21,x21,x28
 mul x4,x4,x19
 umulh x28,x13,x17
 adcs x22,x22,x0
 umulh x0,x14,x17
 adcs x23,x23,x1
 umulh x1,x15,x17
 adcs x24,x24,x3
 umulh x3,x16,x17
 adcs x25,x25,xzr
 adc x17,xzr,xzr
 adds x20,x20,x26
 adcs x21,x21,x27
 mul x27,x6,x4
 adcs x22,x22,x28
 mul x28,x7,x4
 adcs x23,x23,x0
 mul x0,x8,x4
 adcs x24,x24,x1
 mul x1,x9,x4
 adcs x25,x25,x3
 mul x3,x10,x4
 adc x17,x17,xzr
 subs xzr,x19,#1
 umulh x26,x5,x4
 adcs x20,x20,x27
 umulh x27,x6,x4
 adcs x21,x21,x28
 umulh x28,x7,x4
 adcs x22,x22,x0
 umulh x0,x8,x4
 adcs x23,x23,x1
 umulh x1,x9,x4
 adcs x24,x24,x3
 umulh x3,x10,x4
 adcs x25,x25,xzr
 adc x4,x17,xzr
 ldr x17,[x2,8*5]
 adds x19,x20,x26
 mul x26,x11,x17
 adcs x20,x21,x27
 mul x27,x12,x17
 adcs x21,x22,x28
 mul x28,x13,x17
 adcs x22,x23,x0
 mul x0,x14,x17
 adcs x23,x24,x1
 mul x1,x15,x17
 adcs x24,x25,x3
 mul x3,x16,x17
 adc x25,x4,xzr
 ldr x4,[x29,#12*8]
 adds x19,x19,x26
 umulh x26,x11,x17
 adcs x20,x20,x27
 umulh x27,x12,x17
 adcs x21,x21,x28
 mul x4,x4,x19
 umulh x28,x13,x17
 adcs x22,x22,x0
 umulh x0,x14,x17
 adcs x23,x23,x1
 umulh x1,x15,x17
 adcs x24,x24,x3
 umulh x3,x16,x17
 adcs x25,x25,xzr
 adc x17,xzr,xzr
 adds x20,x20,x26
 adcs x21,x21,x27
 mul x27,x6,x4
 adcs x22,x22,x28
 mul x28,x7,x4
 adcs x23,x23,x0
 mul x0,x8,x4
 adcs x24,x24,x1
 mul x1,x9,x4
 adcs x25,x25,x3
 mul x3,x10,x4
 adc x17,x17,xzr
 subs xzr,x19,#1
 umulh x26,x5,x4
 adcs x20,x20,x27
 umulh x27,x6,x4
 adcs x21,x21,x28
 umulh x28,x7,x4
 adcs x22,x22,x0
 umulh x0,x8,x4
 adcs x23,x23,x1
 umulh x1,x9,x4
 adcs x24,x24,x3
 umulh x3,x10,x4
 adcs x25,x25,xzr
 ldp x4,x2,[x29,#12*8]
 adc x17,x17,xzr
 adds x19,x20,x26
 adcs x20,x21,x27
 adcs x21,x22,x28
 adcs x22,x23,x0
 adcs x23,x24,x1
 adcs x24,x25,x3
 adc x25,x17,xzr
 subs x26,x19,x5
 sbcs x27,x20,x6
 sbcs x28,x21,x7
 sbcs x0,x22,x8
 sbcs x1,x23,x9
 sbcs x3,x24,x10
 sbcs xzr, x25,xzr
 csel x11,x19,x26,lo
 csel x12,x20,x27,lo
 csel x13,x21,x28,lo
 csel x14,x22,x0,lo
 csel x15,x23,x1,lo
 csel x16,x24,x3,lo
 ret
.size cw_word384___mul_mont_384,.-cw_word384___mul_mont_384
.globl cw_word384_sqr_mont_384
.hidden cw_word384_sqr_mont_384
.type cw_word384_sqr_mont_384,%function
.align 5
cw_word384_sqr_mont_384:
 hint #25
 stp x29,x30,[sp,#-16*8]!
 add x29,sp,#0
 stp x19,x20,[sp,#2*8]
 stp x21,x22,[sp,#4*8]
 stp x23,x24,[sp,#6*8]
 stp x25,x26,[sp,#8*8]
 stp x27,x28,[sp,#10*8]
 sub sp,sp,#96
 mov x4,x3
 mov x3,x0
 mov x0,sp
 ldp x11,x12,[x1]
 ldp x13,x14,[x1,#16]
 ldp x15,x16,[x1,#32]
 bl cw_word384___sqr_384
 ldp x5,x6,[x2]
 ldp x7,x8,[x2,#16]
 ldp x9,x10,[x2,#32]
 mov x1,sp
 mov x0,x3
 bl cw_word384___mul_by_1_mont_384
 bl cw_word384___redc_tail_mont_384
 ldr x30,[x29,#8]
 add sp,sp,#96
 ldp x19,x20,[x29,#2*8]
 ldp x21,x22,[x29,#4*8]
 ldp x23,x24,[x29,#6*8]
 ldp x25,x26,[x29,#8*8]
 ldp x27,x28,[x29,#10*8]
 ldr x29,[sp],#16*8
 hint #29
 ret
.size cw_word384_sqr_mont_384,.-cw_word384_sqr_mont_384
.globl cw_word384_sqr_n_mul_mont_383
.hidden cw_word384_sqr_n_mul_mont_383
.type cw_word384_sqr_n_mul_mont_383,%function
.align 5
cw_word384_sqr_n_mul_mont_383:
 hint #25
 stp x29,x30,[sp,#-16*8]!
 add x29,sp,#0
 stp x19,x20,[sp,#2*8]
 stp x21,x22,[sp,#4*8]
 stp x23,x24,[sp,#6*8]
 stp x25,x26,[sp,#8*8]
 stp x27,x28,[sp,#10*8]
 stp x4,x0,[sp,#12*8]
 sub sp,sp,#96
 mov x17,x5
 ldp x11,x12,[x1]
 ldp x13,x14,[x1,#16]
 ldp x15,x16,[x1,#32]
 mov x0,sp
.Loop_sqr_383:
 bl cw_word384___sqr_384
 sub x2,x2,#1
 ldp x5,x6,[x3]
 ldp x7,x8,[x3,#16]
 ldp x9,x10,[x3,#32]
 mov x1,sp
 bl cw_word384___mul_by_1_mont_384
 ldp x19,x20,[x1,#48]
 ldp x21,x22,[x1,#64]
 ldp x23,x24,[x1,#80]
 adds x11,x11,x19
 adcs x12,x12,x20
 adcs x13,x13,x21
 adcs x14,x14,x22
 adcs x15,x15,x23
 adc x16,x16,x24
 cbnz x2,.Loop_sqr_383
 mov x2,x17
 ldr x17,[x17]
 bl cw_word384___mul_mont_384
 ldr x30,[x29,#8]
 stp x11,x12,[x2]
 stp x13,x14,[x2,#16]
 stp x15,x16,[x2,#32]
 add sp,sp,#96
 ldp x19,x20,[x29,#2*8]
 ldp x21,x22,[x29,#4*8]
 ldp x23,x24,[x29,#6*8]
 ldp x25,x26,[x29,#8*8]
 ldp x27,x28,[x29,#10*8]
 ldr x29,[sp],#16*8
 hint #29
 ret
.size cw_word384_sqr_n_mul_mont_383,.-cw_word384_sqr_n_mul_mont_383
.type cw_word384___sqr_384,%function
.align 5
cw_word384___sqr_384:
 mul x19,x12,x11
 mul x20,x13,x11
 mul x21,x14,x11
 mul x22,x15,x11
 mul x23,x16,x11
 umulh x6,x12,x11
 umulh x7,x13,x11
 umulh x8,x14,x11
 umulh x9,x15,x11
 adds x20,x20,x6
 umulh x10,x16,x11
 adcs x21,x21,x7
 mul x7,x13,x12
 adcs x22,x22,x8
 mul x8,x14,x12
 adcs x23,x23,x9
 mul x9,x15,x12
 adc x24,xzr, x10
 mul x10,x16,x12
 adds x21,x21,x7
 umulh x7,x13,x12
 adcs x22,x22,x8
 umulh x8,x14,x12
 adcs x23,x23,x9
 umulh x9,x15,x12
 adcs x24,x24,x10
 umulh x10,x16,x12
 adc x25,xzr,xzr
 mul x5,x11,x11
 adds x22,x22,x7
 umulh x11, x11,x11
 adcs x23,x23,x8
 mul x8,x14,x13
 adcs x24,x24,x9
 mul x9,x15,x13
 adc x25,x25,x10
 mul x10,x16,x13
 adds x23,x23,x8
 umulh x8,x14,x13
 adcs x24,x24,x9
 umulh x9,x15,x13
 adcs x25,x25,x10
 umulh x10,x16,x13
 adc x26,xzr,xzr
 mul x6,x12,x12
 adds x24,x24,x8
 umulh x12, x12,x12
 adcs x25,x25,x9
 mul x9,x15,x14
 adc x26,x26,x10
 mul x10,x16,x14
 adds x25,x25,x9
 umulh x9,x15,x14
 adcs x26,x26,x10
 umulh x10,x16,x14
 adc x27,xzr,xzr
 mul x7,x13,x13
 adds x26,x26,x9
 umulh x13, x13,x13
 adc x27,x27,x10
 mul x8,x14,x14
 mul x10,x16,x15
 umulh x14, x14,x14
 adds x27,x27,x10
 umulh x10,x16,x15
 mul x9,x15,x15
 adc x28,x10,xzr
 adds x19,x19,x19
 adcs x20,x20,x20
 adcs x21,x21,x21
 adcs x22,x22,x22
 adcs x23,x23,x23
 adcs x24,x24,x24
 adcs x25,x25,x25
 adcs x26,x26,x26
 umulh x15, x15,x15
 adcs x27,x27,x27
 mul x10,x16,x16
 adcs x28,x28,x28
 umulh x16, x16,x16
 adc x1,xzr,xzr
 adds x19,x19,x11
 adcs x20,x20,x6
 adcs x21,x21,x12
 adcs x22,x22,x7
 adcs x23,x23,x13
 adcs x24,x24,x8
 adcs x25,x25,x14
 stp x5,x19,[x0]
 adcs x26,x26,x9
 stp x20,x21,[x0,#16]
 adcs x27,x27,x15
 stp x22,x23,[x0,#32]
 adcs x28,x28,x10
 stp x24,x25,[x0,#48]
 adc x16,x16,x1
 stp x26,x27,[x0,#64]
 stp x28,x16,[x0,#80]
 ret
.size cw_word384___sqr_384,.-cw_word384___sqr_384
.globl cw_word384_sqr_384
.hidden cw_word384_sqr_384
.type cw_word384_sqr_384,%function
.align 5
cw_word384_sqr_384:
 hint #25
 stp x29,x30,[sp,#-16*8]!
 add x29,sp,#0
 stp x19,x20,[sp,#2*8]
 stp x21,x22,[sp,#4*8]
 stp x23,x24,[sp,#6*8]
 stp x25,x26,[sp,#8*8]
 stp x27,x28,[sp,#10*8]
 ldp x11,x12,[x1]
 ldp x13,x14,[x1,#16]
 ldp x15,x16,[x1,#32]
 bl cw_word384___sqr_384
 ldr x30,[x29,#8]
 ldp x19,x20,[x29,#2*8]
 ldp x21,x22,[x29,#4*8]
 ldp x23,x24,[x29,#6*8]
 ldp x25,x26,[x29,#8*8]
 ldp x27,x28,[x29,#10*8]
 ldr x29,[sp],#16*8
 hint #29
 ret
.size cw_word384_sqr_384,.-cw_word384_sqr_384
.globl cw_word384_redc_mont_384
.hidden cw_word384_redc_mont_384
.type cw_word384_redc_mont_384,%function
.align 5
cw_word384_redc_mont_384:
 hint #25
 stp x29,x30,[sp,#-16*8]!
 add x29,sp,#0
 stp x19,x20,[sp,#2*8]
 stp x21,x22,[sp,#4*8]
 stp x23,x24,[sp,#6*8]
 stp x25,x26,[sp,#8*8]
 stp x27,x28,[sp,#10*8]
 mov x4,x3
 ldp x5,x6,[x2]
 ldp x7,x8,[x2,#16]
 ldp x9,x10,[x2,#32]
 bl cw_word384___mul_by_1_mont_384
 bl cw_word384___redc_tail_mont_384
 ldr x30,[x29,#8]
 ldp x19,x20,[x29,#2*8]
 ldp x21,x22,[x29,#4*8]
 ldp x23,x24,[x29,#6*8]
 ldp x25,x26,[x29,#8*8]
 ldp x27,x28,[x29,#10*8]
 ldr x29,[sp],#16*8
 hint #29
 ret
.size cw_word384_redc_mont_384,.-cw_word384_redc_mont_384
.globl cw_word384_from_mont_384
.hidden cw_word384_from_mont_384
.type cw_word384_from_mont_384,%function
.align 5
cw_word384_from_mont_384:
 hint #25
 stp x29,x30,[sp,#-16*8]!
 add x29,sp,#0
 stp x19,x20,[sp,#2*8]
 stp x21,x22,[sp,#4*8]
 stp x23,x24,[sp,#6*8]
 stp x25,x26,[sp,#8*8]
 stp x27,x28,[sp,#10*8]
 mov x4,x3
 ldp x5,x6,[x2]
 ldp x7,x8,[x2,#16]
 ldp x9,x10,[x2,#32]
 bl cw_word384___mul_by_1_mont_384
 ldr x30,[x29,#8]
 subs x19,x11,x5
 sbcs x20,x12,x6
 sbcs x21,x13,x7
 sbcs x22,x14,x8
 sbcs x23,x15,x9
 sbcs x24,x16,x10
 csel x11,x11,x19,lo
 csel x12,x12,x20,lo
 csel x13,x13,x21,lo
 csel x14,x14,x22,lo
 csel x15,x15,x23,lo
 csel x16,x16,x24,lo
 stp x11,x12,[x0]
 stp x13,x14,[x0,#16]
 stp x15,x16,[x0,#32]
 ldp x19,x20,[x29,#2*8]
 ldp x21,x22,[x29,#4*8]
 ldp x23,x24,[x29,#6*8]
 ldp x25,x26,[x29,#8*8]
 ldp x27,x28,[x29,#10*8]
 ldr x29,[sp],#16*8
 hint #29
 ret
.size cw_word384_from_mont_384,.-cw_word384_from_mont_384
.type cw_word384___mul_by_1_mont_384,%function
.align 5
cw_word384___mul_by_1_mont_384:
 ldp x11,x12,[x1]
 ldp x13,x14,[x1,#16]
 mul x26,x4,x11
 ldp x15,x16,[x1,#32]
 mul x20,x6,x26
 mul x21,x7,x26
 mul x22,x8,x26
 mul x23,x9,x26
 mul x24,x10,x26
 subs xzr,x11,#1
 umulh x11,x5,x26
 adcs x20,x20,x12
 umulh x12,x6,x26
 adcs x21,x21,x13
 umulh x13,x7,x26
 adcs x22,x22,x14
 umulh x14,x8,x26
 adcs x23,x23,x15
 umulh x15,x9,x26
 adcs x24,x24,x16
 umulh x16,x10,x26
 adc x25,xzr,xzr
 adds x11,x11,x20
 adcs x12,x12,x21
 adcs x13,x13,x22
 mul x26,x4,x11
 adcs x14,x14,x23
 adcs x15,x15,x24
 adc x16,x16,x25
 mul x20,x6,x26
 mul x21,x7,x26
 mul x22,x8,x26
 mul x23,x9,x26
 mul x24,x10,x26
 subs xzr,x11,#1
 umulh x11,x5,x26
 adcs x20,x20,x12
 umulh x12,x6,x26
 adcs x21,x21,x13
 umulh x13,x7,x26
 adcs x22,x22,x14
 umulh x14,x8,x26
 adcs x23,x23,x15
 umulh x15,x9,x26
 adcs x24,x24,x16
 umulh x16,x10,x26
 adc x25,xzr,xzr
 adds x11,x11,x20
 adcs x12,x12,x21
 adcs x13,x13,x22
 mul x26,x4,x11
 adcs x14,x14,x23
 adcs x15,x15,x24
 adc x16,x16,x25
 mul x20,x6,x26
 mul x21,x7,x26
 mul x22,x8,x26
 mul x23,x9,x26
 mul x24,x10,x26
 subs xzr,x11,#1
 umulh x11,x5,x26
 adcs x20,x20,x12
 umulh x12,x6,x26
 adcs x21,x21,x13
 umulh x13,x7,x26
 adcs x22,x22,x14
 umulh x14,x8,x26
 adcs x23,x23,x15
 umulh x15,x9,x26
 adcs x24,x24,x16
 umulh x16,x10,x26
 adc x25,xzr,xzr
 adds x11,x11,x20
 adcs x12,x12,x21
 adcs x13,x13,x22
 mul x26,x4,x11
 adcs x14,x14,x23
 adcs x15,x15,x24
 adc x16,x16,x25
 mul x20,x6,x26
 mul x21,x7,x26
 mul x22,x8,x26
 mul x23,x9,x26
 mul x24,x10,x26
 subs xzr,x11,#1
 umulh x11,x5,x26
 adcs x20,x20,x12
 umulh x12,x6,x26
 adcs x21,x21,x13
 umulh x13,x7,x26
 adcs x22,x22,x14
 umulh x14,x8,x26
 adcs x23,x23,x15
 umulh x15,x9,x26
 adcs x24,x24,x16
 umulh x16,x10,x26
 adc x25,xzr,xzr
 adds x11,x11,x20
 adcs x12,x12,x21
 adcs x13,x13,x22
 mul x26,x4,x11
 adcs x14,x14,x23
 adcs x15,x15,x24
 adc x16,x16,x25
 mul x20,x6,x26
 mul x21,x7,x26
 mul x22,x8,x26
 mul x23,x9,x26
 mul x24,x10,x26
 subs xzr,x11,#1
 umulh x11,x5,x26
 adcs x20,x20,x12
 umulh x12,x6,x26
 adcs x21,x21,x13
 umulh x13,x7,x26
 adcs x22,x22,x14
 umulh x14,x8,x26
 adcs x23,x23,x15
 umulh x15,x9,x26
 adcs x24,x24,x16
 umulh x16,x10,x26
 adc x25,xzr,xzr
 adds x11,x11,x20
 adcs x12,x12,x21
 adcs x13,x13,x22
 mul x26,x4,x11
 adcs x14,x14,x23
 adcs x15,x15,x24
 adc x16,x16,x25
 mul x20,x6,x26
 mul x21,x7,x26
 mul x22,x8,x26
 mul x23,x9,x26
 mul x24,x10,x26
 subs xzr,x11,#1
 umulh x11,x5,x26
 adcs x20,x20,x12
 umulh x12,x6,x26
 adcs x21,x21,x13
 umulh x13,x7,x26
 adcs x22,x22,x14
 umulh x14,x8,x26
 adcs x23,x23,x15
 umulh x15,x9,x26
 adcs x24,x24,x16
 umulh x16,x10,x26
 adc x25,xzr,xzr
 adds x11,x11,x20
 adcs x12,x12,x21
 adcs x13,x13,x22
 adcs x14,x14,x23
 adcs x15,x15,x24
 adc x16,x16,x25
 ret
.size cw_word384___mul_by_1_mont_384,.-cw_word384___mul_by_1_mont_384
.type cw_word384___redc_tail_mont_384,%function
.align 5
cw_word384___redc_tail_mont_384:
 ldp x19,x20,[x1,#48]
 ldp x21,x22,[x1,#64]
 ldp x23,x24,[x1,#80]
 adds x11,x11,x19
 adcs x12,x12,x20
 adcs x13,x13,x21
 adcs x14,x14,x22
 adcs x15,x15,x23
 adcs x16,x16,x24
 adc x25,xzr,xzr
 subs x19,x11,x5
 sbcs x20,x12,x6
 sbcs x21,x13,x7
 sbcs x22,x14,x8
 sbcs x23,x15,x9
 sbcs x24,x16,x10
 sbcs xzr,x25,xzr
 csel x11,x11,x19,lo
 csel x12,x12,x20,lo
 csel x13,x13,x21,lo
 csel x14,x14,x22,lo
 csel x15,x15,x23,lo
 csel x16,x16,x24,lo
 stp x11,x12,[x0]
 stp x13,x14,[x0,#16]
 stp x15,x16,[x0,#32]
 ret
.size cw_word384___redc_tail_mont_384,.-cw_word384___redc_tail_mont_384
.globl cw_word384_mul_384
.hidden cw_word384_mul_384
.type cw_word384_mul_384,%function
.align 5
cw_word384_mul_384:
 hint #25
 stp x29,x30,[sp,#-16*8]!
 add x29,sp,#0
 stp x19,x20,[sp,#2*8]
 stp x21,x22,[sp,#4*8]
 stp x23,x24,[sp,#6*8]
 stp x25,x26,[sp,#8*8]
 stp x27,x28,[sp,#10*8]
 bl cw_word384___mul_384
 ldr x30,[x29,#8]
 ldp x19,x20,[x29,#2*8]
 ldp x21,x22,[x29,#4*8]
 ldp x23,x24,[x29,#6*8]
 ldp x25,x26,[x29,#8*8]
 ldp x27,x28,[x29,#10*8]
 ldr x29,[sp],#16*8
 hint #29
 ret
.size cw_word384_mul_384,.-cw_word384_mul_384
.type cw_word384___mul_384,%function
.align 5
cw_word384___mul_384:
 ldp x11,x12,[x1]
 ldr x17, [x2]
 ldp x13,x14,[x1,#16]
 ldp x15,x16,[x1,#32]
 mul x19,x11,x17
 mul x20,x12,x17
 mul x21,x13,x17
 mul x22,x14,x17
 mul x23,x15,x17
 mul x24,x16,x17
 umulh x5,x11,x17
 umulh x6,x12,x17
 umulh x7,x13,x17
 umulh x8,x14,x17
 umulh x9,x15,x17
 umulh x10,x16,x17
 ldr x17,[x2,8*1]
 str x19,[x0]
 adds x19,x20,x5
 mul x5,x11,x17
 adcs x20,x21,x6
 mul x6,x12,x17
 adcs x21,x22,x7
 mul x7,x13,x17
 adcs x22,x23,x8
 mul x8,x14,x17
 adcs x23,x24,x9
 mul x9,x15,x17
 adc x24,xzr, x10
 mul x10,x16,x17
 adds x19,x19,x5
 umulh x5,x11,x17
 adcs x20,x20,x6
 umulh x6,x12,x17
 adcs x21,x21,x7
 umulh x7,x13,x17
 adcs x22,x22,x8
 umulh x8,x14,x17
 adcs x23,x23,x9
 umulh x9,x15,x17
 adcs x24,x24,x10
 umulh x10,x16,x17
 ldr x17,[x2,#8*(1+1)]
 adc x25,xzr,xzr
 str x19,[x0,8*1]
 adds x19,x20,x5
 mul x5,x11,x17
 adcs x20,x21,x6
 mul x6,x12,x17
 adcs x21,x22,x7
 mul x7,x13,x17
 adcs x22,x23,x8
 mul x8,x14,x17
 adcs x23,x24,x9
 mul x9,x15,x17
 adc x24,x25,x10
 mul x10,x16,x17
 adds x19,x19,x5
 umulh x5,x11,x17
 adcs x20,x20,x6
 umulh x6,x12,x17
 adcs x21,x21,x7
 umulh x7,x13,x17
 adcs x22,x22,x8
 umulh x8,x14,x17
 adcs x23,x23,x9
 umulh x9,x15,x17
 adcs x24,x24,x10
 umulh x10,x16,x17
 ldr x17,[x2,#8*(2+1)]
 adc x25,xzr,xzr
 str x19,[x0,8*2]
 adds x19,x20,x5
 mul x5,x11,x17
 adcs x20,x21,x6
 mul x6,x12,x17
 adcs x21,x22,x7
 mul x7,x13,x17
 adcs x22,x23,x8
 mul x8,x14,x17
 adcs x23,x24,x9
 mul x9,x15,x17
 adc x24,x25,x10
 mul x10,x16,x17
 adds x19,x19,x5
 umulh x5,x11,x17
 adcs x20,x20,x6
 umulh x6,x12,x17
 adcs x21,x21,x7
 umulh x7,x13,x17
 adcs x22,x22,x8
 umulh x8,x14,x17
 adcs x23,x23,x9
 umulh x9,x15,x17
 adcs x24,x24,x10
 umulh x10,x16,x17
 ldr x17,[x2,#8*(3+1)]
 adc x25,xzr,xzr
 str x19,[x0,8*3]
 adds x19,x20,x5
 mul x5,x11,x17
 adcs x20,x21,x6
 mul x6,x12,x17
 adcs x21,x22,x7
 mul x7,x13,x17
 adcs x22,x23,x8
 mul x8,x14,x17
 adcs x23,x24,x9
 mul x9,x15,x17
 adc x24,x25,x10
 mul x10,x16,x17
 adds x19,x19,x5
 umulh x5,x11,x17
 adcs x20,x20,x6
 umulh x6,x12,x17
 adcs x21,x21,x7
 umulh x7,x13,x17
 adcs x22,x22,x8
 umulh x8,x14,x17
 adcs x23,x23,x9
 umulh x9,x15,x17
 adcs x24,x24,x10
 umulh x10,x16,x17
 ldr x17,[x2,#8*(4+1)]
 adc x25,xzr,xzr
 str x19,[x0,8*4]
 adds x19,x20,x5
 mul x5,x11,x17
 adcs x20,x21,x6
 mul x6,x12,x17
 adcs x21,x22,x7
 mul x7,x13,x17
 adcs x22,x23,x8
 mul x8,x14,x17
 adcs x23,x24,x9
 mul x9,x15,x17
 adc x24,x25,x10
 mul x10,x16,x17
 adds x19,x19,x5
 umulh x5,x11,x17
 adcs x20,x20,x6
 umulh x6,x12,x17
 adcs x21,x21,x7
 umulh x7,x13,x17
 adcs x22,x22,x8
 umulh x8,x14,x17
 adcs x23,x23,x9
 umulh x9,x15,x17
 adcs x24,x24,x10
 umulh x10,x16,x17
 adc x25,xzr,xzr
 str x19,[x0,8*5]
 adds x19,x20,x5
 adcs x20,x21,x6
 adcs x21,x22,x7
 adcs x22,x23,x8
 adcs x23,x24,x9
 adc x24,x25,x10
 stp x19,x20,[x0,#48]
 stp x21,x22,[x0,#64]
 stp x23,x24,[x0,#80]
 ret
.size cw_word384___mul_384,.-cw_word384___mul_384
.globl cw_word384_mul_382x
.hidden cw_word384_mul_382x
.type cw_word384_mul_382x,%function
.align 5
cw_word384_mul_382x:
 hint #25
 stp x29,x30,[sp,#-16*8]!
 add x29,sp,#0
 stp x19,x20,[sp,#2*8]
 stp x21,x22,[sp,#4*8]
 stp x23,x24,[sp,#6*8]
 stp x25,x26,[sp,#8*8]
 stp x27,x28,[sp,#10*8]
 sub sp,sp,#96
 ldp x11,x12,[x1]
 mov x26,x0
 ldp x19,x20,[x1,#48]
 mov x27,x1
 ldp x13,x14,[x1,#16]
 mov x28,x2
 ldp x21,x22,[x1,#64]
 ldp x15,x16,[x1,#32]
 adds x5,x11,x19
 ldp x23,x24,[x1,#80]
 adcs x6,x12,x20
 ldp x11,x12,[x2]
 adcs x7,x13,x21
 ldp x19,x20,[x2,#48]
 adcs x8,x14,x22
 ldp x13,x14,[x2,#16]
 adcs x9,x15,x23
 ldp x21,x22,[x2,#64]
 adc x10,x16,x24
 ldp x15,x16,[x2,#32]
 stp x5,x6,[sp]
 adds x5,x11,x19
 ldp x23,x24,[x2,#80]
 adcs x6,x12,x20
 stp x7,x8,[sp,#16]
 adcs x7,x13,x21
 adcs x8,x14,x22
 stp x9,x10,[sp,#32]
 adcs x9,x15,x23
 stp x5,x6,[sp,#48]
 adc x10,x16,x24
 stp x7,x8,[sp,#64]
 stp x9,x10,[sp,#80]
 bl cw_word384___mul_384
 add x1,sp,#0
 add x2,sp,#48
 add x0,x26,#96
 bl cw_word384___mul_384
 add x1,x27,#48
 add x2,x28,#48
 add x0,sp,#0
 bl cw_word384___mul_384
 ldp x5,x6,[x3]
 ldp x7,x8,[x3,#16]
 ldp x9,x10,[x3,#32]
 add x1,x26,#96
 add x2,sp,#0
 add x0,x26,#96
 bl cw_word384___sub_mod_384x384
 add x2,x26,#0
 bl cw_word384___sub_mod_384x384
 add x1,x26,#0
 add x2,sp,#0
 add x0,x26,#0
 bl cw_word384___sub_mod_384x384
 ldr x30,[x29,#8]
 add sp,sp,#96
 ldp x19,x20,[x29,#2*8]
 ldp x21,x22,[x29,#4*8]
 ldp x23,x24,[x29,#6*8]
 ldp x25,x26,[x29,#8*8]
 ldp x27,x28,[x29,#10*8]
 ldr x29,[sp],#16*8
 hint #29
 ret
.size cw_word384_mul_382x,.-cw_word384_mul_382x
.globl cw_word384_sqr_382x
.hidden cw_word384_sqr_382x
.type cw_word384_sqr_382x,%function
.align 5
cw_word384_sqr_382x:
 hint #25
 stp x29,x30,[sp,#-16*8]!
 add x29,sp,#0
 stp x19,x20,[sp,#2*8]
 stp x21,x22,[sp,#4*8]
 stp x23,x24,[sp,#6*8]
 stp x25,x26,[sp,#8*8]
 stp x27,x28,[sp,#10*8]
 ldp x11,x12,[x1]
 ldp x19,x20,[x1,#48]
 ldp x13,x14,[x1,#16]
 adds x5,x11,x19
 ldp x21,x22,[x1,#64]
 adcs x6,x12,x20
 ldp x15,x16,[x1,#32]
 adcs x7,x13,x21
 ldp x23,x24,[x1,#80]
 adcs x8,x14,x22
 stp x5,x6,[x0]
 adcs x9,x15,x23
 ldp x5,x6,[x2]
 adc x10,x16,x24
 stp x7,x8,[x0,#16]
 subs x11,x11,x19
 ldp x7,x8,[x2,#16]
 sbcs x12,x12,x20
 stp x9,x10,[x0,#32]
 sbcs x13,x13,x21
 ldp x9,x10,[x2,#32]
 sbcs x14,x14,x22
 sbcs x15,x15,x23
 sbcs x16,x16,x24
 sbc x25,xzr,xzr
 and x19,x5,x25
 and x20,x6,x25
 adds x11,x11,x19
 and x21,x7,x25
 adcs x12,x12,x20
 and x22,x8,x25
 adcs x13,x13,x21
 and x23,x9,x25
 adcs x14,x14,x22
 and x24,x10,x25
 adcs x15,x15,x23
 stp x11,x12,[x0,#48]
 adc x16,x16,x24
 stp x13,x14,[x0,#64]
 stp x15,x16,[x0,#80]
 mov x4,x1
 add x1,x0,#0
 add x2,x0,#48
 bl cw_word384___mul_384
 add x1,x4,#0
 add x2,x4,#48
 add x0,x0,#96
 bl cw_word384___mul_384
 ldr x30,[x29,#8]
 ldp x11,x12,[x0]
 ldp x13,x14,[x0,#16]
 adds x11,x11,x11
 ldp x15,x16,[x0,#32]
 adcs x12,x12,x12
 adcs x13,x13,x13
 adcs x14,x14,x14
 adcs x15,x15,x15
 adcs x16,x16,x16
 adcs x19,x19,x19
 adcs x20,x20,x20
 stp x11,x12,[x0]
 adcs x21,x21,x21
 stp x13,x14,[x0,#16]
 adcs x22,x22,x22
 stp x15,x16,[x0,#32]
 adcs x23,x23,x23
 stp x19,x20,[x0,#48]
 adc x24,x24,x24
 stp x21,x22,[x0,#64]
 stp x23,x24,[x0,#80]
 ldp x19,x20,[x29,#2*8]
 ldp x21,x22,[x29,#4*8]
 ldp x23,x24,[x29,#6*8]
 ldp x25,x26,[x29,#8*8]
 ldp x27,x28,[x29,#10*8]
 ldr x29,[sp],#16*8
 hint #29
 ret
.size cw_word384_sqr_382x,.-cw_word384_sqr_382x
.globl cw_word384_sqr_mont_382x
.hidden cw_word384_sqr_mont_382x
.type cw_word384_sqr_mont_382x,%function
.align 5
cw_word384_sqr_mont_382x:
 hint #25
 stp x29,x30,[sp,#-16*8]!
 add x29,sp,#0
 stp x19,x20,[sp,#2*8]
 stp x21,x22,[sp,#4*8]
 stp x23,x24,[sp,#6*8]
 stp x25,x26,[sp,#8*8]
 stp x27,x28,[sp,#10*8]
 stp x3,x0,[sp,#12*8]
 sub sp,sp,#112
 mov x4,x3
 ldp x11,x12,[x1]
 ldp x13,x14,[x1,#16]
 ldp x15,x16,[x1,#32]
 ldp x17,x20,[x1,#48]
 ldp x21,x22,[x1,#64]
 ldp x23,x24,[x1,#80]
 adds x5,x11,x17
 adcs x6,x12,x20
 adcs x7,x13,x21
 adcs x8,x14,x22
 adcs x9,x15,x23
 adc x10,x16,x24
 subs x19,x11,x17
 sbcs x20,x12,x20
 sbcs x21,x13,x21
 sbcs x22,x14,x22
 sbcs x23,x15,x23
 sbcs x24,x16,x24
 sbc x25,xzr,xzr
 stp x5,x6,[sp]
 stp x7,x8,[sp,#16]
 stp x9,x10,[sp,#32]
 stp x19,x20,[sp,#48]
 stp x21,x22,[sp,#64]
 stp x23,x24,[sp,#80]
 str x25,[sp,#96]
 ldp x5,x6,[x2]
 ldp x7,x8,[x2,#16]
 ldp x9,x10,[x2,#32]
 add x2,x1,#48
 bl cw_word384___mul_mont_383_nonred
 adds x19,x11,x11
 adcs x20,x12,x12
 adcs x21,x13,x13
 adcs x22,x14,x14
 adcs x23,x15,x15
 adc x24,x16,x16
 stp x19,x20,[x2,#48]
 stp x21,x22,[x2,#64]
 stp x23,x24,[x2,#80]
 ldp x11,x12,[sp]
 ldr x17,[sp,#48]
 ldp x13,x14,[sp,#16]
 ldp x15,x16,[sp,#32]
 add x2,sp,#48
 bl cw_word384___mul_mont_383_nonred
 ldr x30,[x29,#8]
 ldr x25,[sp,#96]
 ldp x19,x20,[sp]
 ldp x21,x22,[sp,#16]
 ldp x23,x24,[sp,#32]
 and x19,x19,x25
 and x20,x20,x25
 and x21,x21,x25
 and x22,x22,x25
 and x23,x23,x25
 and x24,x24,x25
 subs x11,x11,x19
 sbcs x12,x12,x20
 sbcs x13,x13,x21
 sbcs x14,x14,x22
 sbcs x15,x15,x23
 sbcs x16,x16,x24
 sbc x25,xzr,xzr
 and x19,x5,x25
 and x20,x6,x25
 and x21,x7,x25
 and x22,x8,x25
 and x23,x9,x25
 and x24,x10,x25
 adds x11,x11,x19
 adcs x12,x12,x20
 adcs x13,x13,x21
 adcs x14,x14,x22
 adcs x15,x15,x23
 adc x16,x16,x24
 stp x11,x12,[x2]
 stp x13,x14,[x2,#16]
 stp x15,x16,[x2,#32]
 add sp,sp,#112
 ldp x19,x20,[x29,#2*8]
 ldp x21,x22,[x29,#4*8]
 ldp x23,x24,[x29,#6*8]
 ldp x25,x26,[x29,#8*8]
 ldp x27,x28,[x29,#10*8]
 ldr x29,[sp],#16*8
 hint #29
 ret
.size cw_word384_sqr_mont_382x,.-cw_word384_sqr_mont_382x
.type cw_word384___mul_mont_383_nonred,%function
.align 5
cw_word384___mul_mont_383_nonred:
 mul x19,x11,x17
 mul x20,x12,x17
 mul x21,x13,x17
 mul x22,x14,x17
 mul x23,x15,x17
 mul x24,x16,x17
 mul x4,x4,x19
 umulh x26,x11,x17
 umulh x27,x12,x17
 umulh x28,x13,x17
 umulh x0,x14,x17
 umulh x1,x15,x17
 umulh x3,x16,x17
 adds x20,x20,x26
 mul x26,x5,x4
 adcs x21,x21,x27
 mul x27,x6,x4
 adcs x22,x22,x28
 mul x28,x7,x4
 adcs x23,x23,x0
 mul x0,x8,x4
 adcs x24,x24,x1
 mul x1,x9,x4
 adc x25,xzr, x3
 mul x3,x10,x4
 ldr x17,[x2,8*1]
 adds x19,x19,x26
 umulh x26,x5,x4
 adcs x20,x20,x27
 umulh x27,x6,x4
 adcs x21,x21,x28
 umulh x28,x7,x4
 adcs x22,x22,x0
 umulh x0,x8,x4
 adcs x23,x23,x1
 umulh x1,x9,x4
 adcs x24,x24,x3
 umulh x3,x10,x4
 adc x25,x25,xzr
 ldr x4,[x29,#12*8]
 adds x19,x20,x26
 mul x26,x11,x17
 adcs x20,x21,x27
 mul x27,x12,x17
 adcs x21,x22,x28
 mul x28,x13,x17
 adcs x22,x23,x0
 mul x0,x14,x17
 adcs x23,x24,x1
 mul x1,x15,x17
 adcs x24,x25,x3
 mul x3,x16,x17
 adc x25,xzr,xzr
 adds x19,x19,x26
 umulh x26,x11,x17
 adcs x20,x20,x27
 umulh x27,x12,x17
 adcs x21,x21,x28
 mul x4,x4,x19
 umulh x28,x13,x17
 adcs x22,x22,x0
 umulh x0,x14,x17
 adcs x23,x23,x1
 umulh x1,x15,x17
 adcs x24,x24,x3
 umulh x3,x16,x17
 adc x25,x25,xzr
 adds x20,x20,x26
 mul x26,x5,x4
 adcs x21,x21,x27
 mul x27,x6,x4
 adcs x22,x22,x28
 mul x28,x7,x4
 adcs x23,x23,x0
 mul x0,x8,x4
 adcs x24,x24,x1
 mul x1,x9,x4
 adc x25,x25,x3
 mul x3,x10,x4
 ldr x17,[x2,8*2]
 adds x19,x19,x26
 umulh x26,x5,x4
 adcs x20,x20,x27
 umulh x27,x6,x4
 adcs x21,x21,x28
 umulh x28,x7,x4
 adcs x22,x22,x0
 umulh x0,x8,x4
 adcs x23,x23,x1
 umulh x1,x9,x4
 adcs x24,x24,x3
 umulh x3,x10,x4
 adc x25,x25,xzr
 ldr x4,[x29,#12*8]
 adds x19,x20,x26
 mul x26,x11,x17
 adcs x20,x21,x27
 mul x27,x12,x17
 adcs x21,x22,x28
 mul x28,x13,x17
 adcs x22,x23,x0
 mul x0,x14,x17
 adcs x23,x24,x1
 mul x1,x15,x17
 adcs x24,x25,x3
 mul x3,x16,x17
 adc x25,xzr,xzr
 adds x19,x19,x26
 umulh x26,x11,x17
 adcs x20,x20,x27
 umulh x27,x12,x17
 adcs x21,x21,x28
 mul x4,x4,x19
 umulh x28,x13,x17
 adcs x22,x22,x0
 umulh x0,x14,x17
 adcs x23,x23,x1
 umulh x1,x15,x17
 adcs x24,x24,x3
 umulh x3,x16,x17
 adc x25,x25,xzr
 adds x20,x20,x26
 mul x26,x5,x4
 adcs x21,x21,x27
 mul x27,x6,x4
 adcs x22,x22,x28
 mul x28,x7,x4
 adcs x23,x23,x0
 mul x0,x8,x4
 adcs x24,x24,x1
 mul x1,x9,x4
 adc x25,x25,x3
 mul x3,x10,x4
 ldr x17,[x2,8*3]
 adds x19,x19,x26
 umulh x26,x5,x4
 adcs x20,x20,x27
 umulh x27,x6,x4
 adcs x21,x21,x28
 umulh x28,x7,x4
 adcs x22,x22,x0
 umulh x0,x8,x4
 adcs x23,x23,x1
 umulh x1,x9,x4
 adcs x24,x24,x3
 umulh x3,x10,x4
 adc x25,x25,xzr
 ldr x4,[x29,#12*8]
 adds x19,x20,x26
 mul x26,x11,x17
 adcs x20,x21,x27
 mul x27,x12,x17
 adcs x21,x22,x28
 mul x28,x13,x17
 adcs x22,x23,x0
 mul x0,x14,x17
 adcs x23,x24,x1
 mul x1,x15,x17
 adcs x24,x25,x3
 mul x3,x16,x17
 adc x25,xzr,xzr
 adds x19,x19,x26
 umulh x26,x11,x17
 adcs x20,x20,x27
 umulh x27,x12,x17
 adcs x21,x21,x28
 mul x4,x4,x19
 umulh x28,x13,x17
 adcs x22,x22,x0
 umulh x0,x14,x17
 adcs x23,x23,x1
 umulh x1,x15,x17
 adcs x24,x24,x3
 umulh x3,x16,x17
 adc x25,x25,xzr
 adds x20,x20,x26
 mul x26,x5,x4
 adcs x21,x21,x27
 mul x27,x6,x4
 adcs x22,x22,x28
 mul x28,x7,x4
 adcs x23,x23,x0
 mul x0,x8,x4
 adcs x24,x24,x1
 mul x1,x9,x4
 adc x25,x25,x3
 mul x3,x10,x4
 ldr x17,[x2,8*4]
 adds x19,x19,x26
 umulh x26,x5,x4
 adcs x20,x20,x27
 umulh x27,x6,x4
 adcs x21,x21,x28
 umulh x28,x7,x4
 adcs x22,x22,x0
 umulh x0,x8,x4
 adcs x23,x23,x1
 umulh x1,x9,x4
 adcs x24,x24,x3
 umulh x3,x10,x4
 adc x25,x25,xzr
 ldr x4,[x29,#12*8]
 adds x19,x20,x26
 mul x26,x11,x17
 adcs x20,x21,x27
 mul x27,x12,x17
 adcs x21,x22,x28
 mul x28,x13,x17
 adcs x22,x23,x0
 mul x0,x14,x17
 adcs x23,x24,x1
 mul x1,x15,x17
 adcs x24,x25,x3
 mul x3,x16,x17
 adc x25,xzr,xzr
 adds x19,x19,x26
 umulh x26,x11,x17
 adcs x20,x20,x27
 umulh x27,x12,x17
 adcs x21,x21,x28
 mul x4,x4,x19
 umulh x28,x13,x17
 adcs x22,x22,x0
 umulh x0,x14,x17
 adcs x23,x23,x1
 umulh x1,x15,x17
 adcs x24,x24,x3
 umulh x3,x16,x17
 adc x25,x25,xzr
 adds x20,x20,x26
 mul x26,x5,x4
 adcs x21,x21,x27
 mul x27,x6,x4
 adcs x22,x22,x28
 mul x28,x7,x4
 adcs x23,x23,x0
 mul x0,x8,x4
 adcs x24,x24,x1
 mul x1,x9,x4
 adc x25,x25,x3
 mul x3,x10,x4
 ldr x17,[x2,8*5]
 adds x19,x19,x26
 umulh x26,x5,x4
 adcs x20,x20,x27
 umulh x27,x6,x4
 adcs x21,x21,x28
 umulh x28,x7,x4
 adcs x22,x22,x0
 umulh x0,x8,x4
 adcs x23,x23,x1
 umulh x1,x9,x4
 adcs x24,x24,x3
 umulh x3,x10,x4
 adc x25,x25,xzr
 ldr x4,[x29,#12*8]
 adds x19,x20,x26
 mul x26,x11,x17
 adcs x20,x21,x27
 mul x27,x12,x17
 adcs x21,x22,x28
 mul x28,x13,x17
 adcs x22,x23,x0
 mul x0,x14,x17
 adcs x23,x24,x1
 mul x1,x15,x17
 adcs x24,x25,x3
 mul x3,x16,x17
 adc x25,xzr,xzr
 adds x19,x19,x26
 umulh x26,x11,x17
 adcs x20,x20,x27
 umulh x27,x12,x17
 adcs x21,x21,x28
 mul x4,x4,x19
 umulh x28,x13,x17
 adcs x22,x22,x0
 umulh x0,x14,x17
 adcs x23,x23,x1
 umulh x1,x15,x17
 adcs x24,x24,x3
 umulh x3,x16,x17
 adc x25,x25,xzr
 adds x20,x20,x26
 mul x26,x5,x4
 adcs x21,x21,x27
 mul x27,x6,x4
 adcs x22,x22,x28
 mul x28,x7,x4
 adcs x23,x23,x0
 mul x0,x8,x4
 adcs x24,x24,x1
 mul x1,x9,x4
 adc x25,x25,x3
 mul x3,x10,x4
 adds x19,x19,x26
 umulh x26,x5,x4
 adcs x20,x20,x27
 umulh x27,x6,x4
 adcs x21,x21,x28
 umulh x28,x7,x4
 adcs x22,x22,x0
 umulh x0,x8,x4
 adcs x23,x23,x1
 umulh x1,x9,x4
 adcs x24,x24,x3
 umulh x3,x10,x4
 adc x25,x25,xzr
 ldp x4,x2,[x29,#12*8]
 adds x11,x20,x26
 adcs x12,x21,x27
 adcs x13,x22,x28
 adcs x14,x23,x0
 adcs x15,x24,x1
 adcs x16,x25,x3
 ret
.size cw_word384___mul_mont_383_nonred,.-cw_word384___mul_mont_383_nonred
.globl cw_word384_sgn0_pty_mont_384
.hidden cw_word384_sgn0_pty_mont_384
.type cw_word384_sgn0_pty_mont_384,%function
.align 5
cw_word384_sgn0_pty_mont_384:
 hint #25
 stp x29,x30,[sp,#-16*8]!
 add x29,sp,#0
 stp x19,x20,[sp,#2*8]
 stp x21,x22,[sp,#4*8]
 stp x23,x24,[sp,#6*8]
 stp x25,x26,[sp,#8*8]
 stp x27,x28,[sp,#10*8]
 mov x4,x2
 ldp x5,x6,[x1]
 ldp x7,x8,[x1,#16]
 ldp x9,x10,[x1,#32]
 mov x1,x0
 bl cw_word384___mul_by_1_mont_384
 ldr x30,[x29,#8]
 and x0,x11,#1
 adds x11,x11,x11
 adcs x12,x12,x12
 adcs x13,x13,x13
 adcs x14,x14,x14
 adcs x15,x15,x15
 adcs x16,x16,x16
 adc x17,xzr,xzr
 subs x11,x11,x5
 sbcs x12,x12,x6
 sbcs x13,x13,x7
 sbcs x14,x14,x8
 sbcs x15,x15,x9
 sbcs x16,x16,x10
 sbc x17,x17,xzr
 mvn x17,x17
 and x17,x17,#2
 orr x0,x0,x17
 ldp x19,x20,[x29,#2*8]
 ldp x21,x22,[x29,#4*8]
 ldp x23,x24,[x29,#6*8]
 ldp x25,x26,[x29,#8*8]
 ldp x27,x28,[x29,#10*8]
 ldr x29,[sp],#16*8
 hint #29
 ret
.size cw_word384_sgn0_pty_mont_384,.-cw_word384_sgn0_pty_mont_384
.globl cw_word384_sgn0_pty_mont_384x
.hidden cw_word384_sgn0_pty_mont_384x
.type cw_word384_sgn0_pty_mont_384x,%function
.align 5
cw_word384_sgn0_pty_mont_384x:
 hint #25
 stp x29,x30,[sp,#-16*8]!
 add x29,sp,#0
 stp x19,x20,[sp,#2*8]
 stp x21,x22,[sp,#4*8]
 stp x23,x24,[sp,#6*8]
 stp x25,x26,[sp,#8*8]
 stp x27,x28,[sp,#10*8]
 mov x4,x2
 ldp x5,x6,[x1]
 ldp x7,x8,[x1,#16]
 ldp x9,x10,[x1,#32]
 mov x1,x0
 bl cw_word384___mul_by_1_mont_384
 add x1,x1,#48
 and x2,x11,#1
 orr x3,x11,x12
 adds x11,x11,x11
 orr x3,x3,x13
 adcs x12,x12,x12
 orr x3,x3,x14
 adcs x13,x13,x13
 orr x3,x3,x15
 adcs x14,x14,x14
 orr x3,x3,x16
 adcs x15,x15,x15
 adcs x16,x16,x16
 adc x17,xzr,xzr
 subs x11,x11,x5
 sbcs x12,x12,x6
 sbcs x13,x13,x7
 sbcs x14,x14,x8
 sbcs x15,x15,x9
 sbcs x16,x16,x10
 sbc x17,x17,xzr
 mvn x17,x17
 and x17,x17,#2
 orr x2,x2,x17
 bl cw_word384___mul_by_1_mont_384
 ldr x30,[x29,#8]
 and x0,x11,#1
 orr x1,x11,x12
 adds x11,x11,x11
 orr x1,x1,x13
 adcs x12,x12,x12
 orr x1,x1,x14
 adcs x13,x13,x13
 orr x1,x1,x15
 adcs x14,x14,x14
 orr x1,x1,x16
 adcs x15,x15,x15
 adcs x16,x16,x16
 adc x17,xzr,xzr
 subs x11,x11,x5
 sbcs x12,x12,x6
 sbcs x13,x13,x7
 sbcs x14,x14,x8
 sbcs x15,x15,x9
 sbcs x16,x16,x10
 sbc x17,x17,xzr
 mvn x17,x17
 and x17,x17,#2
 orr x0,x0,x17
 cmp x3,#0
 csel x3,x0,x2,eq
 cmp x1,#0
 csel x1,x0,x2,ne
 and x3,x3,#1
 and x1,x1,#2
 orr x0,x1,x3
 ldp x19,x20,[x29,#2*8]
 ldp x21,x22,[x29,#4*8]
 ldp x23,x24,[x29,#6*8]
 ldp x25,x26,[x29,#8*8]
 ldp x27,x28,[x29,#10*8]
 ldr x29,[sp],#16*8
 hint #29
 ret
.size cw_word384_sgn0_pty_mont_384x,.-cw_word384_sgn0_pty_mont_384x
