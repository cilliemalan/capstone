# Xtensa test assembly file
# The output of the disassembler
# needs to (mostly) match this file.
#
# Note: the _ that precedes some instructions
# prevent the compiler from using alternative
# instructions (such as using movi.n
# instead of movi or vice-versa).

abs	a1,	a0
abs	a0,	a15
abs	a15,	a7

abs.s	f1,	f2
abs.s	f0,	f15
abs.s	f6,	f6

_add	a0,	a1,	a2
_add	a15,	a0,	a7

_add.n	a0,	a1,	a2
_add.n	a15,	a0,	a7

add.s	f1,	f2,	f3
add.s	f15,	f0,	f15

_addi	a0,	a2,	10
_addi	a0,	a2,	-10
_addi	a0,	a2,	-128
_addi	a0,	a2,	127
_addi	a0,	a2,	0

_addi.n	a5,	a1,	-1
_addi.n	a6,	a2,	1
_addi.n	a7,	a3,	5
_addi.n	a8,	a4,	15

addmi	a1,	a2,	-32768
addmi	a1,	a2,	32512
addmi	a1,	a2,	23296

addx2	a0,	a1,	a3
addx4	a4,	a5,	a6
addx8	a7,	a8,	a9

all4	b1,	b4
all8	b3,	b8

and	a1,	a2,	a3
andb	b1,	b2,	b3
andbc	b1,	b2,	b3

any4	b1,	b4
any8	b1,	b8

_ball	a1,	a2,	0

_bany	a1,	a2,	0

_bbc	a1,	a2,	0

_bbci	a1,	0,	0
_bbci	a1,	1,	0
_bbci	a1,	10,	0
_bbci	a1,	30,	0
_bbci	a1,	31,	0

_bbs	a1,	a15,	0

_bbsi	a1,	0,	0
_bbsi	a1,	1,	0
_bbsi	a1,	10,	0
_bbsi	a1,	30,	0
_bbsi	a1,	31,	0

_beq	a1,	a15,	0

_beqi	a1,	-1,	0
_beqi	a2,	1,	0
_beqi	a3,	2,	0
_beqi	a4,	3,	0
_beqi	a5,	4,	0
_beqi	a6,	8,	0
_beqi	a7,	10,	0
_beqi	a8,	12,	0
_beqi	a9,	16,	0
_beqi	a10,	32,	0
_beqi	a11,	64,	0
_beqi	a12,	128,	0
_beqi	a13,	256,	0

_beqz	a1,	0
_beqz	a2,	0
_beqz	a3,	0
_beqz	a4,	0

_bf	b0,	0
_bf	b15,	0

_bge	a0,	a1,	0
_bge	a10,	a11,	0

_bgei	a10,	-1,	0
_bgei	a11,	1,	0
_bgei	a12,	128,	0
_bgei	a13,	256,	0

_bgeu	a1,	a2,	0

_bgeui	a4,	65536,	0
_bgeui	a4,	32768,	0
_bgeui	a3,	2,	0
_bgeui	a4,	3,	0
_bgeui	a5,	4,	0
_bgeui	a6,	8,	0
_bgeui	a7,	10,	0
_bgeui	a8,	12,	0
_bgeui	a9,	16,	0
_bgeui	a10,	32,	0
_bgeui	a11,	64,	0
_bgeui	a12,	128,	0
_bgeui	a13,	256,	0

_bgez	a0,	0
_bgez	a15,	0

_blt	a0,	a1,	0
_blt	a11,	a13,	0

_blti	a0,	-1,	0
_blti	a0,	1,	0
_blti	a0,	128,	0
_blti	a0,	12,	0

_bltu	a0,	a1,	0
_bltu	a11,	a13,	0

_bltui	a0,	65536,	0
_bltui	a4,	32768,	0
_bltui	a8,	5,	0
_bltui	a12,	12,	0

_bltz	a0,	0
_bltz	a10,	0

_bnall	a0,	a1,	0
_bnall	a2,	a3,	0

_bne	a0,	a1,	0

_bnei	a0,	-1,	0
_bnei	a1,	1,	0

_bnez	a0,	0
_bnez	a10,	0

_bnez.n	a0,	0
_bnez.n	a6,	0
_bnez.n	a10,	0
_bnez.n	a15,	0

_bnone	a0,	a1,	0
_bnone	a10,	a11,	0

break	1,	2
break	0,	0
break	15,	15
break	0,	15
break	15,	0

break.n	0
break.n	2
break.n	10
break.n	15

_bt	b0,	0
_bt	b15,	0

_call0	0
_call4	0
_call8	0
_call12	0

_callx0	a0
_callx4	a1
_callx8	a2
_callx12	a3

ceil.s	a0,	f0,	4
ceil.s	a1,	f1,	0
ceil.s	a3,	f3,	15
ceil.s	a15,	f15,	10

clamps	a2,	a1,	7
clamps	a3,	a2,	8
clamps	a4,	a3,	9
clamps	a5,	a5,	10
clamps	a6,	a9,	21
clamps	a7,	a10,	22

dsync	

# entry	a1,	16
# entry	a2,	24
# entry	a3,	32
# entry	a4,	8000
# entry	a5,	32760

esync	
excw	

extui	a0,	a13,	4,	16
extui	a4,	a12,	1,	10
extui	a0,	a10,	31,	1
extui	a6,	a15,	30,	1
extui	a0,	a9,	0,	10
extui	a9,	a10,	1,	16

extw	

float.s	f0,	a15,	0
float.s	f1,	a14,	1
float.s	f15,	a1,	15

floor.s	a0,	f15,	0
floor.s	a1,	f14,	1
floor.s	a15,	f1,	15

_movi.n	a0,	-17
_movi.n	a1,	-1
_movi.n	a2,	0
_movi.n	a3,	10
_movi.n	a4,	95
_movi.n	a5,	-32
