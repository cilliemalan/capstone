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

_movi.n	a0,	-17
_movi.n	a0,	-1
_movi.n	a0,	0
_movi.n	a0,	10
_movi.n	a0,	95
_movi.n	a0,	-32
