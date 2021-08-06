# Xtensa test assembly file
# The output of the disassembler
# needs to (mostly) match this file.
#
# Note: the _ that precedes some instructions
# prevent the compiler from using alternative
# instructions (such as using movi.n
# instead of movi or vice-versa).

abs		a1,	a0
abs		a0,	a15
abs		a15,	a7

_add		a0,	a1,	a2
_add		a15,	a0,	a7

_add.n		a0,	a1,	a2
_add.n		a15,	a0,	a7

_movi.n		a0,	-17
_movi.n		a0,	0
_movi.n		a0,	10
_movi.n		a0,	95
_movi.n		a0,	-32
