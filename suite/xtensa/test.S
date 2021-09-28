# Xtensa test assembly file
# The output of the disassembler
# needs to (mostly) match this file.
#
# The _ that precedes some instructions
# prevent the compiler from using alternative
# instructions (such as using movi.n
# instead of movi or vice-versa).
#
# Some of the instructions are commented
# out either because the assembler does not
# support them or the assembler cannot generate
# the instruction in isolation (i.e. it will
# put a nop before or after the instruction).

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

# These instructions don't assemble correctly
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

idtlb	a0

# The compiler doesn't know these instructions
# iiu	a0,	0
# iiu	a1,	4
# iiu	a15,	240

ill
ill.n

# ipf	a0,	0
# ipf	a1,	4
# ipf	a2,	1000
# ipf	a3,	1020

# ipfl	a0,	0
# ipfl	a1,	4
# ipfl	a3,	240

isync

_j	0
_jx	a0

l8ui	a0,	a9,	0
l8ui	a1,	a8,	1
l8ui	a2,	a7,	100
l8ui	a3,	a6,	200
l8ui	a4,	a5,	255

l16si	a0,	a5,	0
l16si	a1,	a4,	2
l16si	a2,	a3,	510

l16ui	a0,	a1,	128

l32ai	a0,	a1,	512

l32e	a0,	a9,	-4
l32e	a1,	a8,	-8
l32e	a2,	a7,	-16
l32e	a3,	a6,	-60
l32e	a4,	a5,	-64

_l32i	a0,	a15,	0
_l32i	a1,	a14,	4
_l32i	a2,	a13,	100
_l32i	a3,	a12,	1000
_l32i	a4,	a11,	1020

_l32i.n	a9,	a8,	0
_l32i.n	a9,	a8,	4
_l32i.n	a9,	a8,	8
_l32i.n	a9,	a8,	56
_l32i.n	a9,	a8,	60

_l32r	a0,	0

# The compiler doesn't know this instruction
# ldct	a0,	a1

lddec	m0,	a0
lddec	m1,	a1
lddec	m2,	a2
lddec	m3,	a3

ldinc	m0,	a0
ldinc	m1,	a1
ldinc	m2,	a2
ldinc	m3,	a3

# The compiler doesn't know these instructions
# lict	a0,	a1
# licw	a0,	a1

# the loop instrutions don't assemble correctly
# _loop	a0,	0
# _loopgtz	a0,	0
# _loopnez	a0,	0

lsi	f3,	a3,	100
# The compiler doesn't know this instruction
# lsiu	f3,	a3,	100

lsx	f5,	a5,	a6
# The compiler doesn't know this instruction
# lsxu	f5,	a5,	a6

madd.s	f0,	f0,	f0
madd.s	f1,	f2,	f3

max	a0,	a1,	a2
maxu	a0,	a1,	a2

memw

min	a0,	a1,	a2
minu	a0,	a1,	a2

_mov.n	a0,	a15
_mov.n	a7,	a8

mov.s	f0,	f1
mov.s	f15,	f2

moveqz	a0,	a1,	a2
moveqz	a15,	a14,	a13

moveqz.s	f0,	f1,	a2

movf	a0,	a1,	b4
movf.s	f0,	f1,	b1

movgez	a0,	a1,	a2
movgez	a15,	a14,	a13

movgez.s	f0,	f1,	a2

_movi	a0,	0
_movi	a1,	100
_movi	a2,	-100
_movi	a3,	-2000
_movi	a4,	2000
_movi	a5,	-2048
_movi	a6,	2047

_movi.n	a0,	-17
_movi.n	a1,	-1
_movi.n	a2,	0
_movi.n	a3,	10
_movi.n	a4,	95
_movi.n	a5,	-32

movltz	a0,	a1,	a2
movltz.s	f0,	f1,	a2

movnez	a0,	a1,	a2
movnez.s	f0,	f1,	a2

movsp	a0,	a1

movt	a0,	a1,	b4
movt.s	f0,	f1,	b1

msub.s	f0,	f1,	f2

mul.aa.ll	a0,	a10
mul.aa.hl	a3,	a11
mul.aa.lh	a9,	a12
mul.aa.hh	a3,	a15
mul.ad.ll	a0,	m2
mul.ad.hl	a3,	m3
mul.ad.lh	a9,	m2
mul.ad.hh	a3,	m3
mul.da.ll	m0,	a10
mul.da.hl	m1,	a11
mul.da.lh	m1,	a12
mul.da.hh	m0,	a15
mul.dd.ll	m1,	m3
mul.dd.hl	m0,	m2
mul.dd.lh	m0,	m2
mul.dd.hh	m1,	m3

mul.s	f0,	f1,	f2

mul16s	a0,	a1,	a2
mul16u	a0,	a1,	a2


mula.aa.ll	a0,	a10
mula.aa.hl	a3,	a11
mula.aa.lh	a9,	a12
mula.aa.hh	a3,	a15
mula.ad.ll	a0,	m2
mula.ad.hl	a3,	m3
mula.ad.lh	a9,	m2
mula.ad.hh	a3,	m3
mula.da.ll	m0,	a10
mula.da.hl	m1,	a11
mula.da.lh	m1,	a12
mula.da.hh	m0,	a15
mula.dd.ll	m1,	m3
mula.dd.hl	m0,	m2
mula.dd.lh	m0,	m2
mula.dd.hh	m1,	m3

mula.da.ll.lddec	m0,	a10,	m1,	a1
mula.da.hl.lddec	m1,	a11,	m0,	a8
mula.da.lh.lddec	m2,	a12,	m1,	a2
mula.da.hh.lddec	m3,	a15,	m0,	a7
mula.da.ll.ldinc	m0,	a10,	m0,	a3
mula.da.hl.ldinc	m1,	a11,	m0,	a6
mula.da.lh.ldinc	m2,	a12,	m1,	a4
mula.da.hh.ldinc	m3,	a15,	m0,	a5

mula.dd.ll.lddec	m0,	a0,	m0,	m2
mula.dd.hl.lddec	m1,	a1,	m1,	m3
mula.dd.lh.lddec	m2,	a2,	m1,	m2
mula.dd.hh.lddec	m3,	a3,	m0,	m2
mula.dd.ll.ldinc	m0,	a4,	m0,	m3
mula.dd.hl.ldinc	m1,	a5,	m1,	m2
mula.dd.lh.ldinc	m2,	a6,	m0,	m3
mula.dd.hh.ldinc	m3,	a7,	m1,	m3

mull	a0,	a1,	a2

muls.aa.ll	a0,	a10
muls.aa.hl	a3,	a11
muls.aa.lh	a9,	a12
muls.aa.hh	a3,	a15
muls.ad.ll	a0,	m2
muls.ad.hl	a3,	m3
muls.ad.lh	a9,	m2
muls.ad.hh	a3,	m3
muls.da.ll	m0,	a10
muls.da.hl	m1,	a11
muls.da.lh	m1,	a12
muls.da.hh	m0,	a15
muls.dd.ll	m1,	m3
muls.dd.hl	m0,	m2
muls.dd.lh	m0,	m2
muls.dd.hh	m1,	m3

mulsh	a10,	a11,	a12
muluh	a10,	a11,	a12

neg	a10,	a11

neg.s	f1,	f9

_nop

_nop.n

nsa	a10,	a11
nsau	a10,	a11

oeq.s	b11,	f7,	f3
ole.s	b1,	f1,	f8
olt.s	b5,	f11,	f13

or	a0,	a1,	a3
orb	b0,	b1,	b2
orbc	b5,	b6,	b7

pdtlb	a13,	a11

pitlb	a13,	a11

quos	a1,	a2,	a3
quou	a7,	a8,	a9

rdtlb0	a7,	a6
rdtlb1	a3,	a4

rems	a1,	a2,	a3
remu	a1,	a2,	a3
rer	a0,	a0

_ret
_ret.n
_retw
_retw.n

rfdd
rfde
# note: the next isntruction takes an operand
# but not according to the reference manual
rfdo	15
rfe

rfi	0
rfi	7
rfi	1
rfi	15

# compiler doesn't know this one
# rfme

rfr	a1,	f9

# compiler doesn't know this one
# rfue

rfwo
rfwu

ritlb0	a3,	a4
ritlb1	a3,	a4

rotw	-8
rotw	-1
rotw	0
rotw	1
rotw	7

round.s	a3,	f6,	0
round.s	a11,	f9,	15

rsil	a1,	0
rsil	a6,	14

# some are commented out since
# the compiler doesn't seem to know
# about them.
rsr.lbeg	a7
rsr.lend	a7
rsr.lcount	a7
rsr.sar	a7
rsr.br	a7
rsr.litbase	a7
rsr.scompare1	a7
rsr.acclo	a7
rsr.acchi	a7
rsr.m0	a7
rsr.m1	a7
rsr.m2	a7
rsr.m3	a7
rsr.windowbase	a7
rsr.windowstart	a7
# rsr.ptevaddr	a7
# rsr.mmid	a7
# rsr.rasid	a7
# rsr.itlbcfg	a7
# rsr.dtlbcfg	a7
rsr.ibreakenable	a7
rsr.atomctl	a7
rsr.ddr	a7
# rsr.meps	a7
# rsr.mepc	a7
# rsr.mesave	a7
# rsr.mesr	a7
# rsr.mecr	a7
# rsr.mevaddr	a7
rsr.ibreaka0	a7
rsr.ibreaka1	a7
rsr.debugcause	a7
rsr.dbreaka0	a7
rsr.dbreaka1	a7
rsr.dbreakc0	a7
rsr.dbreakc1	a7
rsr.epc1	a7
rsr.epc2	a7
rsr.epc3	a7
rsr.epc4	a7
rsr.epc5	a7
rsr.epc6	a7
rsr.epc7	a7
rsr.depc	a7
rsr.eps2	a7
rsr.eps3	a7
rsr.eps4	a7
rsr.eps5	a7
rsr.eps6	a7
rsr.eps7	a7
rsr.excsave1	a7
rsr.excsave2	a7
rsr.excsave3	a7
rsr.excsave4	a7
rsr.excsave5	a7
rsr.excsave6	a7
rsr.excsave7	a7
rsr.cpenable	a7
rsr.interrupt	a7
# rsr.intclear	a7
rsr.intenable	a7
rsr.ps	a7
rsr.vecbase	a7
rsr.exccause	a7
rsr.ccount	a7
rsr.prid	a7
rsr.icount	a7
rsr.icountlevel	a7
rsr.excvaddr	a7
rsr.ccompare0	a7
rsr.ccompare1	a7
rsr.ccompare2	a7
rsr.misc0	a7
rsr.misc1	a7
rsr.misc2	a7
rsr.misc3	a7

rsync

rur.threadptr	a1
rur.fcr	a7
rur.fsr	a8

s8i	a0,	a1,	0
s8i	a1,	a2,	1
s8i	a4,	a3,	100
s8i	a7,	a4,	200
s8i	a9,	a5,	250
s8i	a2,	a6,	255

s16i	a0,	a1,	0
s16i	a1,	a2,	2
s16i	a4,	a3,	4
s16i	a7,	a4,	250
s16i	a9,	a5,	500
s16i	a2,	a6,	510

s32c1i	a0,	a1,	0
s32c1i	a1,	a2,	4
s32c1i	a4,	a3,	8
s32c1i	a7,	a4,	500
s32c1i	a9,	a5,	1000
s32c1i	a2,	a6,	1020

s32e	a1,	a1,	-64
s32e	a2,	a0,	-20
s32e	a3,	a1,	-8
s32e	a4,	a0,	-4

_s32i	a0,	a1,	0
_s32i	a1,	a2,	4
_s32i	a4,	a3,	8
_s32i	a7,	a4,	500
_s32i	a9,	a5,	1000
_s32i	a2,	a6,	1020

_s32i.n	a0,	a1,	0
_s32i.n	a1,	a2,	4
_s32i.n	a2,	a3,	20
_s32i.n	a3,	a4,	60


s32ri	a0,	a1,	0
s32ri	a1,	a2,	4
s32ri	a4,	a3,	8
s32ri	a7,	a4,	500
s32ri	a9,	a5,	1000
s32ri	a2,	a6,	1020

# sdct	a0,	a1

sext	a0,	a1,	7
sext	a0,	a1,	8
sext	a0,	a1,	9
sext	a10,	a1,	10
sext	a0,	a1,	11
sext	a10,	a1,	12
sext	a0,	a1,	20
sext	a10,	a11,	21
sext	a0,	a7,	22
