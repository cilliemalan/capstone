#include "XtensaMapping.h"

#define STATIC_ASSERT(x, m) _Static_assert(x, m)

#ifndef ARRAYSIZE
#define ARRAYSIZE(x) (sizeof(x) / sizeof(x[0]))
#endif

static const char *xtensa_registers[] =
{
	NULL,
	"a0",
	"a1",
	"a2",
	"a3",
	"a4",
	"a5",
	"a6",
	"a7",
	"a8",
	"a9",
	"a10",
	"a11",
	"a12",
	"a13",
	"a14",
	"a15",
	"f0",
	"f1",
	"f2",
	"f3",
	"f4",
	"f5",
	"f6",
	"f7",
	"f8",
	"f9",
	"f10",
	"f11",
	"f12",
	"f13",
	"f14",
	"f15",
	"b0",
	"b1",
	"b2",
	"b3",
	"b4",
	"b5",
	"b6",
	"b7",
	"b8",
	"b9",
	"b10",
	"b11",
	"b12",
	"b13",
	"b14",
	"b15",
	"m0",
	"m1",
	"m2",
	"m3"
};

static const char *xtensa_instructions[] =
{
	NULL,
	"abs",
	"abs.s",
	"add",
	"add.n",
	"add.s",
	"addi",
	"addi.n",
	"addmi",
	"addx2",
	"addx4",
	"addx8",
	"all4",
	"all8",
	"and",
	"andb",
	"andbc",
	"any4",
	"any8",
	"ball",
	"bany",
	"bbc",
	"bbci",
	"bbci.l",
	"bbs",
	"bbsi",
	"bbsi.l",
	"beq",
	"beqi",
	"beqz",
	"beqz.n",
	"bf",
	"bge",
	"bgei",
	"bgeu",
	"bgeui",
	"bgez",
	"blt",
	"blti",
	"bltu",
	"bltui",
	"bltz",
	"bnall",
	"bne",
	"bnei",
	"bnez",
	"bnez.n",
	"bnone",
	"break",
	"break.n",
	"bt",
	"call0",
	"call4",
	"call8",
	"call12",
	"callx0",
	"callx4",
	"callx8",
	"callx12",
	"ceil.s",
	"clamps",
	"dhi",
	"dhu",
	"dhwb",
	"dhwbi",
	"dii",
	"diu",
	"diwb",
	"diwbi",
	"dpfl",
	"dpfr",
	"dpfro",
	"dpfw",
	"dpfwo",
	"dsync",
	"entry",
	"esync",
	"excw",
	"extui",
	"extw",
	"float.s",
	"floor.s",
	"idtlb",
	"ihi",
	"ihu",
	"iii",
	"iitlb",
	"iiu",
	"ill",
	"ill.n",
	"ipf",
	"ipfl",
	"isync",
	"j",
	"jx",
	"l8ui",
	"l16si",
	"l16ui",
	"l32ai",
	"l32e",
	"l32i",
	"l32i.n",
	"l32r",
	"ldct",
	"lddec",
	"ldinc",
	"lict",
	"licw",
	"loop",
	"loopgtz",
	"loopnez",
	"lsi",
	"lsiu",
	"lsx",
	"lsxu",
	"madd.s",
	"max",
	"maxu",
	"memw",
	"min",
	"minu",
	"mov",
	"mov.n",
	"mov.s",
	"moveqz",
	"moveqz.s",
	"movf",
	"movf.s",
	"movgez",
	"movgez.s",
	"movi",
	"movi.n",
	"movltz",
	"movltz.s",
	"movnez",
	"movnez.s",
	"movsp",
	"movt",
	"movt.s",
	"msub.s",
	"mul.aa.ll",
	"mul.aa.hl",
	"mul.aa.lh",
	"mul.aa.hh",
	"mul.ad.ll",
	"mul.ad.hl",
	"mul.ad.lh",
	"mul.ad.hh",
	"mul.da.ll",
	"mul.da.hl",
	"mul.da.lh",
	"mul.da.hh",
	"mul.da.ll",
	"mul.da.hl",
	"mul.da.lh",
	"mul.da.hh",
	"mul.dd.ll",
	"mul.dd.hl",
	"mul.dd.lh",
	"mul.dd.hh",
	"mul.s",
	"mul16s",
	"mul16u",
	"mula.aa.ll",
	"mula.aa.hl",
	"mula.aa.lh",
	"mula.aa.hh",
	"mula.ad.ll",
	"mula.ad.hl",
	"mula.ad.lh",
	"mula.ad.hh",
	"mula.da.ll",
	"mula.da.hl",
	"mula.da.lh",
	"mula.da.hh",
	"mula.da.lllddec",
	"mula.da.hllddec",
	"mula.da.lhlddec",
	"mula.da.hhlddec",
	"mula.dd.ll",
	"mula.dd.hl",
	"mula.dd.lh",
	"mula.dd.hh",
	"mula.dd.lllddec",
	"mula.dd.hllddec",
	"mula.dd.lhlddec",
	"mula.dd.hhlddec",
	"mula.dd.llldinc",
	"mula.dd.hlldinc",
	"mula.dd.lhldinc",
	"mula.dd.hhldinc",
	"mull",
	"muls.aa.ll",
	"muls.aa.hl",
	"muls.aa.lh",
	"muls.aa.hh",
	"muls.ad.ll",
	"muls.ad.hl",
	"muls.ad.lh",
	"muls.ad.hh",
	"muls.da.ll",
	"muls.da.hl",
	"muls.da.lh",
	"muls.da.hh",
	"muls.dd.ll",
	"muls.dd.hl",
	"muls.dd.lh",
	"muls.dd.hh",
	"mulsh",
	"muluh",
	"neg",
	"neg.s",
	"nop",
	"nop.n",
	"nsa",
	"nsau",
	"qeq.s",
	"ole.s",
	"olt.s",
	"or",
	"orb",
	"orbs",
	"pdtlb",
	"pitlb",
	"quos",
	"quou",
	"rdtlb0",
	"rdtlb1",
	"rems",
	"remu",
	"rer",
	"ret",
	"ret.n",
	"retw",
	"retw.n",
	"rfdd",
	"rfde",
	"rfdo",
	"rfe",
	"rfi",
	"rfme",
	"rfr",
	"rfue",
	"rfwo",
	"rfwu",
	"ritlb0",
	"ritlb1",
	"rotw",
	"round.s",
	"rsil",
	"rsr",
	"rsync",
	"rur",
	"s8i",
	"s16i",
	"s32c1i",
	"s32e",
	"s32i",
	"s32i.n",
	"s32ri",
	"sdct",
	"sext",
	"sict",
	"sicw",
	"simcall",
	"sll",
	"slli",
	"sra",
	"srai",
	"src",
	"srl",
	"srli",
	"ssa8b",
	"ssa8l",
	"ssai",
	"ssi",
	"ssiu",
	"ssl",
	"ssr",
	"ssx",
	"ssxu",
	"sub",
	"sub.s",
	"subx2",
	"subx4",
	"subx8",
	"syscall",
	"trunc.s",
	"ueq.s",
	"ufloat.s",
	"ule.s",
	"ult.s",
	"umul.aa.ll",
	"umul.aa.hl",
	"umul.aa.lh",
	"umul.aa.hh",
	"un.s",
	"utrunc.s",
	"waiti",
	"wdtlb",
	"wer",
	"wfr",
	"witlb",
	"wsr",
	"wur",
	"xor",
	"xorb",
	"xsr",
};

static const char *xtensa_groups[] =
{
	NULL,
	"Jump",
	"Call",
	"Return",
	"Interrupt",
	NULL,
	NULL,
	"Conditional Branch",
	"Load",
	"Store",
	"Memory Ordering",
	"Move",
	"Arithmetic",
	"Bitwise",
	"Shift",
	"Processor Control",
	"Loop",
	"L32R",
	"MAC16",
	"Miscellaneous",
	"Coprocessor",
	"Boolean",
	"Floating-Point Arithmetic",
	"Multiprocessor Synchronization",
	"Conditional Store",
	"Exception",
	"Cache",
};

void Xtensa_get_insn_id(cs_struct *h, cs_insn *insn, unsigned int id)
{
	insn->id = id;
}

const char *Xtensa_reg_name(csh handle, unsigned int id)
{
	if (id >= 0 && id < ARRAYSIZE(xtensa_registers))
	{
		return xtensa_registers[id];
	}
	else
	{
		return NULL;
	}
}

const char *Xtensa_sysreg_name(csh handle, unsigned int id)
{
	switch (id)
	{
	case XTENSA_SPECIAL_REG_LBEG: return "lbeg";
	case XTENSA_SPECIAL_REG_LEND: return "lend";
	case XTENSA_SPECIAL_REG_LCOUNT: return "lcount";
	case XTENSA_SPECIAL_REG_SAR: return "sar";
	case XTENSA_SPECIAL_REG_BR: return "br";
	case XTENSA_SPECIAL_REG_LITBASE: return "litbase";
	case XTENSA_SPECIAL_REG_SCOMPARE1: return "scompare1";
	case XTENSA_SPECIAL_REG_ACCLO: return "acclo";
	case XTENSA_SPECIAL_REG_ACCHI: return "acchi";
	case XTENSA_SPECIAL_REG_MR0: return "mr0";
	case XTENSA_SPECIAL_REG_MR1: return "mr1";
	case XTENSA_SPECIAL_REG_MR2: return "mr2";
	case XTENSA_SPECIAL_REG_MR3: return "mr3";
	case XTENSA_SPECIAL_REG_WINDOWBASE: return "windowbase";
	case XTENSA_SPECIAL_REG_WINDOWSTART: return "windowstart";
	case XTENSA_SPECIAL_REG_PTEVADDR: return "ptevaddr";
	case XTENSA_SPECIAL_REG_MMID: return "mmid";
	case XTENSA_SPECIAL_REG_RASID: return "rasid";
	case XTENSA_SPECIAL_REG_ITLBCFG: return "itlbcfg";
	case XTENSA_SPECIAL_REG_DTLBCFG: return "dtlbcfg";
	case XTENSA_SPECIAL_REG_IBREAKENABLE: return "ibreakenable";
	case XTENSA_SPECIAL_REG_ATOMCTL: return "atomctl";
	case XTENSA_SPECIAL_REG_DDR: return "ddr";
	case XTENSA_SPECIAL_REG_MEPS: return "meps";
	case XTENSA_SPECIAL_REG_MEPC: return "mepc";
	case XTENSA_SPECIAL_REG_MESAVE: return "mesave";
	case XTENSA_SPECIAL_REG_MESR: return "mesr";
	case XTENSA_SPECIAL_REG_MECR: return "mecr";
	case XTENSA_SPECIAL_REG_MEVADDR: return "mevaddr";
	case XTENSA_SPECIAL_REG_IBREAKA0: return "ibreaka0";
	case XTENSA_SPECIAL_REG_IBREAKA1: return "ibreaka1";
	case XTENSA_SPECIAL_REG_DEBUGCAUSE: return "debugcause";
	case XTENSA_SPECIAL_REG_DBREAKA0: return "dbreaka0";
	case XTENSA_SPECIAL_REG_DBREAKA1: return "dbreaka1";
	case XTENSA_SPECIAL_REG_DBREAKC0: return "dbreakc0";
	case XTENSA_SPECIAL_REG_DBREAKC1: return "dbreakc1";
	case XTENSA_SPECIAL_REG_EPC1: return "epc1";
	case XTENSA_SPECIAL_REG_EPC2: return "epc2";
	case XTENSA_SPECIAL_REG_EPC3: return "epc3";
	case XTENSA_SPECIAL_REG_EPC4: return "epc4";
	case XTENSA_SPECIAL_REG_EPC5: return "epc5";
	case XTENSA_SPECIAL_REG_EPC6: return "epc6";
	case XTENSA_SPECIAL_REG_EPC7: return "epc7";
	case XTENSA_SPECIAL_REG_DEPC: return "depc";
	case XTENSA_SPECIAL_REG_EPS2: return "eps2";
	case XTENSA_SPECIAL_REG_EPS3: return "eps3";
	case XTENSA_SPECIAL_REG_EPS4: return "eps4";
	case XTENSA_SPECIAL_REG_EPS5: return "eps5";
	case XTENSA_SPECIAL_REG_EPS6: return "eps6";
	case XTENSA_SPECIAL_REG_EPS7: return "eps7";
	case XTENSA_SPECIAL_REG_EXCSAVE1: return "excsave1";
	case XTENSA_SPECIAL_REG_EXCSAVE2: return "excsave2";
	case XTENSA_SPECIAL_REG_EXCSAVE3: return "excsave3";
	case XTENSA_SPECIAL_REG_EXCSAVE4: return "excsave4";
	case XTENSA_SPECIAL_REG_EXCSAVE5: return "excsave5";
	case XTENSA_SPECIAL_REG_EXCSAVE6: return "excsave6";
	case XTENSA_SPECIAL_REG_EXCSAVE7: return "excsave7";
	case XTENSA_SPECIAL_REG_CPENABLE: return "cpenable";
	case XTENSA_SPECIAL_REG_INTERRUPT: return "interrupt";
	case XTENSA_SPECIAL_REG_INTCLEAR: return "intclear";
	case XTENSA_SPECIAL_REG_INTENABLE: return "intenable";
	case XTENSA_SPECIAL_REG_PS: return "ps";
	case XTENSA_SPECIAL_REG_VECBASE: return "vecbase";
	case XTENSA_SPECIAL_REG_EXCCAUSE: return "exccause";
	case XTENSA_SPECIAL_REG_CCOUNT: return "ccount";
	case XTENSA_SPECIAL_REG_PRID: return "prid";
	case XTENSA_SPECIAL_REG_ICOUNT: return "icount";
	case XTENSA_SPECIAL_REG_ICOUNTLEVEL: return "icountlevel";
	case XTENSA_SPECIAL_REG_EXCVADDR: return "excvaddr";
	case XTENSA_SPECIAL_REG_CCOMPARE0: return "ccompare0";
	case XTENSA_SPECIAL_REG_CCOMPARE1: return "ccompare1";
	case XTENSA_SPECIAL_REG_CCOMPARE2: return "ccompare2";
	case XTENSA_SPECIAL_REG_MISC0: return "misc0";
	case XTENSA_SPECIAL_REG_MISC1: return "misc1";
	case XTENSA_SPECIAL_REG_MISC2: return "misc2";
	case XTENSA_SPECIAL_REG_MISC3: return "misc3";
	default: return NULL;
	}
	return NULL;
}

const char *Xtensa_userreg_name(csh handle, unsigned int id)
{
	switch (id)
	{
	case XTENSA_USER_REG_THREADPTR: return "threadptr";
	case XTENSA_USER_REG_FCR: return "fcr";
	case XTENSA_USER_REG_FSR: return "fsr";
	default:
		// TODO: what about the other 252?
		return NULL;
	}
}

const char *Xtensa_insn_name(csh handle, unsigned int id)
{
	if (id >= 0 && id < ARRAYSIZE(xtensa_instructions))
	{
		return xtensa_instructions[id];
	}
	else
	{
		return NULL;
	}
}

const char *Xtensa_group_name(csh handle, unsigned int id)
{
	if (id >= 0 && id < ARRAYSIZE(xtensa_groups))
	{
		return xtensa_groups[id];
	}
	else
	{
		return NULL;
	}
}

const char *Xtensa_kind_name(unsigned int id)
{
	switch (id)
	{
	case XTENSA_OP_REG: return "Register";
	case XTENSA_OP_IMM: return "Immediate";
	case XTENSA_OP_FP: return "Floating-point Register";
	case XTENSA_OP_SYSREG: return "Special Register";
	case XTENSA_OP_USERREG: return "User Register";
	case XTENSA_OP_INVALID:
	case XTENSA_OP_MEM:
	default: return NULL;
	}
}
