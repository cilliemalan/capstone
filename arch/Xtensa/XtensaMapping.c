#include "XtensaMapping.h"

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
		"fr0",
		"fr1",
		"fr2",
		"fr3",
		"fr4",
		"fr5",
		"fr6",
		"fr7",
		"fr8",
		"fr9",
		"fr10",
		"fr11",
		"fr12",
		"fr13",
		"fr14",
		"fr15",
};

static const char *xtensa_instructions[] =
	{
		NULL,
		"ABS",
		"ABS_S",
		"ADD",
		"ADD_N",
		"ADD_S",
		"ADDI",
		"MOVI",
		"NEG",
};

static const char *xtensa_groups[] =
	{
		NULL,
		"Load",
		"Store",
		"Ordering",
		"Jump/Call",
		"Conditional Branch",
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
};

void Xtensa_get_insn_id(cs_struct *h, cs_insn *insn, unsigned int id)
{
	insn->id = insn->id;
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
	case XTENSA_SPECIAL_REG_LBEG:
		return "LBEG";
	case XTENSA_SPECIAL_REG_LEND:
		return "LEND";
	case XTENSA_SPECIAL_REG_LCOUNT:
		return "LCOUNT";
	case XTENSA_SPECIAL_REG_SAR:
		return "SAR";
	case XTENSA_SPECIAL_REG_BR:
		return "BR";
	case XTENSA_SPECIAL_REG_LITBASE:
		return "LITBASE";
	case XTENSA_SPECIAL_REG_SCOMPARE1:
		return "SCOMPARE1";
	case XTENSA_SPECIAL_REG_ACCLO:
		return "ACCLO";
	case XTENSA_SPECIAL_REG_ACCHI:
		return "ACCHI";
	case XTENSA_SPECIAL_REG_MR0:
		return "MR0";
	case XTENSA_SPECIAL_REG_MR1:
		return "MR1";
	case XTENSA_SPECIAL_REG_MR2:
		return "MR2";
	case XTENSA_SPECIAL_REG_MR3:
		return "MR3";
	case XTENSA_SPECIAL_REG_WINDOWBASE:
		return "WindowBase";
	case XTENSA_SPECIAL_REG_WINDOWSTART:
		return "WindowStart";
	case XTENSA_SPECIAL_REG_PTEVADDR:
		return "PTEVADDR";
	case XTENSA_SPECIAL_REG_MMID:
		return "MMID";
	case XTENSA_SPECIAL_REG_RASID:
		return "RASID";
	case XTENSA_SPECIAL_REG_ITLBCFG:
		return "ITLBCFG";
	case XTENSA_SPECIAL_REG_DTLBCFG:
		return "DTLBCFG";
	case XTENSA_SPECIAL_REG_IBREAKENABLE:
		return "IBREAKENABLE";
	case XTENSA_SPECIAL_REG_ATOMCTL:
		return "ATOMCTL";
	case XTENSA_SPECIAL_REG_DDR:
		return "DDR";
	case XTENSA_SPECIAL_REG_MEPS:
		return "MEPS";
	case XTENSA_SPECIAL_REG_MEPC:
		return "MEPC";
	case XTENSA_SPECIAL_REG_MESAVE:
		return "MESAVE";
	case XTENSA_SPECIAL_REG_MESR:
		return "MESR";
	case XTENSA_SPECIAL_REG_MECR:
		return "MECR";
	case XTENSA_SPECIAL_REG_MEVADDR:
		return "MEVADDR";
	case XTENSA_SPECIAL_REG_IBREAKA0:
		return "IBREAKA0";
	case XTENSA_SPECIAL_REG_IBREAKA1:
		return "IBREAKA1";
	case XTENSA_SPECIAL_REG_DEBUGCAUSE:
		return "DEBUGCAUSE";
	case XTENSA_SPECIAL_REG_DBREAKA0:
		return "DBREAKA0";
	case XTENSA_SPECIAL_REG_DBREAKA1:
		return "DBREAKA1";
	case XTENSA_SPECIAL_REG_DBREAKC0:
		return "DBREAKC0";
	case XTENSA_SPECIAL_REG_DBREAKC1:
		return "DBREAKC1";
	case XTENSA_SPECIAL_REG_EPC1:
		return "EPC1";
	case XTENSA_SPECIAL_REG_EPC2:
		return "EPC2";
	case XTENSA_SPECIAL_REG_EPC3:
		return "EPC3";
	case XTENSA_SPECIAL_REG_EPC4:
		return "EPC4";
	case XTENSA_SPECIAL_REG_EPC5:
		return "EPC5";
	case XTENSA_SPECIAL_REG_EPC6:
		return "EPC6";
	case XTENSA_SPECIAL_REG_EPC7:
		return "EPC7";
	case XTENSA_SPECIAL_REG_DEPC:
		return "DEPC";
	case XTENSA_SPECIAL_REG_EPS2:
		return "EPS2";
	case XTENSA_SPECIAL_REG_EPS3:
		return "EPS3";
	case XTENSA_SPECIAL_REG_EPS4:
		return "EPS4";
	case XTENSA_SPECIAL_REG_EPS5:
		return "EPS5";
	case XTENSA_SPECIAL_REG_EPS6:
		return "EPS6";
	case XTENSA_SPECIAL_REG_EPS7:
		return "EPS7";
	// TODO :shrug: why is EXCSAVE1 == DEPC ??
	// case XTENSA_SPECIAL_REG_EXCSAVE1: return "EXCSAVE1";
	case XTENSA_SPECIAL_REG_EXCSAVE2:
		return "EXCSAVE2";
	case XTENSA_SPECIAL_REG_EXCSAVE3:
		return "EXCSAVE3";
	case XTENSA_SPECIAL_REG_EXCSAVE4:
		return "EXCSAVE4";
	case XTENSA_SPECIAL_REG_EXCSAVE5:
		return "EXCSAVE5";
	case XTENSA_SPECIAL_REG_EXCSAVE6:
		return "EXCSAVE6";
	case XTENSA_SPECIAL_REG_EXCSAVE7:
		return "EXCSAVE7";
	case XTENSA_SPECIAL_REG_CPENABLE:
		return "CPENABLE";
	case XTENSA_SPECIAL_REG_INTERRUPT:
		return "INTERRUPT";
	case XTENSA_SPECIAL_REG_INTCLEAR:
		return "INTCLEAR";
	case XTENSA_SPECIAL_REG_INTENABLE:
		return "INTENABLE";
	case XTENSA_SPECIAL_REG_PS:
		return "PS";
	case XTENSA_SPECIAL_REG_VECBASE:
		return "VECBASE";
	case XTENSA_SPECIAL_REG_EXCCAUSE:
		return "EXCCAUSE";
	case XTENSA_SPECIAL_REG_CCOUNT:
		return "CCOUNT";
	case XTENSA_SPECIAL_REG_PRID:
		return "PRID";
	case XTENSA_SPECIAL_REG_ICOUNT:
		return "ICOUNT";
	case XTENSA_SPECIAL_REG_ICOUNTLEVEL:
		return "ICOUNTLEVEL";
	case XTENSA_SPECIAL_REG_EXCVADDR:
		return "EXCVADDR";
	case XTENSA_SPECIAL_REG_CCOMPARE0:
		return "CCOMPARE0";
	case XTENSA_SPECIAL_REG_CCOMPARE1:
		return "CCOMPARE1";
	case XTENSA_SPECIAL_REG_CCOMPARE2:
		return "CCOMPARE2";
	case XTENSA_SPECIAL_REG_MISC0:
		return "MISC0";
	case XTENSA_SPECIAL_REG_MISC1:
		return "MISC1";
	case XTENSA_SPECIAL_REG_MISC2:
		return "MISC2";
	case XTENSA_SPECIAL_REG_MISC3:
		return "MISC3";
	default:
		return NULL;
	}
	return NULL;
}

const char *Xtensa_userreg_name(csh handle, unsigned int id)
{
	switch (id)
	{
	case XTENSA_USER_REG_THREADPTR:
		return "THREADPTR";
	case XTENSA_USER_REG_FCR:
		return "FCR";
	case XTENSA_USER_REG_FSR:
		return "FSR";
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
	case XTENSA_OP_REG:
		return "Register";
	case XTENSA_OP_IMM:
		return "Immediate";
	case XTENSA_OP_FP:
		return "Floating-point Register";
	case XTENSA_OP_SYSREG:
		return "Special Register";
	case XTENSA_OP_USERREG:
		return "User Register";
	case XTENSA_OP_INVALID:
	case XTENSA_OP_MEM:
	default:
		return NULL;
	}
}
