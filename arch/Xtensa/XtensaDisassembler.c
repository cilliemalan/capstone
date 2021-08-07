#include "XtensaDisassembler.h"
#include "capstone/capstone.h"
#include <memory.h>
#include <stddef.h>

#define ARRAYSIZE(x) sizeof(x) / sizeof(x[0])

typedef union xinsn24
{
	struct rrr
	{
		uint8_t op0 : 4;
		uint8_t t : 4;
		uint8_t s : 4;
		uint8_t r : 4;
		uint8_t op1 : 4;
		uint8_t op2 : 4;
	} rrr;
	struct rri4
	{
		uint8_t op0 : 4;
		uint8_t t : 4;
		uint8_t s : 4;
		uint8_t r : 4;
		uint8_t op1 : 4;
		uint8_t imm4 : 4;
	} rri4;
	struct rri8
	{
		uint8_t op0 : 4;
		uint8_t t : 4;
		uint8_t s : 4;
		uint8_t r : 4;
		uint8_t imm8 : 8;
	} rri8;
	struct rri16
	{
		uint8_t op0 : 4;
		uint8_t t : 4;
		uint8_t s : 4;
		uint8_t imm16 : 8;
	} rri16;
	struct rsr
	{
		uint8_t op0 : 4;
		uint8_t t : 4;
		uint8_t rs : 8;
		uint8_t op1 : 4;
		uint8_t op2 : 4;
	} rsr;
	struct call
	{
		uint8_t op0 : 4;
		uint8_t n : 2;
		uint32_t offset : 18;
	} call;
	struct callx
	{
		uint8_t op0 : 4;
		uint8_t n : 2;
		uint8_t m : 2;
		uint8_t s : 4;
		uint8_t r : 4;
		uint8_t op1 : 4;
		uint8_t op2 : 4;
	} callx;
	struct bri8
	{
		uint8_t op0 : 4;
		uint8_t n : 2;
		uint8_t m : 2;
		uint8_t s : 4;
		uint8_t r : 4;
		uint8_t imm8 : 8;
	} bri8;
	struct bri12
	{
		uint8_t op0 : 4;
		uint8_t n : 2;
		uint8_t m : 2;
		uint8_t s : 4;
		uint16_t imm12 : 12;
	} bri12;
} xinsn24;

typedef union xinsn16
{
	struct rrrn
	{
		uint8_t op0 : 4;
		uint8_t t : 4;
		uint8_t s : 4;
		uint8_t r : 4;
	} rrrn;
	struct ri7
	{
		uint8_t op0 : 4;
		uint8_t imm764 : 3;
		uint8_t i : 1;
		uint8_t s : 4;
		uint8_t imm730 : 4;
	} ri7;
	struct ri6
	{
		uint8_t op0 : 4;
		uint8_t imm754 : 3;
		uint8_t i : 2;
		uint8_t s : 4;
		uint8_t imm730 : 4;
	} ri6;
} xinsn16;

void Xtensa_init(MCRegisterInfo *MRI)
{
	//
}

static void add_register(cs_insn *csn, unsigned int regnr, uint8_t access)
{
	if (csn->detail)
	{
		int c = csn->detail->xtensa.op_count++;
		csn->detail->xtensa.operands[c].type = XTENSA_OP_REG;
		csn->detail->xtensa.operands[c].reg = XTENSA_REG_A0 + regnr;
		csn->detail->xtensa.operands[c].access = access;
		csn->detail->xtensa.operands[c].size = 4;

		if (access & CS_AC_READ)
		{
			csn->detail->regs_read[csn->detail->regs_read_count++] = XTENSA_REG_A0 + regnr;
		}
		if (access & CS_AC_WRITE)
		{
			csn->detail->regs_write[csn->detail->regs_write_count++] = XTENSA_REG_A0 + regnr;
		}
	}
}

static void add_immediate(cs_insn *csn, int immediate, int size, uint8_t access)
{
	if (csn->detail)
	{
		int c = csn->detail->xtensa.op_count++;
		csn->detail->xtensa.operands[c].type = XTENSA_OP_IMM;
		csn->detail->xtensa.operands[c].imm = immediate;
		csn->detail->xtensa.operands[c].access = access;
		csn->detail->xtensa.operands[c].size = size;
	}
}

static inline int32_t compliment(uint32_t bits, uint32_t max, uint32_t immediate)
{
	if (immediate > max)
		return immediate - (1 << bits);
	else
		return immediate;
}

int disassemble_internal(csh ud, const uint8_t *code, size_t code_len,
						 xtensa_insn *pinsn, cs_insn *csn)
{
#define REGR(value) add_register(csn, value, CS_AC_READ)
#define REGW(value) add_register(csn, value, CS_AC_WRITE)
#define IMMR(size, value) add_immediate(csn, value, size, CS_AC_READ)
#define IMMW(size, value) add_immediate(csn, value, size, CS_AC_WRITE)

	xtensa_insn_group group = XTENSA_GRP_INVALID;
	xtensa_insn insn = XTENSA_INSN_INVALID;
	int size;
	if (code_len >= 2)
	{
		if (code[0] & 0b1000)
		{
			// 16 bit instruction
			xinsn16 in16 = *(const xinsn16 *)(code);

			switch (in16.rrrn.op0)
			{
			case 0b1000: // L32I.N
				break;
			case 0b1001: // S32I.N
				break;
			case 0b1010: // ADD.N
				insn = XTENSA_INSN_ADD_N;
				group = XTENSA_GRP_MEMORY_ARITHMETIC;
				REGW(in16.rrrn.r);
				REGR(in16.rrrn.s);
				REGR(in16.rrrn.t);
				break;
			case 0b1011: // ADDI.N
				insn = XTENSA_INSN_ADDI_N;
				group = XTENSA_GRP_MEMORY_ARITHMETIC;
				REGW(in16.rrrn.r);
				REGR(in16.rrrn.s);
				IMMR(1, in16.rrrn.t == 0 ? 0xffffffff : in16.rrrn.t);
				break;
			case 0b1100: // ST2.N
				if (in16.ri7.i == 0) // MOVI.N
				{
					insn = XTENSA_INSN_MOVI_N;
					group = XTENSA_GRP_MEMORY_MOVE;
					REGW(in16.ri7.s);
					IMMR(1, compliment(7, 95, in16.ri7.imm764 << 4 | in16.ri7.imm730));
				}
				break;
			case 0b1101: // ST3.N
				break;
			}
			size = insn ? 2 : 0;
		}
		else if (code_len >= 3)
		{
			// 24 bit instruction
			xinsn24 in24 = *(const xinsn24 *)(code);

			switch (in24.rrr.op0)
			{
			case 0b0000: // QRST
				switch (in24.rrr.op1)
				{
				case 0b0000: // RST0
					switch (in24.rrr.op2)
					{
					case 0b0000: // ST0
					case 0b0001: // AND
					case 0b0010: // OR
					case 0b0011: // XOR
					case 0b0100: // ST1
					case 0b0101: // TLB
					case 0b0110: // RT0
						switch (in24.rrr.s)
						{
						case 0b0000: // NEG
							insn = XTENSA_INSN_NEG;
							group = XTENSA_GRP_MEMORY_ARITHMETIC;
							REGW(in24.rrr.r);
							REGR(in24.rrr.t);
							break;
						case 0b0001: // ABS
							insn = XTENSA_INSN_ABS;
							group = XTENSA_GRP_MEMORY_ARITHMETIC;
							REGW(in24.rrr.r);
							REGR(in24.rrr.t);
							break;
						}
						break;
					case 0b1000: // ADD
							insn = XTENSA_INSN_ADD;
							group = XTENSA_GRP_MEMORY_ARITHMETIC;
							REGW(in24.rrr.r);
							REGR(in24.rrr.s);
							REGR(in24.rrr.t);
							break;
					case 0b1001: // ADDX2
					case 0b1010: // ADDX4
					case 0b1011: // ADDx8
							insn = XTENSA_INSN_ADDX2 + (in24.rrr.op2 & 0b11) - 1;
							group = XTENSA_GRP_MEMORY_ARITHMETIC;
							REGW(in24.rrr.r);
							REGR(in24.rrr.s);
							REGR(in24.rrr.t);
							break;
					case 0b1100: // SUB
					case 0b1101: // SUBX2
					case 0b1110: // SUBX4
					case 0b1111: // SUBX8
						break;
					}
					break;
				}
				break;
			case 0b0001: // L32R
				break;
			case 0b0010: // LSAI
				break;
			case 0b0011: // LSCI
				break;
			case 0b0100: // MAC16
				break;
			case 0b0101: // CALLN
				break;
			case 0b0110: // SI
				break;
			case 0b0111: // B
				break;
			}
			size = insn ? 3 : 0;
		}
	}

	if (csn->detail && group)
	{
		csn->detail->groups[csn->detail->groups_count++] = group;
	}

	*pinsn = insn;
	return size;
}

bool Xtensa_getInstruction(csh ud, const uint8_t *code, size_t code_len, MCInst *mi, uint16_t *size, uint64_t address,
						   void *info)
{
	xtensa_insn instruction;
	if (mi->flat_insn->detail)
	{
		memset(mi->flat_insn->detail, 0, offsetof(cs_detail, xtensa) + sizeof(cs_xtensa));
	}

	int insnbytes = disassemble_internal(ud, code, code_len, &instruction, mi->flat_insn);

	if (insnbytes > 0)
	{
		mi->address = address;
		*size = insnbytes;
		mi->flat_insn->id = instruction;
		mi->OpcodePub = instruction;
		mi->Opcode = instruction;

		return true;
	}
	else
	{
		return false;
	}
}
