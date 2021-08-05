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

int disassemble_internal(csh ud, const uint8_t *code, size_t code_len, xtensa_insn *pinsn, cs_xtensa *csn)
{
#define REG(value, mode)                                       \
	csn->operands[csn->op_count++] = (cs_xtensa_op)            \
	{                                                          \
		XTENSA_OP_REG, {.reg = XTENSA_REG_A0 + value}, mode, 4 \
	}
#define IMM(size, value, mode)                          \
	csn->operands[csn->op_count++] = (cs_xtensa_op)     \
	{                                                   \
		XTENSA_OP_IMM, {.imm = value}, CS_AC_READ, size \
	}
#define REGR(value) REG(value, CS_AC_READ)
#define REGW(value) REG(value, CS_AC_WRITE)
#define IMMR(size, value) IMM(value, size, CS_AC_READ)
#define IMMW(size, value) IMM(value, size, CS_AC_WRITE)

	xtensa_insn insn = XTENSA_INSN_INVALID;
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
				break;
			case 0b1011: // ADDI.N
				break;
			case 0b1100: // ST2.N
				if (in16.ri7.i == 0)
				{
					insn = XTENSA_INSN_MOVI;
					REGW(in16.ri6.s);
					IMMR(1, (int8_t)(in16.ri6.imm754 << 5 | in16.ri6.imm730 << 1) >> 1);
				}
				break;
			case 0b1101: // ST3.N
				break;
			}
			return insn ? 2 : 0;
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
							REGW(in24.rrr.r);
							REGR(in24.rrr.t);
							break;
						case 0b0001: // ABS
							insn = XTENSA_INSN_ABS;
							REGW(in24.rrr.r);
							REGR(in24.rrr.t);
							break;
						}
					case 0b1000: // ADD
					case 0b1001: // ADDX2
					case 0b1010: // ADDX4
					case 0b1011: // ADDx8
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
			return insn ? 3 : 0;
		}
	}

	return false;
}

bool Xtensa_getInstruction(csh ud, const uint8_t *code, size_t code_len, MCInst *mi, uint16_t *size, uint64_t address,
						   void *info)
{
	xtensa_insn instruction;
	cs_xtensa *cs = &mi->flat_insn->detail->xtensa;
	memset(mi->flat_insn->detail, 0, offsetof(cs_detail, xtensa) + sizeof(cs_xtensa));

	int insnbytes = disassemble_internal(ud, code, code_len, &instruction, cs);

	if (insnbytes > 0)
	{
		mi->address = address;
		*size = insnbytes;

		if (mi->flat_insn->detail)
		{
			mi->flat_insn->id = (unsigned int)instruction;
		}

		return true;
	}
	else
	{
		return false;
	}
}
