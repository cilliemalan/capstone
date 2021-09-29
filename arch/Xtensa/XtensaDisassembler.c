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
	struct ri16
	{
		uint8_t op0 : 4;
		uint8_t t : 4;
		uint8_t imm08 : 8;
		uint8_t imm816 : 8;
	} ri16;
	struct rsr
	{
		uint8_t op0 : 4;
		uint8_t t : 4;
		uint8_t s : 4;
		uint8_t r : 4;
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
		uint8_t imm654 : 2;
		uint8_t i : 2;
		uint8_t s : 4;
		uint8_t imm630 : 4;
	} ri6;
} xinsn16;

void Xtensa_init(MCRegisterInfo *MRI)
{
	//
}

static void add_register_operand(cs_insn *csn, xtensa_op_type type, unsigned int regnr, uint8_t access, uint32_t size)
{
	if (csn->detail)
	{
		int c = csn->detail->xtensa.op_count++;
		csn->detail->xtensa.operands[c].type = type;
		csn->detail->xtensa.operands[c].reg = regnr;
		csn->detail->xtensa.operands[c].access = access;
		csn->detail->xtensa.operands[c].size = size;

		if (access & CS_AC_READ)
		{
			csn->detail->regs_read[csn->detail->regs_read_count++] = regnr;
		}
		if (access & CS_AC_WRITE)
		{
			csn->detail->regs_write[csn->detail->regs_write_count++] = regnr;
		}
	}
}

static void add_immediate_operand(cs_insn *csn, int immediate, int size, uint8_t access)
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

static int32_t b4const(uint8_t x)
{
	return x == 0 ? -1 : x < 9			   ? x
					 : x == 9			   ? 10
					 : x == 10			   ? 12
					 : x >= 11 && (x) < 16 ? (1 << (x - 7))
										   : 0;
}

static uint32_t b4constu(uint8_t x)
{
	return x == 0 ? 32768 : x == 1			  ? 65536
						: x < 9				  ? x
						: x == 9			  ? 10
						: x == 10			  ? 12
						: x >= 11 && (x) < 16 ? (1 << (x - 7))
											  : 0;
}

static int disassemble_internal(csh ud, const uint8_t *code, size_t code_len, xtensa_insn *pinsn, cs_insn *csn)
{
#define RGR(value) add_register_operand(csn, XTENSA_OP_REG, XTENSA_REG_A0 + (value), CS_AC_READ, 32)
#define RGW(value) add_register_operand(csn, XTENSA_OP_REG, XTENSA_REG_A0 + (value), CS_AC_WRITE, 32)
#define RGRW(value) add_register_operand(csn, XTENSA_OP_REG, XTENSA_REG_A0 + (value), CS_AC_READ | CS_AC_WRITE, 32)
#define RFR(value) add_register_operand(csn, XTENSA_OP_FP, XTENSA_FP_REG_FR0 + (value), CS_AC_READ, 32)
#define RFW(value) add_register_operand(csn, XTENSA_OP_FP, XTENSA_FP_REG_FR0 + (value), CS_AC_WRITE, 32)
#define RBR(value) add_register_operand(csn, XTENSA_OP_BOOLREG, XTENSA_BR_REG_B0 + (value), CS_AC_READ, 32)
#define RBW(value) add_register_operand(csn, XTENSA_OP_BOOLREG, XTENSA_BR_REG_B0 + (value), CS_AC_WRITE, 32)
#define RMR(value) add_register_operand(csn, XTENSA_OP_MACREG, XTENSA_MR_REG_M0 + (value), CS_AC_READ, 32)
#define RMW(value) add_register_operand(csn, XTENSA_OP_MACREG, XTENSA_MR_REG_M0 + (value), CS_AC_WRITE, 32)
#define RSR(value) add_register_operand(csn, XTENSA_OP_SYSREG, XTENSA_SPECIAL_REG_LBEG + (value), CS_AC_READ, 32)
#define RSW(value) add_register_operand(csn, XTENSA_OP_SYSREG, XTENSA_SPECIAL_REG_LBEG + (value), CS_AC_WRITE, 32)
#define RSRW(value) add_register_operand(csn, XTENSA_OP_SYSREG, XTENSA_SPECIAL_REG_LBEG + (value), CS_AC_READ | CS_AC_WRITE, 32)
#define RUR(value) add_register_operand(csn, XTENSA_OP_USERREG, XTENSA_USER_REG_INVALID + 1 + (value), CS_AC_READ, 32)
#define RUW(value) add_register_operand(csn, XTENSA_OP_USERREG, XTENSA_USER_REG_INVALID + 1 + (value), CS_AC_WRITE, 32)
#define IMMR(size, value) add_immediate_operand(csn, (value), size, CS_AC_READ)
#define INSN(i, a) \
	insn = i;      \
	group1 = a;

	xtensa_insn_group group1 = XTENSA_GRP_INVALID;
	xtensa_insn_group group2 = XTENSA_GRP_INVALID;
	xtensa_insn_group group3 = XTENSA_GRP_INVALID;
	xtensa_insn insn = XTENSA_INSN_INVALID;
	int size = 0;
	if (code_len >= 2)
	{
		if (code[0] & 0b1000)
		{
			// 16 bit instruction
			xinsn16 in16 = *(const xinsn16 *)(code);

			switch (in16.rrrn.op0)
			{
			case 0b1000: // L32I.N
				INSN(XTENSA_INSN_L32I_N, XTENSA_GRP_LOAD);
				RGW(in16.rrrn.t);
				RGR(in16.rrrn.s);
				IMMR(4, in16.rrrn.r * 4);
				break;
			case 0b1001: // S32I.N
				INSN(XTENSA_INSN_S32I_N, XTENSA_GRP_STORE);
				RGR(in16.rrrn.t);
				RGR(in16.rrrn.s);
				IMMR(4, in16.rrrn.r * 4);
				break;
			case 0b1010: // ADD.N
				INSN(XTENSA_INSN_ADD_N, XTENSA_GRP_ARITHMETIC);
				RGW(in16.rrrn.r);
				RGR(in16.rrrn.s);
				RGR(in16.rrrn.t);
				break;
			case 0b1011: // ADDI.N
				INSN(XTENSA_INSN_ADDI_N, XTENSA_GRP_ARITHMETIC);
				RGW(in16.rrrn.r);
				RGR(in16.rrrn.s);
				IMMR(4, in16.rrrn.t == 0 ? 0xffffffff : in16.rrrn.t);
				break;
			case 0b1100:			 // ST2.N
				if (in16.ri7.i == 0) // MOVI.N
				{
					INSN(XTENSA_INSN_MOVI_N, XTENSA_GRP_MOVE);
					RGW(in16.ri7.s);
					IMMR(7, compliment(7, 95, in16.ri7.imm764 << 4 | in16.ri7.imm730));
				}
				else if (in16.ri6.i == 0b10) // BEQZ.N
				{
					INSN(XTENSA_INSN_BEQZ_N, XTENSA_GRP_BRANCH_RELATIVE);
					RGR(in16.ri6.s);
					IMMR(6, in16.ri6.imm654 << 4 | in16.ri6.imm630);
				}
				else // BNEZ.N
				{
					INSN(XTENSA_INSN_BNEZ_N, XTENSA_GRP_BRANCH_RELATIVE);
					RGR(in16.ri6.s);
					IMMR(6, in16.ri6.imm654 << 4 | in16.ri6.imm630);
				}
				break;
			case 0b1101: // ST3.N
				switch (in16.rrrn.r)
				{
				case 0b0000: // MOV.N
					INSN(XTENSA_INSN_MOV_N, XTENSA_GRP_MOVE);
					RGW(in16.rrrn.t);
					RGR(in16.rrrn.s);
					break;
				case 0b1111: // S3
					switch (in16.rrrn.t)
					{
					case 0b0000: // RET.N
						if (in16.rrrn.s == 0)
						{
							INSN(XTENSA_INSN_RET_N, XTENSA_GRP_MISC);
						}
						break;
					case 0b0001: // RETW.N
						if (in16.rrrn.s == 0)
						{
							INSN(XTENSA_INSN_RETW_N, XTENSA_GRP_MISC);
						}
						break;
					case 0b0010: // BREAK.N
						INSN(XTENSA_INSN_BREAK_N, XTENSA_GRP_MISC);
						IMMR(4, in16.rrrn.s);
						break;
					case 0b0011: // NOP.N
						if (in16.rrrn.s == 0)
						{
							INSN(XTENSA_INSN_NOP_N, XTENSA_GRP_EXCEPTION);
						}
						break;
					case 0b0110: // ILL.N
						if (in16.rrrn.s == 0)
						{
							INSN(XTENSA_INSN_ILL_N, XTENSA_GRP_EXCEPTION);
						}
						break;
					}
					break;
				}
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
						switch (in24.rrr.r)
						{
						case 0b0000: // SNM0
							switch (in24.callx.m)
							{
							case 0b00: // ILL
								INSN(XTENSA_INSN_ILL, XTENSA_GRP_EXCEPTION);
								break;
							case 0b10: // JR
								switch (in24.callx.n)
								{
								case 0b00: // RET
									if (in24.callx.s == 0)
									{
										INSN(XTENSA_INSN_RET, XTENSA_GRP_CALL);
									}
									break;
								case 0b01: // RETW
									if (in24.callx.s == 0)
									{
										INSN(XTENSA_INSN_RETW, XTENSA_GRP_CALL);
									}
									break;
								case 0b10: // JX
									INSN(XTENSA_INSN_JX, XTENSA_GRP_CALL);
									RGR(in24.callx.s);
									break;
								}
								break;
							case 0b11: // CALLX
								switch (in24.callx.n)
								{
								case 0b00: // CALLX0
									INSN(XTENSA_INSN_CALLX0, XTENSA_GRP_CALL);
									break;
								case 0b01: // CALLX4
									INSN(XTENSA_INSN_CALLX4, XTENSA_GRP_CALL);
									break;
								case 0b10: // CALLX08
									INSN(XTENSA_INSN_CALLX8, XTENSA_GRP_CALL);
									break;
								case 0b11: // CALLX12
									INSN(XTENSA_INSN_CALLX12, XTENSA_GRP_CALL);
									break;
								}
								RGR(in24.callx.s);
								break;
							}
							break;
						case 0b0001: // MOVSP
							INSN(XTENSA_INSN_MOVSP, XTENSA_GRP_MOVE);
							RGW(in24.rrr.t);
							RGR(in24.rrr.s);
							break;
						case 0b0010: // SYNC
							switch (in24.rrr.t)
							{
							case 0b0000: // ISYNC
								INSN(XTENSA_INSN_ISYNC, XTENSA_GRP_PROCESSOR_CONTROL);
								break;
							case 0b0001: // RSYNC
								INSN(XTENSA_INSN_RSYNC, XTENSA_GRP_PROCESSOR_CONTROL);
								break;
							case 0b0010: // ESYNC
								INSN(XTENSA_INSN_ESYNC, XTENSA_GRP_PROCESSOR_CONTROL);
								break;
							case 0b0011: // DSYNC
								INSN(XTENSA_INSN_DSYNC, XTENSA_GRP_PROCESSOR_CONTROL);
								break;
							case 0b1000: // EXCW
								INSN(XTENSA_INSN_EXCW, XTENSA_GRP_PROCESSOR_CONTROL);
								break;
							case 0b1100: // MEMW
								INSN(XTENSA_INSN_MEMW, XTENSA_GRP_PROCESSOR_CONTROL);
								break;
							case 0b1101: // EXTW
								INSN(XTENSA_INSN_EXTW, XTENSA_GRP_PROCESSOR_CONTROL);
								break;
							case 0b1111: // NOP
								INSN(XTENSA_INSN_NOP, XTENSA_GRP_ARITHMETIC);
								break;
							}
							break;
						case 0b0011: // RFEI
							switch (in24.rrr.t)
							{
							case 0b0000: // RFET
								switch (in24.rrr.s)
								{
								case 0b0000: // RFE
									INSN(XTENSA_INSN_RFE, XTENSA_GRP_RET);
									break;
								case 0b0001: // RFUE
									INSN(XTENSA_INSN_RFUE, XTENSA_GRP_RET);
									break;
								case 0b0010: // RFDE
									INSN(XTENSA_INSN_RFDE, XTENSA_GRP_RET);
									break;
								case 0b0100: // RFWO
									INSN(XTENSA_INSN_RFWO, XTENSA_GRP_RET);
									break;
								case 0b0101: // RFWU
									INSN(XTENSA_INSN_RFWU, XTENSA_GRP_RET);
									break;
								}
								break;
							case 0b0001: // RFI
								INSN(XTENSA_INSN_RFI, XTENSA_GRP_RET);
								IMMR(4, in24.rrr.s);
								break;
							case 0b0010: // RFME
								if (in24.rrr.s == 0)
								{
									INSN(XTENSA_INSN_RFME, XTENSA_GRP_RET);
								}
								break;
							}
							break;
						case 0b0100: // BREAK
							INSN(XTENSA_INSN_BREAK, XTENSA_GRP_MISC);
							IMMR(4, in24.rrr.s);
							IMMR(4, in24.rrr.t);
							break;
						case 0b0101: // SYSCALL
							if (in24.rrr.s == 0)
							{
								INSN(XTENSA_INSN_SYSCALL, XTENSA_GRP_EXCEPTION);
							}
							else if (in24.rrr.s == 1)
							{
								INSN(XTENSA_INSN_SIMCALL, XTENSA_GRP_EXCEPTION);
							}
							break;
						case 0b0110: // RSIL
							INSN(XTENSA_INSN_RSIL, XTENSA_GRP_INT);
							RGW(in24.rrr.t);
							IMMR(4, in24.rrr.s);
							break;
						case 0b0111: // WAITI
							INSN(XTENSA_INSN_WAITI, XTENSA_GRP_INT);
							IMMR(4, in24.rrr.s);
							break;
						case 0b1000: // ANY4
							INSN(XTENSA_INSN_ANY4, XTENSA_GRP_BOOLEAN);
							RBW(in24.rrr.t);
							RBR(in24.rrr.s);
							break;
						case 0b1001: // ALL4
							INSN(XTENSA_INSN_ALL4, XTENSA_GRP_BOOLEAN);
							RBW(in24.rrr.t);
							RBR(in24.rrr.s);
							break;
						case 0b1010: // ANY8
							INSN(XTENSA_INSN_ANY8, XTENSA_GRP_BOOLEAN);
							RBW(in24.rrr.t);
							RBR(in24.rrr.s);
							break;
						case 0b1011: // ALL8
							INSN(XTENSA_INSN_ALL8, XTENSA_GRP_BOOLEAN);
							RBW(in24.rrr.t);
							RBR(in24.rrr.s);
							break;
						}
						break;
					case 0b0001: // AND
						INSN(XTENSA_INSN_AND, XTENSA_GRP_BITWISE);
						RGW(in24.rrr.r);
						RGR(in24.rrr.s);
						RGR(in24.rrr.t);
						break;
					case 0b0010: // OR
						INSN(XTENSA_INSN_OR, XTENSA_GRP_BITWISE);
						RGW(in24.rrr.r);
						RGR(in24.rrr.s);
						RGR(in24.rrr.t);
						break;
					case 0b0011: // XOR
						INSN(XTENSA_INSN_XOR, XTENSA_GRP_BITWISE);
						RGW(in24.rrr.r);
						RGR(in24.rrr.s);
						RGR(in24.rrr.t);
						break;
					case 0b0100: // ST1
						switch (in24.rrr.r)
						{
						case 0b0000: // SSR
							INSN(XTENSA_INSN_SSR, XTENSA_GRP_BITWISE);
							RGR(in24.rrr.s);
							break;
						case 0b0001: // SSL
							INSN(XTENSA_INSN_SSL, XTENSA_GRP_BITWISE);
							RGR(in24.rrr.s);
							break;
						case 0b0010: // SSA8L
							INSN(XTENSA_INSN_SSA8L, XTENSA_GRP_BITWISE);
							RGR(in24.rrr.s);
							break;
						case 0b0011: // SSA8B
							INSN(XTENSA_INSN_SSA8B, XTENSA_GRP_BITWISE);
							RGR(in24.rrr.s);
							break;
						case 0b0100: // SSAI
							INSN(XTENSA_INSN_SSAI, XTENSA_GRP_BITWISE);
							IMMR(5, in24.rrr.s | (in24.rrr.t << 4));
							break;
						case 0b0110: // RER
							INSN(XTENSA_INSN_RER, XTENSA_GRP_BITWISE);
							RGW(in24.rrr.t);
							RGR(in24.rrr.s);
							break;
						case 0b0111: // WER
							INSN(XTENSA_INSN_WER, XTENSA_GRP_BITWISE);
							RGW(in24.rrr.t);
							RGR(in24.rrr.s);
							break;
						case 0b1000: // ROTW
							INSN(XTENSA_INSN_ROTW, XTENSA_GRP_BITWISE);
							IMMR(4, compliment(4, 7, in24.rrr.t));
							break;
						case 0b1110: // NSA
							INSN(XTENSA_INSN_NSA, XTENSA_GRP_BITWISE);
							RGW(in24.rrr.t);
							RGR(in24.rrr.s);
							break;
						case 0b1111: // NSAU
							INSN(XTENSA_INSN_NSAU, XTENSA_GRP_BITWISE);
							RGW(in24.rrr.t);
							RGR(in24.rrr.s);
							break;
						}
						break;
					case 0b0101: // TLB
						switch (in24.rrr.r)
						{
						case 0b0011: // RITLB0
							INSN(XTENSA_INSN_RITLB0, XTENSA_GRP_MMU);
							RGW(in24.rrr.t);
							RGR(in24.rrr.s);
							break;
						case 0b0100: // IITLB
							if (in24.rrr.t == 0)
							{
								INSN(XTENSA_INSN_IITLB, XTENSA_GRP_MMU);
								RGR(in24.rrr.s);
							}
							break;
						case 0b0101: // PITLB
							INSN(XTENSA_INSN_PITLB, XTENSA_GRP_MMU);
							RGW(in24.rrr.t);
							RGR(in24.rrr.s);
							break;
						case 0b0110: // WITLB
							INSN(XTENSA_INSN_WITLB, XTENSA_GRP_MMU);
							RGR(in24.rrr.t);
							RGR(in24.rrr.s);
							break;
						case 0b0111: // RITLB1
							INSN(XTENSA_INSN_RITLB1, XTENSA_GRP_MMU);
							RGW(in24.rrr.t);
							RGR(in24.rrr.s);
							break;
						case 0b1011: // RDTLB0
							INSN(XTENSA_INSN_RDTLB0, XTENSA_GRP_MMU);
							RGW(in24.rrr.t);
							RGR(in24.rrr.s);
							break;
						case 0b1100: // IDTLB
							if (in24.rrr.t == 0)
							{
								INSN(XTENSA_INSN_IDTLB, XTENSA_GRP_MMU);
								RGR(in24.rrr.s);
							}
							break;
						case 0b1101: // PDTLB
							INSN(XTENSA_INSN_PDTLB, XTENSA_GRP_MMU);
							RGW(in24.rrr.t);
							RGR(in24.rrr.s);
							break;
						case 0b1110: // WDTLB
							INSN(XTENSA_INSN_WDTLB, XTENSA_GRP_MMU);
							RGR(in24.rrr.t);
							RGR(in24.rrr.s);
							break;
						case 0b1111: // RDTLB1
							INSN(XTENSA_INSN_RDTLB1, XTENSA_GRP_MMU);
							RGW(in24.rrr.t);
							RGR(in24.rrr.s);
							break;
						}
						break;
					case 0b0110: // RT0
						switch (in24.rrr.s)
						{
						case 0b0000: // NEG
							INSN(XTENSA_INSN_NEG, XTENSA_GRP_ARITHMETIC);
							RGW(in24.rrr.r);
							RGR(in24.rrr.t);
							break;
						case 0b0001: // ABS
							INSN(XTENSA_INSN_ABS, XTENSA_GRP_ARITHMETIC);
							RGW(in24.rrr.r);
							RGR(in24.rrr.t);
							break;
						}
						break;
					case 0b1000: // ADD
						INSN(XTENSA_INSN_ADD, XTENSA_GRP_ARITHMETIC);
						RGW(in24.rrr.r);
						RGR(in24.rrr.s);
						RGR(in24.rrr.t);
						break;
					case 0b1001: // ADDX2
					case 0b1010: // ADDX4
					case 0b1011: // ADDx8
						insn = XTENSA_INSN_ADDX2 + (in24.rrr.op2 & 0b11) - 1;
						INSN(insn, XTENSA_GRP_ARITHMETIC);
						RGW(in24.rrr.r);
						RGR(in24.rrr.s);
						RGR(in24.rrr.t);
						break;
					case 0b1100: // SUB
						INSN(XTENSA_INSN_SUB, XTENSA_GRP_ARITHMETIC);
						RGW(in24.rrr.r);
						RGR(in24.rrr.s);
						RGR(in24.rrr.t);
						break;
					case 0b1101: // SUBX2
					case 0b1110: // SUBX4
					case 0b1111: // SUBX8
						insn = XTENSA_INSN_SUBX2 + (in24.rrr.op2 & 0b11) - 1;
						INSN(insn, XTENSA_GRP_ARITHMETIC);
						RGW(in24.rrr.r);
						RGR(in24.rrr.s);
						RGR(in24.rrr.t);
						break;
					}
					break;
				case 0b0001: // RST1
					switch (in24.rrr.op2)
					{
					case 0b0000:
					case 0b0001: // SLLI
						INSN(XTENSA_INSN_SLLI, XTENSA_GRP_ARITHMETIC);
						RGW(in24.rrr.r);
						RGR(in24.rrr.s);
						IMMR(5, 32 - (in24.rrr.t | ((in24.rrr.op2 & 0b1) << 4)));
						break;
					case 0b0010:
					case 0b0011: // SRAI
						INSN(XTENSA_INSN_SRAI, XTENSA_GRP_ARITHMETIC);
						RGW(in24.rrr.r);
						RGR(in24.rrr.t);
						IMMR(5, in24.rrr.s | ((in24.rrr.op2 & 0b1) << 4));
						break;
					case 0b0100: // SRLI
						INSN(XTENSA_INSN_SRLI, XTENSA_GRP_ARITHMETIC);
						RGW(in24.rrr.r);
						RGR(in24.rrr.t);
						IMMR(4, in24.rrr.s);
						break;
					case 0b0110: // XSR
						INSN(XTENSA_INSN_XSR, XTENSA_GRP_MOVE);
						RGRW(in24.rsr.t);
						RSRW((in24.rsr.r << 4) | in24.rsr.s);
						break;
					case 0b0111: // ACCER
						// what is this??
						switch (in24.rrr.op2)
						{
						case 0b0000: // RER
						case 0b1000: // WER
							break;
						}
						break;
					case 0b1000: // SRC
						INSN(XTENSA_INSN_SRC, XTENSA_GRP_ARITHMETIC);
						RGW(in24.rrr.r);
						RGR(in24.rrr.s);
						RGR(in24.rrr.t);
						break;
					case 0b1001: // SRL
						INSN(XTENSA_INSN_SRL, XTENSA_GRP_ARITHMETIC);
						RGW(in24.rrr.r);
						RGR(in24.rrr.t);
						break;
					case 0b1010: // SLL
						INSN(XTENSA_INSN_SLL, XTENSA_GRP_ARITHMETIC);
						RGW(in24.rrr.r);
						RGR(in24.rrr.s);
						break;
					case 0b1011: // SRA
						INSN(XTENSA_INSN_SRA, XTENSA_GRP_ARITHMETIC);
						RGW(in24.rrr.r);
						RGR(in24.rrr.t);
						break;
					case 0b1100: // MUL16U
						INSN(XTENSA_INSN_MUL16U, XTENSA_GRP_ARITHMETIC);
						RGW(in24.rrr.r);
						RGR(in24.rrr.s);
						RGR(in24.rrr.t);
						break;
					case 0b1101: // MUL16S
						INSN(XTENSA_INSN_MUL16S, XTENSA_GRP_ARITHMETIC);
						RGW(in24.rrr.r);
						RGR(in24.rrr.s);
						RGR(in24.rrr.t);
						break;
					case 0b1111: // IMP
						switch (in24.rrr.r)
						{
						case 0b0000: // LICT
							INSN(XTENSA_INSN_LICT, XTENSA_GRP_CACHE);
							RGW(in24.rrr.t);
							RGR(in24.rrr.s);
							break;
						case 0b0001: // SICT
							INSN(XTENSA_INSN_SICT, XTENSA_GRP_CACHE);
							RGR(in24.rrr.t);
							RGR(in24.rrr.s);
							break;
						case 0b0010: // LICW
							INSN(XTENSA_INSN_LICW, XTENSA_GRP_CACHE);
							RGW(in24.rrr.t);
							RGR(in24.rrr.s);
							break;
						case 0b0011: // SICW
							INSN(XTENSA_INSN_SICW, XTENSA_GRP_CACHE);
							RGR(in24.rrr.t);
							RGR(in24.rrr.s);
							break;
						case 0b1000: // LDCT
							INSN(XTENSA_INSN_LDCT, XTENSA_GRP_CACHE);
							RGW(in24.rrr.t);
							RGR(in24.rrr.s);
							break;
						case 0b1001: // SDCT
							INSN(XTENSA_INSN_LDCT, XTENSA_GRP_CACHE);
							RGR(in24.rrr.t);
							RGR(in24.rrr.s);
							break;
						case 0b1110: // RFDX
							switch (in24.rrr.t)
							{
							case 0b0000: // RFDO
								INSN(XTENSA_INSN_RFDO, XTENSA_GRP_DEBUG);
								IMMR(4, in24.rrr.s);
								break;
							case 0b0001: // RFDD
								INSN(XTENSA_INSN_RFDD, XTENSA_GRP_DEBUG);
								break;
							}
							break;
						}
						break;
					}
					break;
				case 0b0010: // RST2
					switch (in24.rrr.op2)
					{
					case 0b0000: // ANDB
						INSN(XTENSA_INSN_ANDB, XTENSA_GRP_BOOLEAN);
						RBW(in24.rrr.r);
						RBR(in24.rrr.s);
						RBR(in24.rrr.t);
						break;
					case 0b0001: // ANDBC
						INSN(XTENSA_INSN_ANDBC, XTENSA_GRP_BOOLEAN);
						RBW(in24.rrr.r);
						RBR(in24.rrr.s);
						RBR(in24.rrr.t);
						break;
					case 0b0010: // ORB
						INSN(XTENSA_INSN_ORB, XTENSA_GRP_BOOLEAN);
						RBW(in24.rrr.r);
						RBR(in24.rrr.s);
						RBR(in24.rrr.t);
						break;
					case 0b0011: // ORBC
						INSN(XTENSA_INSN_ORBC, XTENSA_GRP_BOOLEAN);
						RBW(in24.rrr.r);
						RBR(in24.rrr.s);
						RBR(in24.rrr.t);
						break;
					case 0b0100: // XORB
						INSN(XTENSA_INSN_XORB, XTENSA_GRP_BOOLEAN);
						RBW(in24.rrr.r);
						RBR(in24.rrr.s);
						RBR(in24.rrr.t);
						break;
					case 0b1000: // MULL
						INSN(XTENSA_INSN_MULL, XTENSA_GRP_BOOLEAN);
						RGW(in24.rrr.r);
						RGR(in24.rrr.s);
						RGR(in24.rrr.t);
						break;
					case 0b1010: // MULUH
						INSN(XTENSA_INSN_MULUH, XTENSA_GRP_BOOLEAN);
						RGW(in24.rrr.r);
						RGR(in24.rrr.s);
						RGR(in24.rrr.t);
						break;
					case 0b1011: // MULSH
						INSN(XTENSA_INSN_MULSH, XTENSA_GRP_BOOLEAN);
						RGW(in24.rrr.r);
						RGR(in24.rrr.s);
						RGR(in24.rrr.t);
						break;
					case 0b1100: // QUOU
						INSN(XTENSA_INSN_QUOU, XTENSA_GRP_BOOLEAN);
						RGW(in24.rrr.r);
						RGR(in24.rrr.s);
						RGR(in24.rrr.t);
						break;
					case 0b1101: // QUOS
						INSN(XTENSA_INSN_QUOS, XTENSA_GRP_BOOLEAN);
						RGW(in24.rrr.r);
						RGR(in24.rrr.s);
						RGR(in24.rrr.t);
						break;
					case 0b1110: // REMU
						INSN(XTENSA_INSN_REMU, XTENSA_GRP_BOOLEAN);
						RGW(in24.rrr.r);
						RGR(in24.rrr.s);
						RGR(in24.rrr.t);
						break;
					case 0b1111: // REMS
						INSN(XTENSA_INSN_REMS, XTENSA_GRP_BOOLEAN);
						RGW(in24.rrr.r);
						RGR(in24.rrr.s);
						RGR(in24.rrr.t);
						break;
					}
					break;
				case 0b0011: // RST3
					switch (in24.rrr.op2)
					{
					case 0b0000: // RSR
						INSN(XTENSA_INSN_RSR, XTENSA_GRP_MOVE);
						RGW(in24.rsr.t);
						RSR((in24.rsr.r << 4) | in24.rsr.s);
						break;
					case 0b0001: // WSR
						INSN(XTENSA_INSN_WSR, XTENSA_GRP_MOVE);
						RGR(in24.rsr.t);
						RSR((in24.rsr.r << 4) | in24.rsr.s);
						break;
					case 0b0010: // SEXT
						INSN(XTENSA_INSN_SEXT, XTENSA_GRP_MOVE);
						RGW(in24.rrr.r);
						RGR(in24.rrr.s);
						IMMR(4, in24.rrr.t + 7);
						break;
					case 0b0011: // CLAMPS
						INSN(XTENSA_INSN_CLAMPS, XTENSA_GRP_DEBUG);
						RGW(in24.rrr.r);
						RGR(in24.rrr.s);
						IMMR(4, in24.rrr.t + 7);
						break;
					case 0b0100: // MIN
						INSN(XTENSA_INSN_MIN, XTENSA_GRP_DEBUG);
						RGW(in24.rrr.r);
						RGR(in24.rrr.s);
						RGR(in24.rrr.t);
						break;
					case 0b0101: // MAX
						INSN(XTENSA_INSN_MAX, XTENSA_GRP_DEBUG);
						RGW(in24.rrr.r);
						RGR(in24.rrr.s);
						RGR(in24.rrr.t);
						break;
					case 0b0110: // MINU
						INSN(XTENSA_INSN_MINU, XTENSA_GRP_DEBUG);
						RGW(in24.rrr.r);
						RGR(in24.rrr.s);
						RGR(in24.rrr.t);
						break;
					case 0b0111: // MAXU
						INSN(XTENSA_INSN_MAXU, XTENSA_GRP_DEBUG);
						RGW(in24.rrr.r);
						RGR(in24.rrr.s);
						RGR(in24.rrr.t);
						break;
					case 0b1000: // MOVEQZ
						INSN(XTENSA_INSN_MOVEQZ, XTENSA_GRP_DEBUG);
						RGW(in24.rrr.r);
						RGR(in24.rrr.s);
						RGR(in24.rrr.t);
						break;
					case 0b1001: // MOVNEZ
						INSN(XTENSA_INSN_MOVNEZ, XTENSA_GRP_DEBUG);
						RGW(in24.rrr.r);
						RGR(in24.rrr.s);
						RGR(in24.rrr.t);
						break;
					case 0b1010: // MOVLTZ
						INSN(XTENSA_INSN_MOVLTZ, XTENSA_GRP_DEBUG);
						RGW(in24.rrr.r);
						RGR(in24.rrr.s);
						RGR(in24.rrr.t);
						break;
					case 0b1011: // MOVGEZ
						INSN(XTENSA_INSN_MOVGEZ, XTENSA_GRP_DEBUG);
						RGW(in24.rrr.r);
						RGR(in24.rrr.s);
						RGR(in24.rrr.t);
						break;
					case 0b1100: // MOVF
						INSN(XTENSA_INSN_MOVF, XTENSA_GRP_DEBUG);
						RGW(in24.rrr.r);
						RGR(in24.rrr.s);
						RBR(in24.rrr.t);
						break;
					case 0b1101: // MOVT
						INSN(XTENSA_INSN_MOVT, XTENSA_GRP_DEBUG);
						RGW(in24.rrr.r);
						RGR(in24.rrr.s);
						RBR(in24.rrr.t);
						break;
					case 0b1110: // RUR
						INSN(XTENSA_INSN_RUR, XTENSA_GRP_MOVE);
						RGW(in24.rrr.r);
						RUR((in24.rrr.s << 4) | in24.rrr.t);
						break;
					case 0b1111: // WUR
						INSN(XTENSA_INSN_WUR, XTENSA_GRP_MOVE);
						RGR(in24.rrr.t);
						RUW((in24.rrr.r << 4) | in24.rrr.s);
						break;
					}
					break;
				case 0b0100:
				case 0b0101: // EXTUI
					INSN(XTENSA_INSN_EXTUI, XTENSA_GRP_ARITHMETIC);
					RGW(in24.rrr.r);
					RGR(in24.rrr.t);
					IMMR(5, in24.rrr.s | ((in24.rrr.op1 & 1) << 4));
					IMMR(4, in24.rrr.op2 + 1);
					break;
				case 0b0110: // CUST0
					break;
				case 0b0111: // CUST1
					break;
				case 0b1000: // LSCX
					switch (in24.rrr.op2)
					{
					case 0b0000: // LSX
						INSN(XTENSA_INSN_LSX, XTENSA_GRP_FLOATING_POINT);
						RFW(in24.rrr.r);
						RGR(in24.rrr.s);
						RGR(in24.rrr.t);
						break;
					case 0b0001: // LSXU
						INSN(XTENSA_INSN_LSX, XTENSA_GRP_FLOATING_POINT);
						RFW(in24.rrr.r);
						RGRW(in24.rrr.s);
						RGR(in24.rrr.t);
						break;
					case 0b0100: // SSX
						INSN(XTENSA_INSN_SSX, XTENSA_GRP_FLOATING_POINT);
						RFR(in24.rrr.r);
						RGR(in24.rrr.s);
						RGR(in24.rrr.t);
						break;
					case 0b0101: // SSXU
						INSN(XTENSA_INSN_SSXU, XTENSA_GRP_FLOATING_POINT);
						RFR(in24.rrr.r);
						RGRW(in24.rrr.s);
						RGR(in24.rrr.t);
						break;
					}
					break;
				case 0b1001: // LSC4
					switch (in24.rrr.op2)
					{
					case 0b0000: // L32E
						INSN(XTENSA_INSN_L32E, XTENSA_GRP_FLOATING_POINT);
						RGW(in24.rri4.t);
						RGR(in24.rri4.s);
						IMMR(4, (in24.rri4.r * 4) - 64);
						break;
					case 0b0100: // S32E
						INSN(XTENSA_INSN_S32E, XTENSA_GRP_FLOATING_POINT);
						RGR(in24.rri4.t);
						RGR(in24.rri4.s);
						IMMR(4, (in24.rri4.r * 4) - 64);
						break;
					}
					break;
				case 0b1010: // FP0
					switch (in24.rrr.op2)
					{
					case 0b0000: // ADD.S
						INSN(XTENSA_INSN_ADD_S, XTENSA_GRP_FLOATING_POINT);
						RFW(in24.rrr.r);
						RFR(in24.rrr.s);
						RFR(in24.rrr.t);
						break;
					case 0b0001: // SUB.S
						INSN(XTENSA_INSN_SUB_S, XTENSA_GRP_FLOATING_POINT);
						RFW(in24.rrr.r);
						RFR(in24.rrr.s);
						RFR(in24.rrr.t);
						break;
					case 0b0010: // MUL.S
						INSN(XTENSA_INSN_MUL_S, XTENSA_GRP_FLOATING_POINT);
						RFW(in24.rrr.r);
						RFR(in24.rrr.s);
						RFR(in24.rrr.t);
						break;
					case 0b0100: // MADD.S
						INSN(XTENSA_INSN_MADD_S, XTENSA_GRP_FLOATING_POINT);
						RFW(in24.rrr.r);
						RFR(in24.rrr.s);
						RFR(in24.rrr.t);
						break;
					case 0b0101: // MSUB.S
						INSN(XTENSA_INSN_MSUB_S, XTENSA_GRP_FLOATING_POINT);
						RFW(in24.rrr.r);
						RFR(in24.rrr.s);
						RFR(in24.rrr.t);
						break;
					case 0b1000: // ROUND.S
						INSN(XTENSA_INSN_ROUND_S, XTENSA_GRP_FLOATING_POINT);
						RGW(in24.rrr.r);
						RFR(in24.rrr.s);
						IMMR(4, in24.rrr.t);
						break;
					case 0b1001: // TRUNC.S
						INSN(XTENSA_INSN_TRUNC_S, XTENSA_GRP_FLOATING_POINT);
						RGW(in24.rrr.r);
						RFR(in24.rrr.s);
						IMMR(4, in24.rrr.t);
						break;
					case 0b1010: // FLOOR.S
						INSN(XTENSA_INSN_FLOOR_S, XTENSA_GRP_FLOATING_POINT);
						RGW(in24.rrr.r);
						RFR(in24.rrr.s);
						IMMR(4, in24.rrr.t);
						break;
					case 0b1011: // CEIL.S
						INSN(XTENSA_INSN_CEIL_S, XTENSA_GRP_FLOATING_POINT);
						RGW(in24.rrr.r);
						RFR(in24.rrr.s);
						IMMR(4, in24.rrr.t);
						break;
					case 0b1100: // FLOAT.S
						INSN(XTENSA_INSN_FLOAT_S, XTENSA_GRP_FLOATING_POINT);
						RFW(in24.rrr.r);
						RGR(in24.rrr.s);
						IMMR(4, in24.rrr.t);
						break;
					case 0b1101: // UFLOAT.S
						INSN(XTENSA_INSN_UFLOAT_S, XTENSA_GRP_FLOATING_POINT);
						RFW(in24.rrr.r);
						RGR(in24.rrr.s);
						IMMR(4, in24.rrr.t);
						break;
					case 0b1110: // UTRUNC.S
						INSN(XTENSA_INSN_UTRUNC_S, XTENSA_GRP_FLOATING_POINT);
						RGW(in24.rrr.r);
						RFR(in24.rrr.s);
						IMMR(4, in24.rrr.t);
						break;
					case 0b1111: // FP1OP
						switch (in24.rrr.t)
						{
						case 0b0000: // MOV.S
							INSN(XTENSA_INSN_MOV_S, XTENSA_GRP_FLOATING_POINT);
							RFW(in24.rrr.r);
							RFR(in24.rrr.s);
							break;
						case 0b0001: // ABS.S
							INSN(XTENSA_INSN_ABS_S, XTENSA_GRP_FLOATING_POINT);
							RFW(in24.rrr.r);
							RFR(in24.rrr.s);
							break;
						case 0b0100: // RFR
							INSN(XTENSA_INSN_RFR, XTENSA_GRP_FLOATING_POINT);
							RGW(in24.rrr.r);
							RFR(in24.rrr.s);
							break;
						case 0b0101: // WFR
							INSN(XTENSA_INSN_WFR, XTENSA_GRP_FLOATING_POINT);
							RFW(in24.rrr.r);
							RGR(in24.rrr.s);
							break;
						case 0b0110: // NEG.S
							INSN(XTENSA_INSN_NEG_S, XTENSA_GRP_FLOATING_POINT);
							RFW(in24.rrr.r);
							RFR(in24.rrr.s);
							break;
						}
						break;
					}
					break;
				case 0b1011: // FP1
					switch (in24.rrr.op2)
					{
					case 0b0001: // UN.S
						INSN(XTENSA_INSN_UN_S, XTENSA_GRP_FLOATING_POINT);
						RBW(in24.rrr.r);
						RFR(in24.rrr.s);
						RFR(in24.rrr.t);
						break;
					case 0b0010: // OEQ.S
						INSN(XTENSA_INSN_OEQ_S, XTENSA_GRP_FLOATING_POINT);
						RBW(in24.rrr.r);
						RFR(in24.rrr.s);
						RFR(in24.rrr.t);
						break;
					case 0b0011: // UEQ.S
						INSN(XTENSA_INSN_UEQ_S, XTENSA_GRP_FLOATING_POINT);
						RBW(in24.rrr.r);
						RFR(in24.rrr.s);
						RFR(in24.rrr.t);
						break;
					case 0b0100: // OLT.S
						INSN(XTENSA_INSN_OLT_S, XTENSA_GRP_FLOATING_POINT);
						RBW(in24.rrr.r);
						RFR(in24.rrr.s);
						RFR(in24.rrr.t);
						break;
					case 0b0101: // ULT.S
						INSN(XTENSA_INSN_ULT_S, XTENSA_GRP_FLOATING_POINT);
						RBW(in24.rrr.r);
						RFR(in24.rrr.s);
						RFR(in24.rrr.t);
						break;
					case 0b0110: // OLE.S
						INSN(XTENSA_INSN_OLE_S, XTENSA_GRP_FLOATING_POINT);
						RBW(in24.rrr.r);
						RFR(in24.rrr.s);
						RFR(in24.rrr.t);
						break;
					case 0b0111: // ULE.S
						INSN(XTENSA_INSN_ULE_S, XTENSA_GRP_FLOATING_POINT);
						RBW(in24.rrr.r);
						RFR(in24.rrr.s);
						RFR(in24.rrr.t);
						break;
					case 0b1000: // MOVEQZ.S
						INSN(XTENSA_INSN_MOVEQZ_S, XTENSA_GRP_FLOATING_POINT);
						RFW(in24.rrr.r);
						RFR(in24.rrr.s);
						RGR(in24.rrr.t);
						break;
					case 0b1001: // MOVNEZ.S
						INSN(XTENSA_INSN_MOVNEZ_S, XTENSA_GRP_FLOATING_POINT);
						RFW(in24.rrr.r);
						RFR(in24.rrr.s);
						RGR(in24.rrr.t);
						break;
					case 0b1010: // MOVLTZ.S
						INSN(XTENSA_INSN_MOVLTZ_S, XTENSA_GRP_FLOATING_POINT);
						RFW(in24.rrr.r);
						RFR(in24.rrr.s);
						RGR(in24.rrr.t);
						break;
					case 0b1011: // MOVGEZ.S
						INSN(XTENSA_INSN_MOVGEZ_S, XTENSA_GRP_FLOATING_POINT);
						RFW(in24.rrr.r);
						RFR(in24.rrr.s);
						RGR(in24.rrr.t);
						break;
					case 0b1100: // MOVF.S
						INSN(XTENSA_INSN_MOVF_S, XTENSA_GRP_FLOATING_POINT);
						RFW(in24.rrr.r);
						RFR(in24.rrr.s);
						RBR(in24.rrr.t);
						break;
					case 0b1101: // MOVT.S
						INSN(XTENSA_INSN_MOVT_S, XTENSA_GRP_FLOATING_POINT);
						RFW(in24.rrr.r);
						RFR(in24.rrr.s);
						RBR(in24.rrr.t);
						break;
					}
					break;
				}
				break;
			case 0b0001: // L32R
				// TODO: this is the only instruction that
				// includes an operand that is 16 bits but
				// not aligned to 16 bits within the structure.
				// We need to check it but cannot make the
				// assembler create valid offsets without
				// linking.
				INSN(XTENSA_INSN_L32R, XTENSA_GRP_LOAD);
				RGW(in24.ri16.t);
				IMMR(16, in24.ri16.imm08 | (in24.ri16.imm816 << 8));
				break;
			case 0b0010: // LSAI
				switch (in24.rri4.r)
				{
				case 0b0000: // L8UI
					INSN(XTENSA_INSN_L8UI, XTENSA_GRP_LOAD);
					RGW(in24.rri8.t);
					RGR(in24.rri8.s);
					IMMR(8, in24.rri8.imm8);
					break;
				case 0b0001: // L16UI
					INSN(XTENSA_INSN_L16UI, XTENSA_GRP_LOAD);
					RGW(in24.rri8.t);
					RGR(in24.rri8.s);
					IMMR(8, in24.rri8.imm8 << 1);
					break;
				case 0b0010: // L32I
					INSN(XTENSA_INSN_L32I, XTENSA_GRP_LOAD);
					RGW(in24.rri8.t);
					RGR(in24.rri8.s);
					IMMR(8, in24.rri8.imm8 << 2);
					break;
				case 0b0100: // S8I
					INSN(XTENSA_INSN_S8I, XTENSA_GRP_STORE);
					RGR(in24.rri8.t);
					RGR(in24.rri8.s);
					IMMR(8, in24.rri8.imm8);
					break;
				case 0b0101: // S16I
					INSN(XTENSA_INSN_S16I, XTENSA_GRP_STORE);
					RGR(in24.rri8.t);
					RGR(in24.rri8.s);
					IMMR(8, in24.rri8.imm8 << 1);
					break;
				case 0b0110: // S32I
					INSN(XTENSA_INSN_S32I, XTENSA_GRP_STORE);
					RGR(in24.rri8.t);
					RGR(in24.rri8.s);
					IMMR(8, in24.rri8.imm8 << 2);
					break;
				case 0b0111: // CACHE
					if (in24.rri4.t < 0b1000)
					{
						switch (in24.rri4.t)
						{
						case 0b0000: // DPFR
							INSN(XTENSA_INSN_DPFR, XTENSA_GRP_CACHE);
							break;
						case 0b0001: // DPFW
							INSN(XTENSA_INSN_DPFW, XTENSA_GRP_CACHE);
							break;
						case 0b0010: // DPFRO
							INSN(XTENSA_INSN_DPFRO, XTENSA_GRP_CACHE);
							break;
						case 0b0011: // DPFWO
							INSN(XTENSA_INSN_DPFWO, XTENSA_GRP_CACHE);
							break;
						case 0b0100: // DHWB
							INSN(XTENSA_INSN_DHWB, XTENSA_GRP_CACHE);
							break;
						case 0b0101: // DHWBI
							INSN(XTENSA_INSN_DHWBI, XTENSA_GRP_CACHE);
							break;
						case 0b0110: // DHI
							INSN(XTENSA_INSN_DHI, XTENSA_GRP_CACHE);
							break;
						case 0b0111: // DII
							INSN(XTENSA_INSN_DII, XTENSA_GRP_CACHE);
							break;
						}
						RGR(in24.rri8.s);
						IMMR(8, in24.rri8.imm8 * 4);
					}
					else
					{
						switch (in24.rri4.t)
						{
						case 0b1000: // DCE
							switch (in24.rri4.op1)
							{
							case 0b0000: // DPFL
								INSN(XTENSA_INSN_DPFL, XTENSA_GRP_CACHE);
								break;
							case 0b0010: // DHU
								INSN(XTENSA_INSN_DHU, XTENSA_GRP_CACHE);
								break;
							case 0b0011: // DIU
								INSN(XTENSA_INSN_DIU, XTENSA_GRP_CACHE);
								break;
							case 0b0100: // DIWB
								INSN(XTENSA_INSN_DIWB, XTENSA_GRP_CACHE);
								break;
							case 0b0101: // DIWBI
								INSN(XTENSA_INSN_DIWBI, XTENSA_GRP_CACHE);
								break;
							}
							RGR(in24.rri4.s * 4);
							IMMR(4, in24.rri4.imm4);
							break;
						case 0b1100: // IPF
							INSN(XTENSA_INSN_IPF, XTENSA_GRP_CACHE);
							RGR(in24.rri8.s);
							IMMR(8, in24.rri8.imm8 * 4);
							break;
						case 0b1101: // ICE
							switch (in24.rri4.op1)
							{
							case 0b0000: // IPFL
								INSN(XTENSA_INSN_IPFL, XTENSA_GRP_CACHE);
								break;
							case 0b0010: // IHU
								INSN(XTENSA_INSN_IHU, XTENSA_GRP_CACHE);
								break;
							case 0b0011: // IIU
								INSN(XTENSA_INSN_IIU, XTENSA_GRP_CACHE);
								break;
							}
							RGR(in24.rri4.s * 4);
							IMMR(4, in24.rri4.imm4);
							break;
						case 0b1110: // IHI
							INSN(XTENSA_INSN_IHI, XTENSA_GRP_CACHE);
							RGR(in24.rri8.s);
							IMMR(8, in24.rri8.imm8 * 4);
							break;
						case 0b1111: // III
							INSN(XTENSA_INSN_III, XTENSA_GRP_CACHE);
							RGR(in24.rri8.s);
							IMMR(8, in24.rri8.imm8 * 4);
							break;
						}
					}
					break;
				case 0b1001: // L16SI
					INSN(XTENSA_INSN_L16SI, XTENSA_GRP_LOAD);
					RGW(in24.rri8.t);
					RGR(in24.rri8.s);
					IMMR(8, in24.rri8.imm8 * 2);
					break;
				case 0b1010: // MOVI
					INSN(XTENSA_INSN_MOVI, XTENSA_GRP_MOVE);
					RGW(in24.rri8.t);
					IMMR(8, compliment(12, 2047, (in24.rri8.s << 8) | in24.rri8.imm8));
					break;
				case 0b1011: // L32AI
					INSN(XTENSA_INSN_L32AI, XTENSA_GRP_LOAD);
					RGW(in24.rri8.t);
					RGR(in24.rri8.s);
					IMMR(8, in24.rri8.imm8 * 4);
					break;
				case 0b1100: // ADDI
					INSN(XTENSA_INSN_ADDI, XTENSA_GRP_ARITHMETIC);
					RGW(in24.rri8.t);
					RGR(in24.rri8.s);
					IMMR(8, (int8_t)in24.rri8.imm8);
					break;
				case 0b1101: // ADDMI
					INSN(XTENSA_INSN_ADDMI, XTENSA_GRP_ARITHMETIC);
					RGW(in24.rri8.t);
					RGR(in24.rri8.s);
					IMMR(8, (int8_t)in24.rri8.imm8 << 8);
					break;
				case 0b1110: // S32C1I
					INSN(XTENSA_INSN_S32C1I, XTENSA_GRP_STORE);
					RGW(in24.rri8.t);
					RGR(in24.rri8.s);
					IMMR(8, in24.rri8.imm8 * 4);
					break;
				case 0b1111: // S32RI
					INSN(XTENSA_INSN_S32RI, XTENSA_GRP_STORE);
					RGW(in24.rri8.t);
					RGR(in24.rri8.s);
					IMMR(8, in24.rri8.imm8 * 4);
					break;
				}
				break;
			case 0b0011: // LSCI
				switch (in24.rri8.r)
				{
				case 0b0000: // LSI
					INSN(XTENSA_INSN_LSI, XTENSA_GRP_FLOATING_POINT);
					RFW(in24.rri8.t);
					RGR(in24.rri8.s);
					IMMR(8, in24.rri8.imm8 * 4);
					break;
				case 0b0100: // SSI
					INSN(XTENSA_INSN_SSI, XTENSA_GRP_FLOATING_POINT);
					RFR(in24.rri8.t);
					RGR(in24.rri8.s);
					IMMR(8, in24.rri8.imm8 * 4);
					break;
				case 0b1000: // LSIU
					INSN(XTENSA_INSN_LSIU, XTENSA_GRP_FLOATING_POINT);
					RFW(in24.rri8.t);
					RGRW(in24.rri8.s);
					IMMR(8, in24.rri8.imm8 * 4);
					break;
				case 0b1100: // SSIU
					INSN(XTENSA_INSN_SSIU, XTENSA_GRP_FLOATING_POINT);
					RFR(in24.rri8.t);
					RGRW(in24.rri8.s);
					IMMR(8, in24.rri8.imm8 * 4);
					break;
				}
				break;
			case 0b0100: // MAC16
				switch (in24.rrr.op2)
				{
				case 0b0000: // MACID
					// MULA.DD.*.LDINC
					INSN(XTENSA_INSN_MULA_DD_LLLDINC + (in24.rrr.op1 & 0b11), XTENSA_GRP_MAC16);
					RMR(in24.rrr.r & 0b11);
					RGR(in24.rrr.s);
					RMR(in24.rrr.r >> 2);
					RMR(2 + (in24.rrr.t >> 2));
					break;
				case 0b0001: // MACCD
					// MULA.DD.*.LDDEC
					INSN(XTENSA_INSN_MULA_DD_LLLDDEC + (in24.rrr.op1 & 0b11), XTENSA_GRP_MAC16);
					RMR(in24.rrr.r & 0b11);
					RGR(in24.rrr.s);
					RMR(in24.rrr.r >> 2);
					RMR(2 + (in24.rrr.t >> 2));
					break;
				case 0b0010: // MACDD
					switch (in24.rrr.op1 >> 2)
					{
					case 0b01: // MUL.DD.*
						INSN(XTENSA_INSN_MUL_DD_LL + (in24.rrr.op1 & 0b11), XTENSA_GRP_MAC16);
						RMR(in24.rrr.t >> 2);
						RMR(2 + (in24.rrr.t >> 2));
						break;
					case 0b10: // MULA.DD.*
						INSN(XTENSA_INSN_MULA_DD_LL + (in24.rrr.op1 & 0b11), XTENSA_GRP_MAC16);
						RMR(in24.rrr.t >> 2);
						RMR(2 + (in24.rrr.t >> 2));
						break;
					case 0b11: // MULS.DD.*
						INSN(XTENSA_INSN_MULS_DD_LL + (in24.rrr.op1 & 0b11), XTENSA_GRP_MAC16);
						RMR(in24.rrr.t >> 2);
						RMR(2 + (in24.rrr.t >> 2));
						break;
					}
					break;
				case 0b0011: // MACAD
					switch (in24.rrr.op1 >> 2)
					{
					case 0b01: // MUL.AD.*
						INSN(XTENSA_INSN_MUL_AD_LL + (in24.rrr.op1 & 0b11), XTENSA_GRP_MAC16);
						RGR(in24.rrr.s);
						RMR(2 + (in24.rrr.t >> 2));
						break;
					case 0b10: // MULA.AD.*
						INSN(XTENSA_INSN_MULA_AD_LL + (in24.rrr.op1 & 0b11), XTENSA_GRP_MAC16);
						RGR(in24.rrr.s);
						RMR(2 + (in24.rrr.t >> 2));
						break;
					case 0b11: // MULS.AD.*
						INSN(XTENSA_INSN_MULS_AD_LL + (in24.rrr.op1 & 0b11), XTENSA_GRP_MAC16);
						RGR(in24.rrr.s);
						RMR(2 + (in24.rrr.t >> 2));
						break;
					}
					break;
				case 0b0100: // MACIA
					// MULA.DA.*.LDINC
					INSN(XTENSA_INSN_MULA_DA_LLLDINC + (in24.rrr.op1 & 0b11), XTENSA_GRP_MAC16);
					RMR(in24.rrr.r & 0b11);
					RGR(in24.rrr.s);
					RMR(in24.rrr.r >> 2);
					RGR(in24.rrr.t);
					break;
				case 0b0101: // MACCA
					// MULA.DA.*.LDDEC
					INSN(XTENSA_INSN_MULA_DA_LLLDDEC + (in24.rrr.op1 & 0b11), XTENSA_GRP_MAC16);
					RMR(in24.rrr.r & 0b11);
					RGR(in24.rrr.s);
					RMR(in24.rrr.r >> 2);
					RGR(in24.rrr.t);
					break;
				case 0b0110: // MACDA
					switch (in24.rrr.op1 >> 2)
					{
					case 0b01: // MUL.DA.*
						INSN(XTENSA_INSN_MUL_DA_LL + (in24.rrr.op1 & 0b11), XTENSA_GRP_MAC16);
						RMR(in24.rrr.r >> 2);
						RGR(in24.rrr.t);
						break;
					case 0b10: // MULA.DA.*
						INSN(XTENSA_INSN_MULA_DA_LL + (in24.rrr.op1 & 0b11), XTENSA_GRP_MAC16);
						RMR(in24.rrr.r >> 2);
						RGR(in24.rrr.t);
						break;
					case 0b11: // MULS.DA.*
						INSN(XTENSA_INSN_MULS_DA_LL + (in24.rrr.op1 & 0b11), XTENSA_GRP_MAC16);
						RMR(in24.rrr.r >> 2);
						RGR(in24.rrr.t);
						break;
					}
					break;
				case 0b0111: // MACAA
					switch (in24.rrr.op1 >> 2)
					{
					case 0b00: // UMUL.AA.*
						INSN(XTENSA_INSN_UMUL_AA_LL + (in24.rrr.op1 & 0b11), XTENSA_GRP_MAC16);
						RGR(in24.rrr.s);
						RGR(in24.rrr.t);
						break;
					case 0b01: // MUL.AA.*
						INSN(XTENSA_INSN_MUL_AA_LL + (in24.rrr.op1 & 0b11), XTENSA_GRP_MAC16);
						RGR(in24.rrr.s);
						RGR(in24.rrr.t);
						break;
					case 0b10: // MULA.AA.*
						INSN(XTENSA_INSN_MULA_AA_LL + (in24.rrr.op1 & 0b11), XTENSA_GRP_MAC16);
						RGR(in24.rrr.s);
						RGR(in24.rrr.t);
						break;
					case 0b11: // MULS.AA.*
						INSN(XTENSA_INSN_MULS_AA_LL + (in24.rrr.op1 & 0b11), XTENSA_GRP_MAC16);
						RGR(in24.rrr.s);
						RGR(in24.rrr.t);
						break;
					}
					break;
				case 0b1000:					// MACI
					if (in24.rrr.op1 == 0b0000) // LDINC
					{
						INSN(XTENSA_INSN_LDINC, XTENSA_GRP_MAC16);
						RMW(in24.rrr.r & 3);
						RGR(in24.rrr.s);
					}
					break;
				case 0b1001:					// MACC
					if (in24.rrr.op1 == 0b0000) // LDDEC
					{
						INSN(XTENSA_INSN_LDDEC, XTENSA_GRP_MAC16);
						RMW(in24.rrr.r & 3);
						RGR(in24.rrr.s);
					}
					break;
				}
				break;
			case 0b0101: // CALLN
				switch (in24.call.n)
				{
				case 0b00: // CALL0
					INSN(XTENSA_INSN_CALL0, XTENSA_GRP_CALL);
					break;
				case 0b01: // CALL4
					INSN(XTENSA_INSN_CALL4, XTENSA_GRP_CALL);
					break;
				case 0b10: // CALL8
					INSN(XTENSA_INSN_CALL8, XTENSA_GRP_CALL);
					break;
				case 0b11: // CALL12
					INSN(XTENSA_INSN_CALL12, XTENSA_GRP_CALL);
					break;
				}
				IMMR(18, in24.call.offset);
				break;
			case 0b0110: // SI
				switch (in24.call.n)
				{
				case 0b00: // J
					INSN(XTENSA_INSN_J, XTENSA_GRP_CALL);
					IMMR(18, in24.call.offset);
					break;
				case 0b01: // BZ
					switch (in24.bri12.m)
					{
					case 0b00: // BEQZ
						INSN(XTENSA_INSN_BEQZ, XTENSA_GRP_BRANCH_RELATIVE);
						break;
					case 0b01: // BNEZ
						INSN(XTENSA_INSN_BNEZ, XTENSA_GRP_BRANCH_RELATIVE);
						break;
					case 0b10: // BLTZ
						INSN(XTENSA_INSN_BLTZ, XTENSA_GRP_BRANCH_RELATIVE);
						break;
					case 0b11: // BGEZ
						INSN(XTENSA_INSN_BGEZ, XTENSA_GRP_BRANCH_RELATIVE);
						break;
					}
					RGR(in24.rri8.s);
					IMMR(8, in24.rri8.imm8);
					break;
				case 0b10: // BI0
					switch (in24.bri12.m)
					{
					case 0b00: // BEQI
						INSN(XTENSA_INSN_BEQI, XTENSA_GRP_BRANCH_RELATIVE);
						break;
					case 0b01: // BNEI
						INSN(XTENSA_INSN_BNEI, XTENSA_GRP_BRANCH_RELATIVE);
						break;
					case 0b10: // BLTI
						INSN(XTENSA_INSN_BLTI, XTENSA_GRP_BRANCH_RELATIVE);
						break;
					case 0b11: // BGEI
						INSN(XTENSA_INSN_BGEI, XTENSA_GRP_BRANCH_RELATIVE);
						break;
					}
					RGR(in24.rri8.s);
					IMMR(4, b4const(in24.rri8.r));
					IMMR(8, in24.rri8.imm8);
					break;
				case 0b11: // BI1
					switch (in24.bri12.m)
					{
					case 0b00: // ENTRY
						INSN(XTENSA_INSN_ENTRY, XTENSA_GRP_CALL);
						RGR(in24.bri12.s);
						IMMR(8, in24.bri12.imm12 * 8);
						break;
					case 0b01: // B1
						switch (in24.bri8.r)
						{
						case 0b0000: // BF
							INSN(XTENSA_INSN_BF, XTENSA_GRP_BRANCH_RELATIVE);
							RBR(in24.rri8.s);
							IMMR(8, in24.rri8.imm8);
							break;
						case 0b0001: // BT
							INSN(XTENSA_INSN_BT, XTENSA_GRP_BRANCH_RELATIVE);
							RBR(in24.rri8.s);
							IMMR(8, in24.rri8.imm8);
							break;
						case 0b1000: // LOOP
							INSN(XTENSA_INSN_LOOP, XTENSA_GRP_LOOP);
							RGR(in24.rri8.s);
							IMMR(8, in24.rri8.imm8);
							break;
						case 0b1001: // LOOPNEZ
							INSN(XTENSA_INSN_LOOPNEZ, XTENSA_GRP_BRANCH_RELATIVE);
							RGR(in24.rri8.s);
							IMMR(8, in24.rri8.imm8);
							break;
						case 0b1010: // LOOPGTZ
							INSN(XTENSA_INSN_LOOPGTZ, XTENSA_GRP_BRANCH_RELATIVE);
							RGR(in24.rri8.s);
							IMMR(8, in24.rri8.imm8);
							break;
						}
						break;
					case 0b10: // BLTUI
						INSN(XTENSA_INSN_BLTUI, XTENSA_GRP_BRANCH_RELATIVE);
						RGR(in24.bri8.s);
						IMMR(4, b4constu(in24.bri8.r));
						IMMR(8, in24.bri8.imm8);
						break;
					case 0b11: // BGEUI
						INSN(XTENSA_INSN_BGEUI, XTENSA_GRP_BRANCH_RELATIVE);
						RGR(in24.bri8.s);
						IMMR(4, b4constu(in24.bri8.r));
						IMMR(8, in24.bri8.imm8);
						break;
					}
					break;
				}
				break;
			case 0b0111: // B
				switch (in24.rri8.r)
				{
				case 0b0000: // BNONE
					INSN(XTENSA_INSN_BNONE, XTENSA_GRP_BRANCH_RELATIVE);
					RGR(in24.rri8.s);
					RGR(in24.rri8.t);
					IMMR(8, in24.rri8.imm8);
					break;
				case 0b0001: // BEQ
					INSN(XTENSA_INSN_BEQ, XTENSA_GRP_BRANCH_RELATIVE);
					RGR(in24.rri8.s);
					RGR(in24.rri8.t);
					IMMR(8, in24.rri8.imm8);
					break;
				case 0b0010: // BLT
					INSN(XTENSA_INSN_BLT, XTENSA_GRP_BRANCH_RELATIVE);
					RGR(in24.rri8.s);
					RGR(in24.rri8.t);
					IMMR(8, in24.rri8.imm8);
					break;
				case 0b0011: // BLTU
					INSN(XTENSA_INSN_BLTU, XTENSA_GRP_BRANCH_RELATIVE);
					RGR(in24.rri8.s);
					RGR(in24.rri8.t);
					IMMR(8, in24.rri8.imm8);
					break;
				case 0b0100: // BALL
					INSN(XTENSA_INSN_BALL, XTENSA_GRP_BRANCH_RELATIVE);
					RGR(in24.rri8.s);
					RGR(in24.rri8.t);
					IMMR(8, in24.rri8.imm8);
					break;
				case 0b0101: // BBC
					INSN(XTENSA_INSN_BBC, XTENSA_GRP_BRANCH_RELATIVE);
					RGR(in24.rri8.s);
					RGR(in24.rri8.t);
					IMMR(8, in24.rri8.imm8);
					break;
				case 0b0110: // BBCI
				case 0b0111:
					INSN(XTENSA_INSN_BBCI, XTENSA_GRP_BRANCH_RELATIVE);
					RGR(in24.rri8.s);
					IMMR(5, in24.rri8.t | ((in24.rri8.r & 1) << 4));
					IMMR(8, in24.rri8.imm8);
					break;
				case 0b1000: // BANY
					INSN(XTENSA_INSN_BANY, XTENSA_GRP_BRANCH_RELATIVE);
					RGR(in24.rri8.s);
					RGR(in24.rri8.t);
					IMMR(8, in24.rri8.imm8);
					break;
				case 0b1001: // BNE
					INSN(XTENSA_INSN_BNE, XTENSA_GRP_BRANCH_RELATIVE);
					RGR(in24.rri8.s);
					RGR(in24.rri8.t);
					IMMR(8, in24.rri8.imm8);
					break;
				case 0b1010: // BGE
					INSN(XTENSA_INSN_BGE, XTENSA_GRP_BRANCH_RELATIVE);
					RGR(in24.rri8.s);
					RGR(in24.rri8.t);
					IMMR(8, in24.rri8.imm8);
					break;
				case 0b1011: // BGEU
					INSN(XTENSA_INSN_BGEU, XTENSA_GRP_BRANCH_RELATIVE);
					RGR(in24.rri8.s);
					RGR(in24.rri8.t);
					IMMR(8, in24.rri8.imm8);
					break;
				case 0b1100: // BNALL
					INSN(XTENSA_INSN_BNALL, XTENSA_GRP_BRANCH_RELATIVE);
					RGR(in24.rri8.s);
					RGR(in24.rri8.t);
					IMMR(8, in24.rri8.imm8);
					break;
				case 0b1101: // BBS
					INSN(XTENSA_INSN_BBS, XTENSA_GRP_BRANCH_RELATIVE);
					RGR(in24.rri8.s);
					RGR(in24.rri8.t);
					IMMR(8, in24.rri8.imm8);
					break;
				case 0b1110: // BBSI
				case 0b1111:
					INSN(XTENSA_INSN_BBSI, XTENSA_GRP_BRANCH_RELATIVE);
					RGR(in24.rri8.s);
					IMMR(5, in24.rri8.t | ((in24.rri8.r & 1) << 4));
					IMMR(8, in24.rri8.imm8);
					break;
				}
				break;
			}
			size = insn ? 3 : 0;
		}
	}

	if (csn->detail)
	{
		if (group1)
			csn->detail->groups[csn->detail->groups_count++] = group1;
		if (group2)
			csn->detail->groups[csn->detail->groups_count++] = group2;
		if (group3)
			csn->detail->groups[csn->detail->groups_count++] = group3;
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
		if (size)
		{
			*size = insnbytes;
		}
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
