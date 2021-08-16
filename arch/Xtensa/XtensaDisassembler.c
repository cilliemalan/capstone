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

static void add_register(cs_insn *csn, xtensa_reg regnr, uint8_t access)
{
	if (csn->detail)
	{
		int c = csn->detail->xtensa.op_count++;
		csn->detail->xtensa.operands[c].type = XTENSA_OP_REG;
		csn->detail->xtensa.operands[c].reg = regnr;
		csn->detail->xtensa.operands[c].access = access;
		csn->detail->xtensa.operands[c].size = 4;

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

int disassemble_internal(csh ud, const uint8_t *code, size_t code_len,
						 xtensa_insn *pinsn, cs_insn *csn)
{
#define REGR(value) add_register(csn, XTENSA_REG_A0 + value, CS_AC_READ)
#define REGW(value) add_register(csn, XTENSA_REG_A0 + value, CS_AC_WRITE)
#define RFR(value) add_register(csn, XTENSA_FP_REG_FR0 + value, CS_AC_READ)
#define RFW(value) add_register(csn, XTENSA_FP_REG_FR0 + value, CS_AC_WRITE)
#define RBR(value) add_register(csn, XTENSA_BR_REG_B0 + value, CS_AC_READ)
#define RBW(value) add_register(csn, XTENSA_BR_REG_B0 + value, CS_AC_WRITE)
#define IMMR(size, value) add_immediate(csn, value, size, CS_AC_READ)
#define INSN(i, a) \
	insn = i;      \
	group1 = a;

	xtensa_insn_group group1 = XTENSA_GRP_INVALID;
	xtensa_insn_group group2 = XTENSA_GRP_INVALID;
	xtensa_insn_group group3 = XTENSA_GRP_INVALID;
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
				INSN(XTENSA_INSN_ADD_N, XTENSA_GRP_ARITHMETIC);
				REGW(in16.rrrn.r);
				REGR(in16.rrrn.s);
				REGR(in16.rrrn.t);
				break;
			case 0b1011: // ADDI.N
				INSN(XTENSA_INSN_ADDI_N, XTENSA_GRP_ARITHMETIC);
				REGW(in16.rrrn.r);
				REGR(in16.rrrn.s);
				IMMR(4, in16.rrrn.t == 0 ? 0xffffffff : in16.rrrn.t);
				break;
			case 0b1100:			 // ST2.N
				if (in16.ri7.i == 0) // MOVI.N
				{
					INSN(XTENSA_INSN_MOVI_N, XTENSA_GRP_MOVE);
					REGW(in16.ri7.s);
					IMMR(7, compliment(7, 95, in16.ri7.imm764 << 4 | in16.ri7.imm730));
				}
				else if (in16.ri6.i == 0b10) // BEQZ.N
				{
					INSN(XTENSA_INSN_BEQZ_N, XTENSA_GRP_BRANCH_RELATIVE);
					REGR(in16.ri6.s);
					IMMR(6, in16.ri6.imm654 << 4 | in16.ri6.imm630);
				}
				else // BNEZ.N
				{
					INSN(XTENSA_INSN_BNEZ_N, XTENSA_GRP_BRANCH_RELATIVE);
					REGR(in16.ri6.s);
					IMMR(6, in16.ri6.imm654 << 4 | in16.ri6.imm630);
				}
				break;
			case 0b1101: // ST3.N
				switch (in16.rrrn.r)
				{
				case 0b0000: // MOV.N
					break;
				case 0b1111: // S3
					switch (in16.rrrn.t)
					{
					case 0b0000: // RET.N
						break;
					case 0b0001: // RETW.N
						break;
					case 0b0010: // BREAK.N
						INSN(XTENSA_INSN_BREAK_N, XTENSA_GRP_MISC);
						IMMR(4, in16.rrrn.s);
						break;
					case 0b0011: // NOP.N
						break;
					case 0b0110: // ILL.N
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
								break;
							case 0b10: // JR
								switch (in24.callx.n)
								{
								case 0b00: // RET
									break;
								case 0b01: // RETW
									break;
								case 0b10: // JX
									break;
								}
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
								REGR(in24.callx.s);
								break;
							}
							break;
						case 0b0001: // MOVSP
							break;
						case 0b0010: // SYNC
							switch (in24.rrr.t)
							{
							case 0b0000: // ISYNC
								break;
							case 0b0001: // RSYNC
								break;
							case 0b0010: // ESYNC
								break;
							case 0b0011: // DSYNC
								break;
							case 0b1000: // EXCW
								break;
							case 0b1100: // MEMW
								break;
							case 0b1101: // EXTW
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
									break;
								case 0b0001: // RFUE
									break;
								case 0b0010: // RFDE
									break;
								case 0b0100: // RFWO
									break;
								case 0b0101: // RFWU
									break;
								}
							case 0b0001: // RFI
								break;
							case 0b0010: // RFME
								break;
							}
							break;
						case 0b0100: // BREAK
							INSN(XTENSA_INSN_BREAK, XTENSA_GRP_MISC);
							IMMR(4, in24.rrr.s);
							IMMR(4, in24.rrr.t);
							break;
						case 0b0101: // SYSCALL
							break;
						case 0b0110: // RSIL
							break;
						case 0b0111: // WAITI
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
						REGW(in24.rrr.r);
						REGR(in24.rrr.s);
						REGR(in24.rrr.t);
						break;
					case 0b0010: // OR
						INSN(XTENSA_INSN_OR, XTENSA_GRP_BITWISE);
						REGW(in24.rrr.r);
						REGR(in24.rrr.s);
						REGR(in24.rrr.t);
						break;
					case 0b0011: // XOR
						INSN(XTENSA_INSN_XOR, XTENSA_GRP_BITWISE);
						REGW(in24.rrr.r);
						REGR(in24.rrr.s);
						REGR(in24.rrr.t);
						break;
					case 0b0100: // ST1
						switch (in24.rrr.r)
						{
						case 0b0000: // SSR
							break;
						case 0b0001: // SSL
							break;
						case 0b0010: // SSA8L
							break;
						case 0b0011: // SSA8B
							break;
						case 0b0100: // SSAI
							break;
						case 0b0110: // RER
							break;
						case 0b0111: // WER
							break;
						case 0b1000: // ROTW
							break;
						case 0b1110: // NSA
							break;
						case 0b1111: // NSAU
							break;
						}
						break;
					case 0b0101: // TLB
						switch (in24.rrr.r)
						{
						case 0b0011: // RITLB0
							break;
						case 0b0100: // IITLB
							break;
						case 0b0101: // PITLB
							break;
						case 0b0110: // WITLB
							break;
						case 0b0111: // RITLB1
							break;
						case 0b1011: // RDTLB0
							break;
						case 0b1100: // IDTLB
							break;
						case 0b1101: // PDTLB
							break;
						case 0b1110: // WDTLB
							break;
						case 0b1111: // RDTLB1
							break;
						}
						break;
					case 0b0110: // RT0
						switch (in24.rrr.s)
						{
						case 0b0000: // NEG
							INSN(XTENSA_INSN_NEG, XTENSA_GRP_ARITHMETIC);
							REGW(in24.rrr.r);
							REGR(in24.rrr.t);
							break;
						case 0b0001: // ABS
							INSN(XTENSA_INSN_ABS, XTENSA_GRP_ARITHMETIC);
							REGW(in24.rrr.r);
							REGR(in24.rrr.t);
							break;
						}
						break;
					case 0b1000: // ADD
						INSN(XTENSA_INSN_ADD, XTENSA_GRP_ARITHMETIC);
						REGW(in24.rrr.r);
						REGR(in24.rrr.s);
						REGR(in24.rrr.t);
						break;
					case 0b1001: // ADDX2
					case 0b1010: // ADDX4
					case 0b1011: // ADDx8
						insn = XTENSA_INSN_ADDX2 + (in24.rrr.op2 & 0b11) - 1;
						INSN(insn, XTENSA_GRP_ARITHMETIC);
						REGW(in24.rrr.r);
						REGR(in24.rrr.s);
						REGR(in24.rrr.t);
						break;
					case 0b1100: // SUB
					case 0b1101: // SUBX2
					case 0b1110: // SUBX4
					case 0b1111: // SUBX8
						insn = XTENSA_INSN_SUBX2 + (in24.rrr.op2 & 0b11) - 1;
						INSN(insn, XTENSA_GRP_ARITHMETIC);
						REGW(in24.rrr.r);
						REGR(in24.rrr.s);
						REGR(in24.rrr.t);
						break;
					}
					break;
				case 0b0001: // RST1
					switch (in24.rrr.op2)
					{
					case 0b0000:
					case 0b0001: // SLLI
						break;
					case 0b0010:
					case 0b0011: // SRAI
						break;
					case 0b0100: // SRLI
						break;
					case 0b0110: // XSR
						break;
					case 0b0111: // ACCER
						switch (in24.rrr.op2)
						{
						case 0b0000: // RER
						case 0b1000: // WER
							break;
						}
						break;
					case 0b1000: // SRC
						break;
					case 0b1001: // SRL
						break;
					case 0b1010: // SLL
						break;
					case 0b1011: // SRA
						break;
					case 0b1100: // MUL16U
						break;
					case 0b1101: // MUL16S
						break;
					case 0b1111: // IMP
						switch (in24.rrr.r)
						{
						case 0b0000: // LICT
							break;
						case 0b0001: // SICT
							break;
						case 0b0010: // LICW
							break;
						case 0b0011: // SICW
							break;
						case 0b1000: // LDCT
							break;
						case 0b1001: // SDCT
							break;
						case 0b1110: // RFDX
							switch (in24.rrr.t)
							{
							case 0b0000: // RFDO
								break;
							case 0b0001: // RFDD
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
						break;
					case 0b1010: // MULUH
						break;
					case 0b1011: // MULSH
						break;
					case 0b1100: // QUOU
						break;
					case 0b1101: // QUOS
						break;
					case 0b1110: // REMU
						break;
					case 0b1111: // REMS
						break;
					}
					break;
				case 0b0011: // RST3
					switch (in24.rrr.op2)
					{
					case 0b0000: // RSR
						break;
					case 0b0001: // WSR
						break;
					case 0b0010: // SEXT
						break;
					case 0b0011: // CLAMPS
						break;
					case 0b0100: // MIN
						break;
					case 0b0101: // MAX
						break;
					case 0b0110: // MINU
						break;
					case 0b0111: // MAXU
						break;
					case 0b1000: // MOVEQZ
						break;
					case 0b1001: // MOVNEZ
						break;
					case 0b1010: // MOVLTZ
						break;
					case 0b1011: // MOVGEZ
						break;
					case 0b1100: // MOVF
						break;
					case 0b1101: // MOVT
						break;
					case 0b1110: // RUR
						break;
					case 0b1111: // WUR
						break;
					}
					break;
				case 0b0100: // EXTUI
					break;
				case 0b0101: // EXTUI
					break;
				case 0b0110: // CUST0
					break;
				case 0b0111: // CUST1
					break;
				case 0b1000: // LSCX
					switch (in24.rrr.op2)
					{
					case 0b0000: // LSX
						break;
					case 0b0001: // LSXU
						break;
					case 0b0100: // SSX
						break;
					case 0b0101: // SSXU
						break;
					}
					break;
				case 0b1001: // LSC4
					switch (in24.rrr.op2)
					{
					case 0b0000: // L32E
						break;
					case 0b0100: // S32E
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
						REGW(in24.rrr.r);
						REGR(in24.rrr.s);
						REGR(in24.rrr.t);
						break;
					case 0b0010: // MUL.S
						INSN(XTENSA_INSN_MUL_S, XTENSA_GRP_FLOATING_POINT);
						REGW(in24.rrr.r);
						REGR(in24.rrr.s);
						REGR(in24.rrr.t);
						break;
					case 0b0100: // MADD.S
						break;
					case 0b0101: // MSUB.S
						break;
					case 0b1000: // ROUND.S
						break;
					case 0b1001: // TRUNC.S
						break;
					case 0b1010: // FLOOR.S
						break;
					case 0b1011: // CEIL.S
						INSN(XTENSA_INSN_CEIL_S, XTENSA_GRP_FLOATING_POINT);
						REGW(in24.rrr.r);
						RFR(in24.rrr.s);
						IMMR(4, in24.rrr.t);
						break;
					case 0b1100: // FLOAT.S
						break;
					case 0b1101: // UFLOAT.S
						break;
					case 0b1110: // UTRUNC.S
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
							break;
						case 0b0101: // WFR
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
						break;
					case 0b0010: // QEQ.S
						break;
					case 0b0011: // UEQ.S
						break;
					case 0b0100: // OLT.S
						break;
					case 0b0101: // ULT.S
						break;
					case 0b0110: // OLE.S
						break;
					case 0b0111: // ULE.S
						break;
					case 0b1000: // MOVEQZ.S
						break;
					case 0b1001: // MOVNEZ.S
						break;
					case 0b1010: // MOVLTZ.S
						break;
					case 0b1011: // MOVGEZ.S
						break;
					case 0b1100: // MOVF.S
						break;
					case 0b1101: // MOVT.S
						break;
					}
					break;
				}
				break;
			case 0b0001: // L32R
				break;
			case 0b0010: // LSAI
				switch (in24.rri4.r)
				{
				case 0b0000: // L8UI
					break;
				case 0b0001: // L16UI
					break;
				case 0b0010: // L32I
					break;
				case 0b0100: // S8I
					break;
				case 0b0101: // S16I
					break;
				case 0b0110: // S32I
					break;
				case 0b0111: // CACHE
					switch (in24.rri4.t)
					{
					case 0b0000: // DPFR
						break;
					case 0b0001: // DPFW
						break;
					case 0b0010: // DPFRO
						break;
					case 0b0011: // DPFWO
						break;
					case 0b0100: // DHWB
						break;
					case 0b0101: // DHWBI
						break;
					case 0b0110: // DHI
						break;
					case 0b0111: // DII
						break;
					case 0b1000: // DCE
						switch (in24.rri4.op1)
						{
						case 0b0000: // DPFL
							break;
						case 0b0010: // DHU
							break;
						case 0b0011: // DIU
							break;
						case 0b0100: // DIWB
							break;
						case 0b0101: // DIWBI
							break;
						}
						break;
					case 0b1100: // IPF
						break;
					case 0b1101: // ICE
						switch (in24.rri4.op1)
						{
						case 0b0000: // IPFL
							break;
						case 0b0010: // IHU
							break;
						case 0b0011: // IIU
							break;
						}
						break;
					case 0b1110: // IHI
						break;
					case 0b1111: // III
						break;
					}
					break;
				case 0b1001: // L16SI
					break;
				case 0b1010: // MOVI
					break;
				case 0b1011: // L32AI
					break;
				case 0b1100: // ADDI
					INSN(XTENSA_INSN_ADDI, XTENSA_GRP_FLOATING_POINT);
					REGW(in24.rri8.t);
					REGR(in24.rri8.s);
					IMMR(8, (int8_t)in24.rri8.imm8);
					break;
				case 0b1101: // ADDMI
					INSN(XTENSA_INSN_ADDMI, XTENSA_GRP_FLOATING_POINT);
					REGW(in24.rri8.t);
					REGR(in24.rri8.s);
					IMMR(8, (int8_t)in24.rri8.imm8 << 8);
					break;
				case 0b1110: // S32C1I
					break;
				case 0b1111: // S32RI
					break;
				}
				break;
			case 0b0011: // LSCI
				switch (in24.rri8.r)
				{
				case 0b0000: // LSI
					break;
				case 0b0100: // SSI
					break;
				case 0b1000: // LSIU
					break;
				case 0b1100: // SSIU
					break;
				}
				break;
			case 0b0100: // MAC16
				switch (in24.rrr.op2)
				{
				case 0b0000: // MACID
					switch (in24.rrr.op1)
					{
					case 0b1000: // MULA.DD.LL.LDINC
						break;
					case 0b1001: // MULA.DD.HL.LDINC
						break;
					case 0b1010: // MULA.DD.LH.LDINC
						break;
					case 0b1011: // MULA.DD.HH.LDINC
						break;
					}
					break;
				case 0b0001: // MACCD
					switch (in24.rrr.op1)
					{
					case 0b1000: // MULA.DD.LL.LDDEC
						break;
					case 0b1001: // MULA.DD.HL.LDDEC
						break;
					case 0b1010: // MULA.DD.LH.LDDEC
						break;
					case 0b1011: // MULA.DD.HH.LDDEC
						break;
					}
				case 0b0010: // MACDD
					switch (in24.rrr.op1)
					{
					case 0b0100: // MUL.DD.LL
						break;
					case 0b0101: // MUL.DD.HL
						break;
					case 0b0110: // MUL.DD.LH
						break;
					case 0b0111: // MUL.DD.HH
						break;
					case 0b1000: // MULA.DD.LL
						break;
					case 0b1001: // MULA.DD.HL
						break;
					case 0b1010: // MULA.DD.LH
						break;
					case 0b1011: // MULA.DD.HH
						break;
					case 0b1100: // MULS.DD.LL
						break;
					case 0b1101: // MULS.DD.HL
						break;
					case 0b1110: // MULS.DD.LH
						break;
					case 0b1111: // MULS.DD.HH
						break;
					}
					break;
				case 0b0011: // MACAD
					switch (in24.rrr.op1)
					{
					case 0b0100: // MUL.AD.LL
						break;
					case 0b0101: // MUL.AD.HL
						break;
					case 0b0110: // MUL.AD.LH
						break;
					case 0b0111: // MUL.AD.HH
						break;
					case 0b1000: // MULA.AD.LL
						break;
					case 0b1001: // MULA.AD.HL
						break;
					case 0b1010: // MULA.AD.LH
						break;
					case 0b1011: // MULA.AD.HH
						break;
					case 0b1100: // MULS.AD.LL
						break;
					case 0b1101: // MULS.AD.HL
						break;
					case 0b1110: // MULS.AD.LH
						break;
					case 0b1111: // MULS.AD.HH
						break;
					}
					break;
				case 0b0100: // MACIA
					switch (in24.rrr.op1)
					{
					case 0b1000: // MULA.DA.LL.LDINC
						break;
					case 0b1001: // MULA.DA.HL.LDINC
						break;
					case 0b1010: // MULA.DA.LH.LDINC
						break;
					case 0b1011: // MULA.DA.HH.LDINC
						break;
					}
					break;
				case 0b0101: // MACCA
					switch (in24.rrr.op1)
					{
					case 0b1000: // MULA.DA.LL.LDDEC
						break;
					case 0b1001: // MULA.DA.HL.LDDEC
						break;
					case 0b1010: // MULA.DA.LH.LDDEC
						break;
					case 0b1011: // MULA.DA.HH.LDDEC
						break;
					}
					break;
				case 0b0110: // MACDA
					switch (in24.rrr.op1)
					{
					case 0b0100: // MUL.DA.LL
						break;
					case 0b0101: // MUL.DA.HL
						break;
					case 0b0110: // MUL.DA.LH
						break;
					case 0b0111: // MUL.DA.HH
						break;
					case 0b1000: // MULA.DA.LL
						break;
					case 0b1001: // MULA.DA.HL
						break;
					case 0b1010: // MULA.DA.LH
						break;
					case 0b1011: // MULA.DA.HH
						break;
					case 0b1100: // MULS.DA.LL
						break;
					case 0b1101: // MULS.DA.HL
						break;
					case 0b1110: // MULS.DA.LH
						break;
					case 0b1111: // MULS.DA.HH
						break;
					}
					break;
				case 0b0111: // MACAA
					switch (in24.rrr.op1)
					{
					case 0b0000: // UMUL.AA.LL
						break;
					case 0b0001: // UMUL.AA.HL
						break;
					case 0b0010: // UMUL.AA.LH
						break;
					case 0b0011: // UMUL.AA.HH
						break;
					case 0b0100: // MUL.AA.LL
						break;
					case 0b0101: // MUL.AA.HL
						break;
					case 0b0110: // MUL.AA.LH
						break;
					case 0b0111: // MUL.AA.HH
						break;
					case 0b1000: // MULA.AA.LL
						break;
					case 0b1001: // MULA.AA.HL
						break;
					case 0b1010: // MULA.AA.LH
						break;
					case 0b1011: // MULA.AA.HH
						break;
					case 0b1100: // MULS.AA.LL
						break;
					case 0b1101: // MULS.AA.HL
						break;
					case 0b1110: // MULS.AA.LH
						break;
					case 0b1111: // MULS.AA.HH
						break;
					}
					break;
				case 0b1000:					// MACI
					if (in24.rrr.op1 == 0b0000) // LDINC
					{
					}
					break;
				case 0b1001:					// MACC
					if (in24.rrr.op1 == 0b0000) // LDDEC
					{
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
					REGR(in24.rri8.s);
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
					REGR(in24.rri8.s);
					IMMR(4, B4CONST(in24.rri8.r));
					IMMR(8, in24.rri8.imm8);
					break;
				case 0b11: // BI1
					switch (in24.bri12.m)
					{
					case 0b00: // ENTRY
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
							break;
						case 0b1001: // LOOPNEZ
							break;
						case 0b1010: // LOOPGTZ
							break;
						}
						break;
					case 0b10: // BLTUI
						INSN(XTENSA_INSN_BLTUI, XTENSA_GRP_BRANCH_RELATIVE);
						REGR(in24.bri8.s);
						IMMR(4, B4CONSTU(in24.bri8.r));
						IMMR(8, in24.bri8.imm8);
						break;
					case 0b11: // BGEUI
						INSN(XTENSA_INSN_BGEUI, XTENSA_GRP_BRANCH_RELATIVE);
						REGR(in24.bri8.s);
						IMMR(4, B4CONSTU(in24.bri8.r));
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
					REGR(in24.rri8.s);
					REGR(in24.rri8.t);
					IMMR(8, in24.rri8.imm8);
					break;
				case 0b0001: // BEQ
					INSN(XTENSA_INSN_BEQ, XTENSA_GRP_BRANCH_RELATIVE);
					REGR(in24.rri8.s);
					REGR(in24.rri8.t);
					IMMR(8, in24.rri8.imm8);
					break;
				case 0b0010: // BLT
					INSN(XTENSA_INSN_BLT, XTENSA_GRP_BRANCH_RELATIVE);
					REGR(in24.rri8.s);
					REGR(in24.rri8.t);
					IMMR(8, in24.rri8.imm8);
					break;
				case 0b0011: // BLTU
					INSN(XTENSA_INSN_BLTU, XTENSA_GRP_BRANCH_RELATIVE);
					REGR(in24.rri8.s);
					REGR(in24.rri8.t);
					IMMR(8, in24.rri8.imm8);
					break;
				case 0b0100: // BALL
					INSN(XTENSA_INSN_BALL, XTENSA_GRP_BRANCH_RELATIVE);
					REGR(in24.rri8.s);
					REGR(in24.rri8.t);
					IMMR(8, in24.rri8.imm8);
					break;
				case 0b0101: // BBC
					INSN(XTENSA_INSN_BBC, XTENSA_GRP_BRANCH_RELATIVE);
					REGR(in24.rri8.s);
					REGR(in24.rri8.t);
					IMMR(8, in24.rri8.imm8);
					break;
				case 0b0110: // BBCI
				case 0b0111:
					INSN(XTENSA_INSN_BBCI, XTENSA_GRP_BRANCH_RELATIVE);
					REGR(in24.rri8.s);
					IMMR(5, in24.rri8.t | ((in24.rri8.r & 1) << 4));
					IMMR(8, in24.rri8.imm8);
					break;
				case 0b1000: // BANY
					INSN(XTENSA_INSN_BANY, XTENSA_GRP_BRANCH_RELATIVE);
					REGR(in24.rri8.s);
					REGR(in24.rri8.t);
					IMMR(8, in24.rri8.imm8);
					break;
				case 0b1001: // BNE
					INSN(XTENSA_INSN_BNE, XTENSA_GRP_BRANCH_RELATIVE);
					REGR(in24.rri8.s);
					REGR(in24.rri8.t);
					IMMR(8, in24.rri8.imm8);
					break;
				case 0b1010: // BGE
					INSN(XTENSA_INSN_BGE, XTENSA_GRP_BRANCH_RELATIVE);
					REGR(in24.rri8.s);
					REGR(in24.rri8.t);
					IMMR(8, in24.rri8.imm8);
					break;
				case 0b1011: // BGEU
					INSN(XTENSA_INSN_BGEU, XTENSA_GRP_BRANCH_RELATIVE);
					REGR(in24.rri8.s);
					REGR(in24.rri8.t);
					IMMR(8, in24.rri8.imm8);
					break;
				case 0b1100: // BNALL
					INSN(XTENSA_INSN_BNALL, XTENSA_GRP_BRANCH_RELATIVE);
					REGR(in24.rri8.s);
					REGR(in24.rri8.t);
					IMMR(8, in24.rri8.imm8);
					break;
				case 0b1101: // BBS
					INSN(XTENSA_INSN_BBS, XTENSA_GRP_BRANCH_RELATIVE);
					REGR(in24.rri8.s);
					REGR(in24.rri8.t);
					IMMR(8, in24.rri8.imm8);
					break;
				case 0b1110: // BBSI
				case 0b1111:
					INSN(XTENSA_INSN_BBSI, XTENSA_GRP_BRANCH_RELATIVE);
					REGR(in24.rri8.s);
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
