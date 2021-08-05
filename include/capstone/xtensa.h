#ifndef CAPSTONE_XTENSA_H
#define CAPSTONE_XTENSA_H

/* Capstone Disassembly Engine */
/* Xtensa Backend By Cillié Malan */

#ifdef __cplusplus
extern "C"
{
#endif

#if !defined(_MSC_VER) || !defined(_KERNEL_MODE)
#include <stdint.h>
#endif

#include "platform.h"

	/// Operand type for instruction's operands
	typedef enum xtensa_op_type
	{
		XTENSA_OP_INVALID = 0, ///< = CS_OP_INVALID (Uninitialized).
		XTENSA_OP_REG,		   ///< = CS_OP_REG (Register operand).
		XTENSA_OP_IMM,		   ///< = CS_OP_IMM (Immediate operand).
		XTENSA_OP_MEM,		   ///< = CS_OP_MEM (Immediate operand).
							   ///< Note: Xtensa doesn't have memory operands.
		XTENSA_OP_FP,		   ///< = CS_OP_FP (Immediate operand).
		XTENSA_OP_SYSREG,	   ///< = XTENSA_OP_SYSREG (System register operand).
		XTENSA_OP_USERREG,	   ///< = XTENSA_OP_USERREG (User register operand).
	} xtensa_op_type;

	// Instruction operand
	typedef struct cs_xtensa_op
	{
		xtensa_op_type type; ///< operand type
		union
		{
			unsigned int reg; ///< register value for REG operand
			int32_t imm;	  ///< immediate value for IMM operand
		};

		/// size of this operand (in bytes).
		uint8_t size;

		/// How is this operand accessed? (READ, WRITE or READ|WRITE)
		/// This field is combined of cs_ac_type.
		/// NOTE: this field is irrelevant if engine is compiled in DIET mode.
		uint8_t access;
	} cs_xtensa_op;

	// Instruction structure
	typedef struct cs_xtensa
	{
		/// Number of operands of this instruction.
		uint8_t op_count;

		/// operands for this instruction.
		cs_xtensa_op operands[4];

		/// The movement, in bytes, of the register window (see 5.3.6 Windowed
		/// Register Option Special Registers) of the ISA. e.g. if
		/// register_window_movement = 12 it means a12..a15 will be made a0..a3
		/// when ENTRY is called.
		/// @remarks This is only set for CALL4/8/12 and CALLX4/8/12 instructions.
		int8_t register_window_movement;
	} cs_xtensa;

	typedef enum xtensa_reg
	{
		XTENSA_REG_INVALID = 0,

		//> General purpose registers
		XTENSA_REG_A0,
		XTENSA_REG_A1,
		XTENSA_REG_A2,
		XTENSA_REG_A3,
		XTENSA_REG_A4,
		XTENSA_REG_A5,
		XTENSA_REG_A6,
		XTENSA_REG_A7,
		XTENSA_REG_A8,
		XTENSA_REG_A9,
		XTENSA_REG_A10,
		XTENSA_REG_A11,
		XTENSA_REG_A12,
		XTENSA_REG_A13,
		XTENSA_REG_A14,
		XTENSA_REG_A15,

		//> Floating point co-processor registers
		XTENSA_FP_REG_FR0,
		XTENSA_FP_REG_FR1,
		XTENSA_FP_REG_FR2,
		XTENSA_FP_REG_FR3,
		XTENSA_FP_REG_FR4,
		XTENSA_FP_REG_FR5,
		XTENSA_FP_REG_FR6,
		XTENSA_FP_REG_FR7,
		XTENSA_FP_REG_FR8,
		XTENSA_FP_REG_FR9,
		XTENSA_FP_REG_FR10,
		XTENSA_FP_REG_FR11,
		XTENSA_FP_REG_FR12,
		XTENSA_FP_REG_FR13,
		XTENSA_FP_REG_FR14,
		XTENSA_FP_REG_FR15,
	} xtensa_reg;

	typedef enum xtensa_special_reg
	{
		XTENSA_SPECIAL_REG_INVALID = 0,

		//> Xtensa special registers
		XTENSA_SPECIAL_REG_LBEG = 1 + 0,
		XTENSA_SPECIAL_REG_LEND = 1 + 1,
		XTENSA_SPECIAL_REG_LCOUNT = 1 + 2,
		XTENSA_SPECIAL_REG_SAR = 1 + 3,
		XTENSA_SPECIAL_REG_BR = 1 + 4,
		XTENSA_SPECIAL_REG_LITBASE = 1 + 5,
		XTENSA_SPECIAL_REG_SCOMPARE1 = 1 + 12,
		XTENSA_SPECIAL_REG_ACCLO = 1 + 16,
		XTENSA_SPECIAL_REG_ACCHI = 1 + 17,
		XTENSA_SPECIAL_REG_MR0 = 1 + 32,
		XTENSA_SPECIAL_REG_MR1 = 1 + 33,
		XTENSA_SPECIAL_REG_MR2 = 1 + 34,
		XTENSA_SPECIAL_REG_MR3 = 1 + 35,
		XTENSA_SPECIAL_REG_WINDOWBASE = 1 + 72,
		XTENSA_SPECIAL_REG_WINDOWSTART = 1 + 73,
		XTENSA_SPECIAL_REG_PTEVADDR = 1 + 83,
		XTENSA_SPECIAL_REG_MMID = 1 + 89,
		XTENSA_SPECIAL_REG_RASID = 1 + 90,
		XTENSA_SPECIAL_REG_ITLBCFG = 1 + 91,
		XTENSA_SPECIAL_REG_DTLBCFG = 1 + 92,
		XTENSA_SPECIAL_REG_IBREAKENABLE = 1 + 96,
		XTENSA_SPECIAL_REG_ATOMCTL = 1 + 99,
		XTENSA_SPECIAL_REG_DDR = 1 + 104,
		XTENSA_SPECIAL_REG_MEPS = 1 + 107,
		XTENSA_SPECIAL_REG_MEPC = 1 + 106,
		XTENSA_SPECIAL_REG_MESAVE = 1 + 108,
		XTENSA_SPECIAL_REG_MESR = 1 + 109,
		XTENSA_SPECIAL_REG_MECR = 1 + 110,
		XTENSA_SPECIAL_REG_MEVADDR = 1 + 111,
		XTENSA_SPECIAL_REG_IBREAKA0 = 1 + 128,
		XTENSA_SPECIAL_REG_IBREAKA1 = 1 + 129,
		XTENSA_SPECIAL_REG_DEBUGCAUSE = 1 + 233,
		XTENSA_SPECIAL_REG_DBREAKA0 = 1 + 144,
		XTENSA_SPECIAL_REG_DBREAKA1 = 1 + 145,
		XTENSA_SPECIAL_REG_DBREAKC0 = 1 + 160,
		XTENSA_SPECIAL_REG_DBREAKC1 = 1 + 161,
		XTENSA_SPECIAL_REG_EPC1 = 1 + 177,
		XTENSA_SPECIAL_REG_EPC2 = 1 + 178,
		XTENSA_SPECIAL_REG_EPC3 = 1 + 179,
		XTENSA_SPECIAL_REG_EPC4 = 1 + 180,
		XTENSA_SPECIAL_REG_EPC5 = 1 + 181,
		XTENSA_SPECIAL_REG_EPC6 = 1 + 182,
		XTENSA_SPECIAL_REG_EPC7 = 1 + 183,
		XTENSA_SPECIAL_REG_DEPC = 1 + 192,
		XTENSA_SPECIAL_REG_EPS2 = 1 + 194,
		XTENSA_SPECIAL_REG_EPS3 = 1 + 195,
		XTENSA_SPECIAL_REG_EPS4 = 1 + 196,
		XTENSA_SPECIAL_REG_EPS5 = 1 + 197,
		XTENSA_SPECIAL_REG_EPS6 = 1 + 198,
		XTENSA_SPECIAL_REG_EPS7 = 1 + 199,
		XTENSA_SPECIAL_REG_EXCSAVE1 = 1 + 209,
		XTENSA_SPECIAL_REG_EXCSAVE2 = 1 + 210,
		XTENSA_SPECIAL_REG_EXCSAVE3 = 1 + 211,
		XTENSA_SPECIAL_REG_EXCSAVE4 = 1 + 212,
		XTENSA_SPECIAL_REG_EXCSAVE5 = 1 + 213,
		XTENSA_SPECIAL_REG_EXCSAVE6 = 1 + 214,
		XTENSA_SPECIAL_REG_EXCSAVE7 = 1 + 215,
		XTENSA_SPECIAL_REG_CPENABLE = 1 + 224,
		XTENSA_SPECIAL_REG_INTERRUPT = 1 + 226,
		XTENSA_SPECIAL_REG_INTSET = 1 + 226,
		XTENSA_SPECIAL_REG_INTCLEAR = 1 + 227,
		XTENSA_SPECIAL_REG_INTENABLE = 1 + 228,
		XTENSA_SPECIAL_REG_PS = 1 + 230,
		XTENSA_SPECIAL_REG_VECBASE = 1 + 231,
		XTENSA_SPECIAL_REG_EXCCAUSE = 1 + 232,
		XTENSA_SPECIAL_REG_CCOUNT = 1 + 234,
		XTENSA_SPECIAL_REG_PRID = 1 + 235,
		XTENSA_SPECIAL_REG_ICOUNT = 1 + 236,
		XTENSA_SPECIAL_REG_ICOUNTLEVEL = 1 + 237,
		XTENSA_SPECIAL_REG_EXCVADDR = 1 + 238,
		XTENSA_SPECIAL_REG_CCOMPARE0 = 1 + 240,
		XTENSA_SPECIAL_REG_CCOMPARE1 = 1 + 241,
		XTENSA_SPECIAL_REG_CCOMPARE2 = 1 + 242,
		XTENSA_SPECIAL_REG_MISC0 = 1 + 244,
		XTENSA_SPECIAL_REG_MISC1 = 1 + 245,
		XTENSA_SPECIAL_REG_MISC2 = 1 + 246,
		XTENSA_SPECIAL_REG_MISC3 = 1 + 247,
	} xtensa_special_reg;

	typedef enum xtensa_user_reg
	{
		XTENSA_USER_REG_INVALID = 0,

		//> Xtensa user registers
		XTENSA_USER_REG_THREADPTR = 1 + 231,
		XTENSA_USER_REG_FCR = 1 + 232,
		XTENSA_USER_REG_FSR = 1 + 233,
	} xtensa_user_reg;

	typedef enum xtensa_insn_group
	{
		XTENSA_GRP_INVALID = 0,

		//> Xtensa instruction groups
		XTENSA_GRP_LOAD,
		XTENSA_GRP_STORE,
		XTENSA_GRP_MEMORY_ORDERING,
		XTENSA_GRP_MEMORY_JUMP_CALL,
		XTENSA_GRP_MEMORY_CONDITIONAL_BRANCH,
		XTENSA_GRP_MEMORY_MOVE,
		XTENSA_GRP_MEMORY_ARITHMETIC,
		XTENSA_GRP_MEMORY_BITWISE,
		XTENSA_GRP_MEMORY_SHIFT,
		XTENSA_GRP_MEMORY_PROCESSOR_CONTROL,
		XTENSA_GRP_MEMORY_LOOP,
		XTENSA_GRP_MEMORY_L32R,
		XTENSA_GRP_MEMORY_MAC16,
		XTENSA_GRP_MEMORY_MISC,
		XTENSA_GRP_MEMORY_COPROCESSOR,
		XTENSA_GRP_MEMORY_BOOLEAN,
		XTENSA_GRP_MEMORY_FLOATING_POINT,
		XTENSA_GRP_MEMORY_MULTIPROCESSOR_SYNCHRONIZATION,
	} xtensa_insn_group;

	typedef enum xtensa_insn
	{
		XTENSA_INSN_INVALID,

		//> Xtensa instructions
		XTENSA_INSN_ABS,
		XTENSA_INSN_ABS_S,
		XTENSA_INSN_ADD,
		XTENSA_INSN_ADD_N,
		XTENSA_INSN_ADD_S,
		XTENSA_INSN_ADDI,
		XTENSA_INSN_MOVI,

		XTENSA_INSN_NEG,
	} xtensa_insn;

#ifdef __cplusplus
}
#endif

#endif
