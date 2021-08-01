#ifndef CAPSTONE_XTENSA_H
#define CAPSTONE_XTENSA_H

/* Capstone Disassembly Engine */
/* Xtensa Backend By Cillié Malan */


#ifdef __cplusplus
extern "C" {
#endif

#if !defined(_MSC_VER) || !defined(_KERNEL_MODE)
#include <stdint.h>
#endif

#include "platform.h"

/// Operand type for instruction's operands
typedef enum xtensa_op_type {
	XTENSA_OP_INVALID = 0, ///< = CS_OP_INVALID (Uninitialized).
	XTENSA_OP_REG, ///< = CS_OP_REG (Register operand).
	XTENSA_OP_IMM, ///< = CS_OP_IMM (Immediate operand).
	// Note: Xtensa doesn't have memory operands.
} xtensa_op_type;

// Instruction operand
typedef struct cs_xtensa_op {
	xtensa_op_type type;	///< operand type
	union {
		unsigned int reg;	///< register value for REG operand
		int32_t imm;		///< immediate value for IMM operand
	};

	/// size of this operand (in bytes).
	uint8_t size;

	/// How is this operand accessed? (READ, WRITE or READ|WRITE)
	/// This field is combined of cs_ac_type.
	/// NOTE: this field is irrelevant if engine is compiled in DIET mode.
	uint8_t access;
} cs_xtensa_op;

// Instruction structure
typedef struct cs_xtensa {
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


#ifdef __cplusplus
}
#endif

#endif

