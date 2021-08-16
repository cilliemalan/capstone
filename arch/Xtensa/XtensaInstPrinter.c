#include "XtensaInstPrinter.h"
#include "XtensaMapping.h"

void Xtensa_printInst(MCInst *MI, SStream *O, void *info)
{
	SStream_concat(O, "%s", Xtensa_insn_name((csh)MI->csh, MI->Opcode));
	const cs_xtensa *xt = &MI->flat_insn->detail->xtensa;
	for (uint8_t i = 0; i < xt->op_count; i++)
	{
		const cs_xtensa_op *op = &xt->operands[i];

		// TODO: some instructions have a different format such as XSR.*

		if (i == 0)
		{
			SStream_concat(O, "\t");
		}
		else
		{
			SStream_concat(O, ",\t");
		}

		switch (op->type)
		{
		case XTENSA_OP_REG:
		case XTENSA_OP_FP:
			SStream_concat(O, Xtensa_reg_name((csh)MI->csh, op->reg));
			break;
		case XTENSA_OP_IMM:
			// TODO: proper handling for large unsigned immediates
			SStream_concat(O, "%i", op->imm);
			break;
		case XTENSA_OP_SYSREG:
			SStream_concat(O, Xtensa_sysreg_name((csh)MI->csh, op->reg));
			break;
		case XTENSA_OP_USERREG:
			SStream_concat(O, Xtensa_userreg_name((csh)MI->csh, op->reg));
			break;
		case XTENSA_OP_MEM:
			// xtensa doesn't have memory operands
		case XTENSA_OP_INVALID:
		default:
			break;
		}
	}
}
