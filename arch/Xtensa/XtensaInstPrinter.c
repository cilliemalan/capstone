#include "XtensaInstPrinter.h"
#include "XtensaMapping.h"

static void print_operand(MCInst *MI, SStream *O, void *info, const cs_xtensa_op *op)
{
	switch (op->type)
	{
	case XTENSA_OP_REG:
	case XTENSA_OP_FP:
	case XTENSA_OP_BOOLREG:
	case XTENSA_OP_MACREG:
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

void Xtensa_printInst(MCInst *MI, SStream *O, void *info)
{
	SStream_concat(O, "%s", Xtensa_insn_name((csh)MI->csh, MI->Opcode));
	const cs_xtensa *xt = &MI->flat_insn->detail->xtensa;

	if ((MI->Opcode == XTENSA_INSN_RSR || MI->Opcode == XTENSA_INSN_WSR) && xt->op_count == 2)
	{
		SStream_concat(O, ".%s\t", Xtensa_sysreg_name((csh)MI->csh, xt->operands[1].reg));
		print_operand(MI, O, info, &xt->operands[0]);
	}
	else if ((MI->Opcode == XTENSA_INSN_RUR || MI->Opcode == XTENSA_INSN_WUR) && xt->op_count == 2)
	{
		SStream_concat(O, ".%s\t", Xtensa_userreg_name((csh)MI->csh, xt->operands[1].reg));
		print_operand(MI, O, info, &xt->operands[0]);
	}
	else
	{
		for (uint8_t i = 0; i < xt->op_count; i++)
		{
			if (i == 0)
			{
				SStream_concat(O, "\t");
			}
			else
			{
				SStream_concat(O, ",\t");
			}

			const cs_xtensa_op *op = &xt->operands[i];
			print_operand(MI, O, info, op);
		}
	}
}
