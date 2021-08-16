#include <stdio.h>
#include <stdlib.h>

#include <capstone/capstone.h>

const char *Xtensa_sysreg_name(csh handle, unsigned int id);
const char *Xtensa_userreg_name(csh handle, unsigned int id);

void print_insn_detail_xtensa(csh handle, cs_insn *ins)
{
	cs_xtensa *xtensa;
	int i;

	// detail can be NULL on "data" instruction if SKIPDATA option is turned ON
	if (ins->detail == NULL)
		return;

	xtensa = &(ins->detail->xtensa);
	if (xtensa->op_count)
		printf("\top_count: %u\n", xtensa->op_count);

	for (i = 0; i < xtensa->op_count; i++) {
		cs_xtensa_op *op = &(xtensa->operands[i]);
		switch((int)op->type) {
			case XTENSA_OP_REG:
				printf("\t\toperands[%u].type: REG = %s\n", i, cs_reg_name(handle, op->reg));
				break;
            case XTENSA_OP_FP:
				printf("\t\toperands[%u].type: FP = %s\n", i, cs_reg_name(handle, op->reg));
				break;
            case XTENSA_OP_BOOLREG:
				printf("\t\toperands[%u].type: BOOLREG = %s\n", i, cs_reg_name(handle, op->reg));
				break;
			case XTENSA_OP_IMM:
                // TODO: proper handling for large unsigned immediates
				printf("\t\toperands[%u].type: IMM = %d\n", i, op->imm);
				break;
            case XTENSA_OP_SYSREG:
                printf("\t\toperands[%u].type: SYSREG = %s\n", i, Xtensa_sysreg_name(handle, op->reg));
                break;
            case XTENSA_OP_USERREG:
                printf("\t\toperands[%u].type: USERREG = %s\n", i, Xtensa_userreg_name(handle, op->reg));
                break;
            default:
				break;
		}
	}

	printf("\n");
}
