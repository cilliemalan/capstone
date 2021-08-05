/* Capstone Disassembly Engine */
/* Xtensa backend by Cillié Malan <me@chills.co.za> */

#include "XtensaModule.h"
#include "../../MCRegisterInfo.h"
#include "../../utils.h"
#include "XtensaDisassembler.h"
#include "XtensaInstPrinter.h"
#include "XtensaMapping.h"

cs_err Xtensa_global_init(cs_struct *ud)
{
	ud->printer = Xtensa_printInst;
	ud->printer_info = NULL;
	ud->getinsn_info = NULL;
	ud->disasm = Xtensa_getInstruction;
	ud->post_printer = NULL;

	ud->reg_name = Xtensa_reg_name;
	ud->insn_id = Xtensa_get_insn_id;
	ud->insn_name = Xtensa_insn_name;
	ud->group_name = Xtensa_group_name;

	return CS_ERR_OK;
}

cs_err Xtensa_option(cs_struct *handle, cs_opt_type type, size_t value)
{
	return CS_ERR_OK;
}
