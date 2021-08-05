
#ifndef CS_RISCV_MAP_H
#define CS_RISCV_MAP_H

#include "../../include/capstone/capstone.h"
#include "../../MCInst.h"

void Xtensa_get_insn_id(cs_struct *h, cs_insn *insn, unsigned int id);
const char *Xtensa_reg_name(csh handle, unsigned int id);
const char *Xtensa_sysreg_name(csh handle, unsigned int id);
const char *Xtensa_userreg_name(csh handle, unsigned int id);
const char *Xtensa_insn_name(csh handle, unsigned int id);
const char *Xtensa_group_name(csh handle, unsigned int id);
const char *Xtensa_kind_name(unsigned int id);

#endif