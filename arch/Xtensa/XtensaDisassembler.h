    
#ifndef CS_XTENSADISASSEMBLER_H
#define CS_XTENSADISASSEMBLER_H

#include "../../include/capstone/capstone.h"
#include "../../MCRegisterInfo.h"
#include "../../MCInst.h"

void Xtensa_init(MCRegisterInfo *MRI);
bool Xtensa_getInstruction(csh ud, const uint8_t *code, size_t code_len,
		          MCInst *instr, uint16_t *size, uint64_t address,
		          void *info);

#endif
