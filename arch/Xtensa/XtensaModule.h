/* Capstone Disassembly Engine */
/* Xtensa backend by Cillié Malan <me@chills.co.za> */

#ifndef CS_XTENSA_MODULE_H
#define CS_XTENSA_MODULE_H

#include "../../utils.h"

cs_err Xtensa_global_init(cs_struct * ud);
cs_err Xtensa_option(cs_struct * handle, cs_opt_type type, size_t value);

#endif
