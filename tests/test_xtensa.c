#include <stdio.h>
#include <stdlib.h>

#include <capstone/platform.h>
#include <capstone/capstone.h>

struct platform {
	cs_arch arch;
	cs_mode mode;
	unsigned char *code;
	size_t size;
	const char *comment;
};

static csh handle;

static void print_string_hex(const char *comment, unsigned char *str, size_t len)
{
	unsigned char *c;

	printf("%s", comment);
	for (c = str; c < str + len; c++) {
		printf("0x%02x ", *c & 0xff);
	}

	printf("\n");
}

static void print_insn_detail(cs_insn *ins)
{
	int i;
	int n;
	cs_xtensa *xtensa;
	cs_detail *detail;

	// detail can be NULL on "data" instruction if SKIPDATA option is turned ON
	if (ins->detail == NULL)
		return;

	xtensa = &(ins->detail->xtensa);
	detail = ins->detail;
	if (xtensa->op_count)
		printf("\top_count: %u\n", xtensa->op_count);

	for (i = 0; i < xtensa->op_count; i++) {
		cs_xtensa_op *op = &(xtensa->operands[i]);
		switch((int)op->type) {
			default:
				printf("\terror in opt_type: %u\n", (int)op->type);
				break;
			case XTENSA_OP_REG:
				printf("\t\toperands[%u].type: REG = %s\n", i, cs_reg_name(handle, op->reg));
				break;
			case XTENSA_OP_IMM:
				printf("\t\toperands[%u].type: IMM = 0x%" PRIx32 "\n", i, op->imm);
				break;
		}

	}
	
	//print the groups this instruction belongs to
	if (detail->groups_count > 0) {
		printf("\tThis instruction belongs to groups: ");
		for (n = 0; n < detail->groups_count; n++) {
			printf("%s ", cs_group_name(handle, detail->groups[n]));
		}
		printf("\n");
	}

	printf("\n");
}

static void test()
{
#define XTENSA_CODE ""
	struct platform platforms[] = {
		{
			CS_ARCH_XTENSA,
			CS_MODE_LITTLE_ENDIAN,
			(unsigned char *)XTENSA_CODE,
			sizeof(XTENSA_CODE) - 1,
			"xtensa"
		},
	};
	
	uint64_t address = 0x1000;
	cs_insn *insn;
	int i;
	size_t count;

	for (i = 0; i < sizeof(platforms)/sizeof(platforms[0]); i++) {
		cs_err err = cs_open(platforms[i].arch, platforms[i].mode, &handle);
		if (err) {
			printf("Failed on cs_open() with error returned: %u\n", err);
			continue;
		}
		
		//To turn on or off the Print Details option
		cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);

		count = cs_disasm(handle, platforms[i].code, platforms[i].size, address, 0, &insn);
		if (count) {
			size_t j;

			printf("****************\n");
			printf("Platform: %s\n", platforms[i].comment);
			print_string_hex("Code:", platforms[i].code, platforms[i].size);
			printf("Disasm:\n");

			for (j = 0; j < count; j++) {
				printf("0x%" PRIx64 ":\t%s\t%s\n", insn[j].address, insn[j].mnemonic, insn[j].op_str);
				print_insn_detail(&insn[j]);
			}
			printf("0x%" PRIx64 ":\n", insn[j-1].address + insn[j-1].size);

			cs_free(insn, count);
		} else {
			printf("****************\n");
			printf("Platform: %s\n", platforms[i].comment);
			print_string_hex("Code:", platforms[i].code, platforms[i].size);
			printf("ERROR: Failed to disasm given code!\n");
		}

		printf("\n");

		cs_close(&handle);
	}
}

int main()
{
	test();

	return 0;
}
