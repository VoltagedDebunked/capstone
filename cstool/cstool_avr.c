#include <stdio.h>
#include <capstone/capstone.h>
#include "cstool.h"

void print_insn_detail_avr(csh handle, cs_insn *ins)
{
    cs_avr *avr;
    int i;
    cs_regs regs_read, regs_write;
    uint8_t regs_read_count, regs_write_count;

    if (ins->detail == NULL)
        return;

    avr = &(ins->detail->avr);

    if (avr->op_count)
        printf("\top_count: %u\n", avr->op_count);

    for (i = 0; i < avr->op_count; i++) {
        cs_avr_op *op = &(avr->operands[i]);
        switch (op->type) {
        default:
            printf("\t\toperands[%d].type: INVALID\n", i);
            break;

        case AVR_OP_REG:
            printf("\t\toperands[%d].type: REG = %s\n", i,
                   cs_reg_name(handle, op->reg));
            break;

        case AVR_OP_IMM:
            printf("\t\toperands[%d].type: IMM = 0x%x (%d)\n", i,
                   op->imm, op->imm);
            break;

        case AVR_OP_MEM:
            printf("\t\toperands[%d].type: MEM\n", i);
            printf("\t\t\tbase register: %s\n", cs_reg_name(handle, op->mem.base));
            printf("\t\t\tdisplacement: %d\n", op->mem.disp);
            break;
        }
    }

    // Print registers read/written by instruction
    if (!cs_regs_access(handle, ins, regs_read, &regs_read_count,
                        regs_write, &regs_write_count)) {
        if (regs_read_count) {
            printf("\tRegisters read:");
            for (i = 0; i < regs_read_count; i++)
                printf(" %s", cs_reg_name(handle, regs_read[i]));
            printf("\n");
        }

        if (regs_write_count) {
            printf("\tRegisters modified:");
            for (i = 0; i < regs_write_count; i++)
                printf(" %s", cs_reg_name(handle, regs_write[i]));
            printf("\n");
        }
    }
}
